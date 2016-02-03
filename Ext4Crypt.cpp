/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "Ext4Crypt.h"

#include "KeyStorage.h"
#include "Utils.h"

#include <iomanip>
#include <map>
#include <set>
#include <string>
#include <sstream>

#include <stdio.h>
#include <errno.h>
#include <dirent.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cutils/properties.h>
#include <openssl/sha.h>
#include <selinux/android.h>

#include <private/android_filesystem_config.h>

#include "unencrypted_properties.h"
#include "key_control.h"
#include "cryptfs.h"
#include "ext4_crypt_init_extensions.h"

#define LOG_TAG "Ext4Crypt"

#define EMULATED_USES_SELINUX 0

#include <cutils/fs.h>
#include <cutils/log.h>
#include <cutils/klog.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>

using android::base::StringPrintf;

static bool e4crypt_is_native() {
    char value[PROPERTY_VALUE_MAX];
    property_get("ro.crypto.type", value, "none");
    return !strcmp(value, "file");
}

static bool e4crypt_is_emulated() {
    return property_get_bool("persist.sys.emulate_fbe", false);
}

namespace {
    // Key length in bits
    const int key_length = 128;
    static_assert(key_length % 8 == 0,
                  "Key length must be multiple of 8 bits");

    const std::string device_key_leaf = "/unencrypted/key";
    const std::string device_key_temp = "/unencrypted/temp";

    const std::string user_key_dir = std::string() + DATA_MNT_POINT + "/misc/vold/user_keys";
    const std::string user_key_temp = user_key_dir + "/temp";

    bool s_enabled = false;

    // Some users are ephemeral, don't try to wipe their keys from disk
    std::set<userid_t> s_ephemeral_users;

    // Map user ids to key references
    std::map<userid_t, std::string> s_de_key_raw_refs;
    std::map<userid_t, std::string> s_ce_key_raw_refs;

    // ext4enc:TODO get this const from somewhere good
    const int EXT4_KEY_DESCRIPTOR_SIZE = 8;

    // ext4enc:TODO Include structure from somewhere sensible
    // MUST be in sync with ext4_crypto.c in kernel
    const int EXT4_MAX_KEY_SIZE = 64;
    const int EXT4_ENCRYPTION_MODE_AES_256_XTS = 1;
    struct ext4_encryption_key {
        uint32_t mode;
        char raw[EXT4_MAX_KEY_SIZE];
        uint32_t size;
    };
}

static bool install_key(const std::string &key, std::string &raw_ref);

static UnencryptedProperties GetProps(const char* path)
{
    return UnencryptedProperties(path);
}

int e4crypt_crypto_complete(const char* path)
{
    SLOGI("ext4 crypto complete called on %s", path);
    if (GetProps(path).Get<std::string>(properties::ref).empty()) {
        SLOGI("No key reference, so not ext4enc");
        return -1;
    }

    return 0;
}

// Get raw keyref - used to make keyname and to pass to ioctl
static std::string generate_key_ref(const char* key, int length)
{
    SHA512_CTX c;

    SHA512_Init(&c);
    SHA512_Update(&c, key, length);
    unsigned char key_ref1[SHA512_DIGEST_LENGTH];
    SHA512_Final(key_ref1, &c);

    SHA512_Init(&c);
    SHA512_Update(&c, key_ref1, SHA512_DIGEST_LENGTH);
    unsigned char key_ref2[SHA512_DIGEST_LENGTH];
    SHA512_Final(key_ref2, &c);

    return std::string((char*)key_ref2, EXT4_KEY_DESCRIPTOR_SIZE);
}

static ext4_encryption_key fill_key(const std::string &key)
{
    // ext4enc:TODO Currently raw key is required to be of length
    // sizeof(ext4_key.raw) == EXT4_MAX_KEY_SIZE, so zero pad to
    // this length. Change when kernel bug is fixed.
    ext4_encryption_key ext4_key = {EXT4_ENCRYPTION_MODE_AES_256_XTS,
                                    {0},
                                    sizeof(ext4_key.raw)};
    memset(ext4_key.raw, 0, sizeof(ext4_key.raw));
    static_assert(key_length / 8 <= sizeof(ext4_key.raw),
                  "Key too long!");
    memcpy(ext4_key.raw, &key[0], key.size());
    return ext4_key;
}

static std::string keyname(const std::string &raw_ref)
{
    std::ostringstream o;
    o << "ext4:";
    for (auto i = raw_ref.begin(); i != raw_ref.end(); ++i) {
        o << std::hex << std::setw(2) << std::setfill('0') << (int)*i;
    }
    return o.str();
}

// Get the keyring we store all keys in
static key_serial_t e4crypt_keyring()
{
    return keyctl_search(KEY_SPEC_SESSION_KEYRING, "keyring", "e4crypt", 0);
}

// Install password into global keyring
// Return raw key reference for use in policy
static bool install_key(const std::string &key, std::string &raw_ref)
{
    if (key.size() != key_length/8) {
        LOG(ERROR) << "Wrong size key " << key.size();
        return false;
    }
    auto ext4_key = fill_key(key);
    raw_ref = generate_key_ref(ext4_key.raw, ext4_key.size);
    auto ref = keyname(raw_ref);
    key_serial_t device_keyring = e4crypt_keyring();
    key_serial_t key_id = add_key("logon", ref.c_str(),
                                  (void*)&ext4_key, sizeof(ext4_key),
                                  device_keyring);
    if (key_id == -1) {
        PLOG(ERROR) << "Failed to insert key into keyring " << device_keyring;
        return false;
    }
    LOG(INFO) << "Added key " << key_id << " (" << ref << ") to keyring "
        << device_keyring << " in process " << getpid();
    return true;
}

static std::string get_de_key_path(userid_t user_id) {
    return StringPrintf("%s/de/%d", user_key_dir.c_str(), user_id);
}

static std::string get_ce_key_path(userid_t user_id) {
    return StringPrintf("%s/ce/%d/current", user_key_dir.c_str(), user_id);
}

static bool read_and_install_key(const std::string &key_path, std::string &raw_ref)
{
    std::string key;
    if (!android::vold::retrieveKey(key_path, key)) return false;
    if (!install_key(key, raw_ref)) return false;
    return true;
}

static bool read_and_install_user_ce_key(userid_t user_id)
{
    if (s_ce_key_raw_refs.count(user_id) != 0) return true;
    const auto key_path = get_ce_key_path(user_id);
    std::string raw_ref;
    if (!read_and_install_key(key_path, raw_ref)) return false;
    s_ce_key_raw_refs[user_id] = raw_ref;
    LOG(DEBUG) << "Installed ce key for user " << user_id;
    return true;
}

static bool prepare_dir(const std::string &dir, mode_t mode, uid_t uid, gid_t gid) {
    LOG(DEBUG) << "Preparing: " << dir;
    if (fs_prepare_dir(dir.c_str(), mode, uid, gid) != 0) {
        PLOG(ERROR) << "Failed to prepare " << dir;
        return false;
    }
    return true;
}

static bool random_key(std::string &key) {
    if (android::vold::ReadRandomBytes(key_length / 8, key) != 0) {
        // TODO status_t plays badly with PLOG, fix it.
        LOG(ERROR) << "Random read failed";
        return false;
    }
    return true;
}

static bool path_exists(const std::string &path) {
    return access(path.c_str(), F_OK) == 0;
}

// NB this assumes that there is only one thread listening for crypt commands, because
// it creates keys in a fixed location.
static bool store_key(const std::string &key_path, const std::string &key) {
    if (path_exists(key_path)) {
        LOG(ERROR) << "Already exists, cannot create key at: " << key_path;
        return false;
    }
    if (path_exists(user_key_temp)) {
        android::vold::destroyKey(user_key_temp);
    }
    if (!android::vold::storeKey(user_key_temp, key)) return false;
    if (rename(user_key_temp.c_str(), key_path.c_str()) != 0) {
        PLOG(ERROR) << "Unable to move new key to location: " << key_path;
        return false;
    }
    LOG(DEBUG) << "Created key " << key_path;
    return true;
}

static bool create_and_install_user_keys(userid_t user_id, bool create_ephemeral) {
    std::string de_key, ce_key;
    if (!random_key(de_key)) return false;
    if (!random_key(ce_key)) return false;
    if (create_ephemeral) {
        // If the key should be created as ephemeral, don't store it.
        s_ephemeral_users.insert(user_id);
    } else {
        if (!store_key(get_de_key_path(user_id), de_key)) return false;
        if (!prepare_dir(user_key_dir + "/ce/" + std::to_string(user_id),
            0700, AID_ROOT, AID_ROOT)) return false;
        if (!store_key(get_ce_key_path(user_id), ce_key)) return false;
    }
    std::string de_raw_ref;
    if (!install_key(de_key, de_raw_ref)) return false;
    s_de_key_raw_refs[user_id] = de_raw_ref;
    std::string ce_raw_ref;
    if (!install_key(ce_key, ce_raw_ref)) return false;
    s_ce_key_raw_refs[user_id] = ce_raw_ref;
    LOG(DEBUG) << "Created keys for user " << user_id;
    return true;
}

static bool lookup_key_ref(const std::map<userid_t, std::string> &key_map,
        userid_t user_id, std::string &raw_ref) {
    auto refi = key_map.find(user_id);
    if (refi == key_map.end()) {
        LOG(ERROR) << "Cannot find key for " << user_id;
        return false;
    }
    raw_ref = refi->second;
    return true;
}

static bool set_policy(const std::string &raw_ref, const std::string& path) {
    if (do_policy_set(path.c_str(), raw_ref.data(), raw_ref.size()) != 0) {
        LOG(ERROR) << "Failed to set policy on: " << path;
        return false;
    }
    return true;
}

static bool is_numeric(const char *name) {
    for (const char *p = name; *p != '\0'; p++) {
        if (!isdigit(*p))
            return false;
    }
    return true;
}

static bool load_all_de_keys() {
    auto de_dir = user_key_dir + "/de";
    auto dirp = std::unique_ptr<DIR, int(*)(DIR*)>(opendir(de_dir.c_str()), closedir);
    if (!dirp) {
        PLOG(ERROR) << "Unable to read de key directory";
        return false;
    }
    for (;;) {
        errno = 0;
        auto entry = readdir(dirp.get());
        if (!entry) {
            if (errno) {
                PLOG(ERROR) << "Unable to read de key directory";
                return false;
            }
            break;
        }
        if (entry->d_type != DT_DIR || !is_numeric(entry->d_name)) {
            LOG(DEBUG) << "Skipping non-de-key " << entry->d_name;
            continue;
        }
        userid_t user_id = atoi(entry->d_name);
        if (s_de_key_raw_refs.count(user_id) == 0) {
            std::string raw_ref;
            if (!read_and_install_key(de_dir + "/" + entry->d_name, raw_ref)) return false;
            s_de_key_raw_refs[user_id] = raw_ref;
            LOG(DEBUG) << "Installed de key for user " << user_id;
        }
    }
    // ext4enc:TODO: go through all DE directories, ensure that all user dirs have the
    // correct policy set on them, and that no rogue ones exist.
    return true;
}

int e4crypt_enable(const char* path)
{
    LOG(INFO) << "e4crypt_enable";

    if (s_enabled) {
        LOG(INFO) << "Already enabled";
        return 0;
    }

    std::string device_key;
    std::string device_key_path = std::string(path) + device_key_leaf;
    if (!android::vold::retrieveKey(device_key_path, device_key)) {
        LOG(INFO) << "Creating new key";
        if (!random_key(device_key)) {
            return -1;
        }

        std::string key_temp = std::string(path) + device_key_temp;
        if (path_exists(key_temp)) {
            android::vold::destroyKey(key_temp);
        }

        if (!android::vold::storeKey(key_temp, device_key)) return false;
        if (rename(key_temp.c_str(), device_key_path.c_str()) != 0) {
            PLOG(ERROR) << "Unable to move new key to location: "
                        << device_key_path;
            return false;
        }
    }

    std::string device_key_ref;
    if (!install_key(device_key, device_key_ref)) {
        LOG(ERROR) << "Failed to install device key";
        return -1;
    }

    UnencryptedProperties props(path);
    if (!props.Remove(properties::ref)) {
        LOG(ERROR) << "Failed to remove key ref";
        return -1;
    }

    if (!props.Set(properties::ref, device_key_ref)) {
        LOG(ERROR) << "Cannot save key reference";
        return -1;
    }

    s_enabled = true;
    return 0;
}

int e4crypt_init_user0() {
    LOG(DEBUG) << "e4crypt_init_user0";
    if (e4crypt_is_native()) {
        if (!prepare_dir(user_key_dir, 0700, AID_ROOT, AID_ROOT)) return -1;
        if (!prepare_dir(user_key_dir + "/ce", 0700, AID_ROOT, AID_ROOT)) return -1;
        if (!prepare_dir(user_key_dir + "/de", 0700, AID_ROOT, AID_ROOT)) return -1;
        auto de_path = get_de_key_path(0);
        auto ce_path = get_ce_key_path(0);
        if (!path_exists(de_path) || !path_exists(ce_path)) {
            if (path_exists(de_path)) {
                android::vold::destroyKey(de_path); // Ignore failure
            }
            if (path_exists(ce_path)) {
                android::vold::destroyKey(ce_path); // Ignore failure
            }
            if (!create_and_install_user_keys(0, false)) return -1;
        }
        if (!load_all_de_keys()) return -1;
    }
    // Ignore failures. FIXME this is horrid
    // FIXME: we need an idempotent policy-setting call, which simply verifies the
    // policy is already set on a second run, even if the directory is nonempty.
    // Then we need to call it all the time.
    e4crypt_prepare_user_storage(nullptr, 0, 0, false);
    return 0;
}

int e4crypt_vold_create_user_key(userid_t user_id, int serial, bool ephemeral) {
    LOG(DEBUG) << "e4crypt_vold_create_user_key for " << user_id << " serial " << serial;
    if (!e4crypt_is_native()) {
        return 0;
    }
    // FIXME test for existence of key that is not loaded yet
    if (s_ce_key_raw_refs.count(user_id) != 0) {
        LOG(ERROR) << "Already exists, can't e4crypt_vold_create_user_key for "
            << user_id << " serial " << serial;
        // FIXME should we fail the command?
        return 0;
    }
    if (!create_and_install_user_keys(user_id, ephemeral)) {
        return -1;
    }
    // TODO: create second key for user_de data
    return 0;
}

static bool evict_key(const std::string &raw_ref) {
    auto ref = keyname(raw_ref);
    auto key_serial = keyctl_search(e4crypt_keyring(), "logon", ref.c_str(), 0);
    if (keyctl_revoke(key_serial) != 0) {
        PLOG(ERROR) << "Failed to revoke key with serial " << key_serial << " ref " << ref;
        return false;
    }
    LOG(DEBUG) << "Revoked key with serial " << key_serial << " ref " << ref;
    return true;
}

int e4crypt_destroy_user_key(userid_t user_id) {
    LOG(DEBUG) << "e4crypt_destroy_user_key(" << user_id << ")";
    if (!e4crypt_is_native()) {
        return 0;
    }
    bool success = true;
    std::string raw_ref;
    success &= lookup_key_ref(s_ce_key_raw_refs, user_id, raw_ref) && evict_key(raw_ref);
    success &= lookup_key_ref(s_de_key_raw_refs, user_id, raw_ref) && evict_key(raw_ref);
    auto it = s_ephemeral_users.find(user_id);
    if (it != s_ephemeral_users.end()) {
        s_ephemeral_users.erase(it);
    } else {
        success &= android::vold::destroyKey(get_ce_key_path(user_id));
        success &= android::vold::destroyKey(get_de_key_path(user_id));
    }
    return success ? 0 : -1;
}

static int emulated_lock(const std::string& path) {
    if (chmod(path.c_str(), 0000) != 0) {
        PLOG(ERROR) << "Failed to chmod " << path;
        return -1;
    }
#if EMULATED_USES_SELINUX
    if (setfilecon(path.c_str(), "u:object_r:storage_stub_file:s0") != 0) {
        PLOG(WARNING) << "Failed to setfilecon " << path;
        return -1;
    }
#endif
    return 0;
}

static int emulated_unlock(const std::string& path, mode_t mode) {
    if (chmod(path.c_str(), mode) != 0) {
        PLOG(ERROR) << "Failed to chmod " << path;
        // FIXME temporary workaround for b/26713622
        if (e4crypt_is_emulated()) return -1;
    }
#if EMULATED_USES_SELINUX
    if (selinux_android_restorecon(path.c_str(), SELINUX_ANDROID_RESTORECON_FORCE) != 0) {
        PLOG(WARNING) << "Failed to restorecon " << path;
        // FIXME temporary workaround for b/26713622
        if (e4crypt_is_emulated()) return -1;
    }
#endif
    return 0;
}

int e4crypt_unlock_user_key(userid_t user_id, int serial, const char* token) {
    LOG(DEBUG) << "e4crypt_unlock_user_key " << user_id << " " << (token != nullptr);
    if (e4crypt_is_native()) {
        if (!read_and_install_user_ce_key(user_id)) {
            LOG(ERROR) << "Couldn't read key for " << user_id;
            return -1;
        }
    } else {
        // When in emulation mode, we just use chmod. However, we also
        // unlock directories when not in emulation mode, to bring devices
        // back into a known-good state.
        if (emulated_unlock(android::vold::BuildDataSystemCePath(user_id), 0771) ||
                emulated_unlock(android::vold::BuildDataMediaPath(nullptr, user_id), 0770) ||
                emulated_unlock(android::vold::BuildDataUserPath(nullptr, user_id), 0771)) {
            LOG(ERROR) << "Failed to unlock user " << user_id;
            return -1;
        }
    }
    return 0;
}

int e4crypt_lock_user_key(userid_t user_id) {
    if (e4crypt_is_native()) {
        // TODO: remove from kernel keyring
    } else if (e4crypt_is_emulated()) {
        // When in emulation mode, we just use chmod
        if (emulated_lock(android::vold::BuildDataSystemCePath(user_id)) ||
                emulated_lock(android::vold::BuildDataMediaPath(nullptr, user_id)) ||
                emulated_lock(android::vold::BuildDataUserPath(nullptr, user_id))) {
            PLOG(ERROR) << "Failed to lock user " << user_id;
            return -1;
        }
    }

    return 0;
}

int e4crypt_prepare_user_storage(const char* volume_uuid,
                                 userid_t user_id,
                                 int serial,
                                 bool ephemeral) {
    if (volume_uuid) {
        LOG(DEBUG) << "e4crypt_prepare_user_storage " << volume_uuid << " " << user_id;
    } else {
        LOG(DEBUG) << "e4crypt_prepare_user_storage, null volume " << user_id;
    }
    auto system_ce_path = android::vold::BuildDataSystemCePath(user_id);
    auto media_ce_path = android::vold::BuildDataMediaPath(volume_uuid, user_id);
    auto user_ce_path = android::vold::BuildDataUserPath(volume_uuid, user_id);
    auto user_de_path = android::vold::BuildDataUserDePath(volume_uuid, user_id);

    // FIXME: should this be 0770 or 0700?
    if (!prepare_dir(system_ce_path, 0770, AID_SYSTEM, AID_SYSTEM)) return -1;
    if (!prepare_dir(media_ce_path, 0770, AID_MEDIA_RW, AID_MEDIA_RW)) return -1;
    if (!prepare_dir(user_ce_path, 0771, AID_SYSTEM, AID_SYSTEM)) return -1;
    if (!prepare_dir(user_de_path, 0771, AID_SYSTEM, AID_SYSTEM)) return -1;

    if (e4crypt_crypto_complete(DATA_MNT_POINT) == 0) {
        std::string ce_raw_ref, de_raw_ref;
        if (!lookup_key_ref(s_ce_key_raw_refs, user_id, ce_raw_ref)) return -1;
        if (!lookup_key_ref(s_de_key_raw_refs, user_id, de_raw_ref)) return -1;
        if (!set_policy(ce_raw_ref, system_ce_path)) return -1;
        if (!set_policy(ce_raw_ref, media_ce_path)) return -1;
        if (!set_policy(ce_raw_ref, user_ce_path)) return -1;
        if (!set_policy(de_raw_ref, user_de_path)) return -1;
        // FIXME I thought there were more DE directories than this
    }

    return 0;
}
