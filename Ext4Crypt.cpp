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

#include "key_control.h"
#include "cryptfs.h"
#include "ext4_crypt.h"

#define LOG_TAG "Ext4Crypt"

#define EMULATED_USES_SELINUX 0

#include <cutils/fs.h>
#include <cutils/log.h>
#include <cutils/klog.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>

using android::base::StringPrintf;
using android::vold::kEmptyAuthentication;

// NOTE: keep in sync with StorageManager
static constexpr int FLAG_STORAGE_DE = 1 << 0;
static constexpr int FLAG_STORAGE_CE = 1 << 1;

static bool e4crypt_is_native() {
    char value[PROPERTY_VALUE_MAX];
    property_get("ro.crypto.type", value, "none");
    return !strcmp(value, "file");
}

static bool e4crypt_is_emulated() {
    return property_get_bool("persist.sys.emulate_fbe", false);
}

static const char* escape_null(const char* value) {
    return (value == nullptr) ? "null" : value;
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
    // TODO abolish this map. Keys should not be long-lived in user memory, only kernel memory.
    // See b/26948053
    std::map<userid_t, std::string> s_ce_keys;

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

// TODO replace with proper function to test for file encryption
int e4crypt_crypto_complete(const char* path)
{
    return e4crypt_is_native() ? 0 : -1;
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

static bool read_and_install_user_ce_key(
        userid_t user_id, const android::vold::KeyAuthentication &auth) {
    if (s_ce_key_raw_refs.count(user_id) != 0) return true;
    const auto ce_key_path = get_ce_key_path(user_id);
    std::string ce_key;
    if (!android::vold::retrieveKey(ce_key_path, auth, ce_key)) return false;
    std::string ce_raw_ref;
    if (!install_key(ce_key, ce_raw_ref)) return false;
    s_ce_keys[user_id] = ce_key;
    s_ce_key_raw_refs[user_id] = ce_raw_ref;
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
static bool store_key(const std::string &key_path,
        const android::vold::KeyAuthentication &auth, const std::string &key) {
    if (path_exists(key_path)) {
        LOG(ERROR) << "Already exists, cannot create key at: " << key_path;
        return false;
    }
    if (path_exists(user_key_temp)) {
        android::vold::destroyKey(user_key_temp);
    }
    if (!android::vold::storeKey(user_key_temp, auth, key)) return false;
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
        if (!store_key(get_de_key_path(user_id), kEmptyAuthentication, de_key)) return false;
        if (!prepare_dir(user_key_dir + "/ce/" + std::to_string(user_id),
            0700, AID_ROOT, AID_ROOT)) return false;
        if (!store_key(get_ce_key_path(user_id), kEmptyAuthentication, ce_key)) return false;
    }
    std::string de_raw_ref;
    if (!install_key(de_key, de_raw_ref)) return false;
    s_de_key_raw_refs[user_id] = de_raw_ref;
    std::string ce_raw_ref;
    if (!install_key(ce_key, ce_raw_ref)) return false;
    s_ce_keys[user_id] = ce_key;
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

static bool ensure_policy(const std::string &raw_ref, const std::string& path) {
    if (e4crypt_policy_ensure(path.c_str(), raw_ref.data(), raw_ref.size()) != 0) {
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
            auto key_path = de_dir + "/" + entry->d_name;
            std::string key;
            if (!android::vold::retrieveKey(key_path, kEmptyAuthentication, key)) return false;
            std::string raw_ref;
            if (!install_key(key, raw_ref)) return false;
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
    if (!android::vold::retrieveKey(device_key_path, kEmptyAuthentication, device_key)) {
        LOG(INFO) << "Creating new key";
        if (!random_key(device_key)) {
            return -1;
        }

        std::string key_temp = std::string(path) + device_key_temp;
        if (path_exists(key_temp)) {
            android::vold::destroyKey(key_temp);
        }

        if (!android::vold::storeKey(key_temp, kEmptyAuthentication, device_key)) return -1;
        if (rename(key_temp.c_str(), device_key_path.c_str()) != 0) {
            PLOG(ERROR) << "Unable to move new key to location: "
                        << device_key_path;
            return -1;
        }
    }

    std::string device_key_ref;
    if (!install_key(device_key, device_key_ref)) {
        LOG(ERROR) << "Failed to install device key";
        return -1;
    }

    std::string ref_filename = std::string("/data") + e4crypt_key_ref;
    if (!android::base::WriteStringToFile(device_key_ref, ref_filename)) {
        PLOG(ERROR) << "Cannot save key reference";
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
        // TODO: switch to loading only DE_0 here once framework makes
        // explicit calls to install DE keys for secondary users
        if (!load_all_de_keys()) return -1;
    }
    // We can only safely prepare DE storage here, since CE keys are probably
    // entangled with user credentials.  The framework will always prepare CE
    // storage once CE keys are installed.
    if (e4crypt_prepare_user_storage(nullptr, 0, 0, FLAG_STORAGE_DE) != 0) {
        LOG(ERROR) << "Failed to prepare user 0 storage";
        return -1;
    }

    // If this is a non-FBE device that recently left an emulated mode,
    // restore user data directories to known-good state.
    if (!e4crypt_is_native() && !e4crypt_is_emulated()) {
        e4crypt_unlock_user_key(0, 0, "!", "!");
    }

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
    s_ce_keys.erase(user_id);
    std::string raw_ref;
    success &= lookup_key_ref(s_ce_key_raw_refs, user_id, raw_ref) && evict_key(raw_ref);
    s_ce_key_raw_refs.erase(user_id);
    success &= lookup_key_ref(s_de_key_raw_refs, user_id, raw_ref) && evict_key(raw_ref);
    s_de_key_raw_refs.erase(user_id);
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

static bool parse_hex(const char *hex, std::string &result) {
    if (strcmp("!", hex) == 0) {
        result = "";
        return true;
    }
    if (android::vold::HexToStr(hex, result) != 0) {
        LOG(ERROR) << "Invalid FBE hex string"; // Don't log the string for security reasons
        return false;
    }
    return true;
}

int e4crypt_change_user_key(userid_t user_id, int serial,
        const char* token_hex, const char* old_secret_hex, const char* new_secret_hex) {
    LOG(DEBUG) << "e4crypt_change_user_key " << user_id << " serial=" << serial <<
        " token_present=" << (strcmp(token_hex, "!") != 0);
    if (!e4crypt_is_native()) return 0;
    if (s_ephemeral_users.count(user_id) != 0) return 0;
    std::string token, old_secret, new_secret;
    if (!parse_hex(token_hex, token)) return -1;
    if (!parse_hex(old_secret_hex, old_secret)) return -1;
    if (!parse_hex(new_secret_hex, new_secret)) return -1;
    auto auth = new_secret.empty()
        ? kEmptyAuthentication
        : android::vold::KeyAuthentication(token, new_secret);
    auto it = s_ce_keys.find(user_id);
    if (it == s_ce_keys.end()) {
        LOG(ERROR) << "Key not loaded into memory, can't change for user " << user_id;
        return -1;
    }
    auto ce_key = it->second;
    auto ce_key_path = get_ce_key_path(user_id);
    android::vold::destroyKey(ce_key_path);
    if (!store_key(ce_key_path, auth, ce_key)) return -1;
    return 0;
}

// TODO: rename to 'install' for consistency, and take flags to know which keys to install
int e4crypt_unlock_user_key(userid_t user_id, int serial,
        const char* token_hex, const char* secret_hex) {
    LOG(DEBUG) << "e4crypt_unlock_user_key " << user_id << " serial=" << serial <<
        " token_present=" << (strcmp(token_hex, "!") != 0);
    if (e4crypt_is_native()) {
        if (s_ce_key_raw_refs.count(user_id) != 0) {
            LOG(WARNING) << "Tried to unlock already-unlocked key for user " << user_id;
            return 0;
        }
        std::string token, secret;
        if (!parse_hex(token_hex, token)) return false;
        if (!parse_hex(secret_hex, secret)) return false;
        android::vold::KeyAuthentication auth(token, secret);
        if (!read_and_install_user_ce_key(user_id, auth)) {
            LOG(ERROR) << "Couldn't read key for " << user_id;
            return -1;
        }
    } else {
        // When in emulation mode, we just use chmod. However, we also
        // unlock directories when not in emulation mode, to bring devices
        // back into a known-good state.
        if (emulated_unlock(android::vold::BuildDataSystemCePath(user_id), 0771) ||
                emulated_unlock(android::vold::BuildDataMiscCePath(user_id), 01771) ||
                emulated_unlock(android::vold::BuildDataMediaPath(nullptr, user_id), 0770) ||
                emulated_unlock(android::vold::BuildDataUserPath(nullptr, user_id), 0771)) {
            LOG(ERROR) << "Failed to unlock user " << user_id;
            return -1;
        }
    }
    return 0;
}

// TODO: rename to 'evict' for consistency
int e4crypt_lock_user_key(userid_t user_id) {
    if (e4crypt_is_native()) {
        // TODO: remove from kernel keyring
    } else if (e4crypt_is_emulated()) {
        // When in emulation mode, we just use chmod
        if (emulated_lock(android::vold::BuildDataSystemCePath(user_id)) ||
                emulated_lock(android::vold::BuildDataMiscCePath(user_id)) ||
                emulated_lock(android::vold::BuildDataMediaPath(nullptr, user_id)) ||
                emulated_lock(android::vold::BuildDataUserPath(nullptr, user_id))) {
            LOG(ERROR) << "Failed to lock user " << user_id;
            return -1;
        }
    }

    return 0;
}

int e4crypt_prepare_user_storage(const char* volume_uuid, userid_t user_id,
        int serial, int flags) {
    LOG(DEBUG) << "e4crypt_prepare_user_storage for volume " << escape_null(volume_uuid)
            << ", user " << user_id << ", serial " << serial << ", flags " << flags;

    if (flags & FLAG_STORAGE_DE) {
        auto system_de_path = android::vold::BuildDataSystemDePath(user_id);
        auto misc_de_path = android::vold::BuildDataMiscDePath(user_id);
        auto user_de_path = android::vold::BuildDataUserDePath(volume_uuid, user_id);

        if (!prepare_dir(system_de_path, 0770, AID_SYSTEM, AID_SYSTEM)) return -1;
        if (!prepare_dir(misc_de_path, 01771, AID_SYSTEM, AID_MISC)) return -1;
        if (!prepare_dir(user_de_path, 0771, AID_SYSTEM, AID_SYSTEM)) return -1;

        if (e4crypt_crypto_complete(DATA_MNT_POINT) == 0) {
            std::string de_raw_ref;
            if (!lookup_key_ref(s_de_key_raw_refs, user_id, de_raw_ref)) return -1;
            if (!ensure_policy(de_raw_ref, system_de_path)) return -1;
            if (!ensure_policy(de_raw_ref, misc_de_path)) return -1;
            if (!ensure_policy(de_raw_ref, user_de_path)) return -1;
        }
    }

    if (flags & FLAG_STORAGE_CE) {
        auto system_ce_path = android::vold::BuildDataSystemCePath(user_id);
        auto misc_ce_path = android::vold::BuildDataMiscCePath(user_id);
        auto media_ce_path = android::vold::BuildDataMediaPath(volume_uuid, user_id);
        auto user_ce_path = android::vold::BuildDataUserPath(volume_uuid, user_id);

        if (!prepare_dir(system_ce_path, 0770, AID_SYSTEM, AID_SYSTEM)) return -1;
        if (!prepare_dir(misc_ce_path, 01771, AID_SYSTEM, AID_MISC)) return -1;
        if (!prepare_dir(media_ce_path, 0770, AID_MEDIA_RW, AID_MEDIA_RW)) return -1;
        if (!prepare_dir(user_ce_path, 0771, AID_SYSTEM, AID_SYSTEM)) return -1;

        if (e4crypt_crypto_complete(DATA_MNT_POINT) == 0) {
            std::string ce_raw_ref;
            if (!lookup_key_ref(s_ce_key_raw_refs, user_id, ce_raw_ref)) return -1;
            if (!ensure_policy(ce_raw_ref, system_ce_path)) return -1;
            if (!ensure_policy(ce_raw_ref, misc_ce_path)) return -1;
            if (!ensure_policy(ce_raw_ref, media_ce_path)) return -1;
            if (!ensure_policy(ce_raw_ref, user_ce_path)) return -1;
        }
    }

    return 0;
}
