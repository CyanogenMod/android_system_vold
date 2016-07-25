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

#include <algorithm>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <string>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/sha.h>
#include <selinux/android.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <private/android_filesystem_config.h>

#include "cryptfs.h"
#include "ext4_crypt.h"
#include "key_control.h"

#define EMULATED_USES_SELINUX 0
#define MANAGE_MISC_DIRS 0

#include <cutils/fs.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>

using android::base::StringPrintf;
using android::vold::kEmptyAuthentication;

// NOTE: keep in sync with StorageManager
static constexpr int FLAG_STORAGE_DE = 1 << 0;
static constexpr int FLAG_STORAGE_CE = 1 << 1;

namespace {
const std::string device_key_dir = std::string() + DATA_MNT_POINT + e4crypt_unencrypted_folder;
const std::string device_key_path = device_key_dir + "/key";
const std::string device_key_temp = device_key_dir + "/temp";

const std::string user_key_dir = std::string() + DATA_MNT_POINT + "/misc/vold/user_keys";
const std::string user_key_temp = user_key_dir + "/temp";

bool s_global_de_initialized = false;

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
constexpr int EXT4_ENCRYPTION_MODE_AES_256_XTS = 1;
constexpr int EXT4_AES_256_XTS_KEY_SIZE = 64;
constexpr int EXT4_MAX_KEY_SIZE = 64;
struct ext4_encryption_key {
    uint32_t mode;
    char raw[EXT4_MAX_KEY_SIZE];
    uint32_t size;
};
}

static bool e4crypt_is_emulated() {
    return property_get_bool("persist.sys.emulate_fbe", false);
}

static const char* escape_null(const char* value) {
    return (value == nullptr) ? "null" : value;
}

// Get raw keyref - used to make keyname and to pass to ioctl
static std::string generate_key_ref(const char* key, int length) {
    SHA512_CTX c;

    SHA512_Init(&c);
    SHA512_Update(&c, key, length);
    unsigned char key_ref1[SHA512_DIGEST_LENGTH];
    SHA512_Final(key_ref1, &c);

    SHA512_Init(&c);
    SHA512_Update(&c, key_ref1, SHA512_DIGEST_LENGTH);
    unsigned char key_ref2[SHA512_DIGEST_LENGTH];
    SHA512_Final(key_ref2, &c);

    static_assert(EXT4_KEY_DESCRIPTOR_SIZE <= SHA512_DIGEST_LENGTH,
                  "Hash too short for descriptor");
    return std::string((char*)key_ref2, EXT4_KEY_DESCRIPTOR_SIZE);
}

static bool fill_key(const std::string& key, ext4_encryption_key* ext4_key) {
    if (key.size() != EXT4_AES_256_XTS_KEY_SIZE) {
        LOG(ERROR) << "Wrong size key " << key.size();
        return false;
    }
    static_assert(EXT4_AES_256_XTS_KEY_SIZE <= sizeof(ext4_key->raw), "Key too long!");
    ext4_key->mode = EXT4_ENCRYPTION_MODE_AES_256_XTS;
    ext4_key->size = key.size();
    memset(ext4_key->raw, 0, sizeof(ext4_key->raw));
    memcpy(ext4_key->raw, key.data(), key.size());
    return true;
}

static std::string keyname(const std::string& raw_ref) {
    std::ostringstream o;
    o << "ext4:";
    for (auto i : raw_ref) {
        o << std::hex << std::setw(2) << std::setfill('0') << (int)i;
    }
    return o.str();
}

// Get the keyring we store all keys in
static bool e4crypt_keyring(key_serial_t* device_keyring) {
    *device_keyring = keyctl_search(KEY_SPEC_SESSION_KEYRING, "keyring", "e4crypt", 0);
    if (*device_keyring == -1) {
        PLOG(ERROR) << "Unable to find device keyring";
        return false;
    }
    return true;
}

// Install password into global keyring
// Return raw key reference for use in policy
static bool install_key(const std::string& key, std::string* raw_ref) {
    ext4_encryption_key ext4_key;
    if (!fill_key(key, &ext4_key)) return false;
    *raw_ref = generate_key_ref(ext4_key.raw, ext4_key.size);
    auto ref = keyname(*raw_ref);
    key_serial_t device_keyring;
    if (!e4crypt_keyring(&device_keyring)) return false;
    key_serial_t key_id =
        add_key("logon", ref.c_str(), (void*)&ext4_key, sizeof(ext4_key), device_keyring);
    if (key_id == -1) {
        PLOG(ERROR) << "Failed to insert key into keyring " << device_keyring;
        return false;
    }
    LOG(DEBUG) << "Added key " << key_id << " (" << ref << ") to keyring " << device_keyring
               << " in process " << getpid();

    return true;
}

static std::string get_de_key_path(userid_t user_id) {
    return StringPrintf("%s/de/%d", user_key_dir.c_str(), user_id);
}

static std::string get_ce_key_directory_path(userid_t user_id) {
    return StringPrintf("%s/ce/%d", user_key_dir.c_str(), user_id);
}

// Returns the keys newest first
static std::vector<std::string> get_ce_key_paths(const std::string& directory_path) {
    auto dirp = std::unique_ptr<DIR, int (*)(DIR*)>(opendir(directory_path.c_str()), closedir);
    if (!dirp) {
        PLOG(ERROR) << "Unable to open ce key directory: " + directory_path;
        return std::vector<std::string>();
    }
    std::vector<std::string> result;
    for (;;) {
        errno = 0;
        auto const entry = readdir(dirp.get());
        if (!entry) {
            if (errno) {
                PLOG(ERROR) << "Unable to read ce key directory: " + directory_path;
                return std::vector<std::string>();
            }
            break;
        }
        if (entry->d_type != DT_DIR || entry->d_name[0] != 'c') {
            LOG(DEBUG) << "Skipping non-key " << entry->d_name;
            continue;
        }
        result.emplace_back(directory_path + "/" + entry->d_name);
    }
    std::sort(result.begin(), result.end());
    std::reverse(result.begin(), result.end());
    return result;
}

static std::string get_ce_key_current_path(const std::string& directory_path) {
    return directory_path + "/current";
}

static bool get_ce_key_new_path(const std::string& directory_path,
                                const std::vector<std::string>& paths,
                                std::string *ce_key_path) {
    if (paths.empty()) {
        *ce_key_path = get_ce_key_current_path(directory_path);
        return true;
    }
    for (unsigned int i = 0; i < UINT_MAX; i++) {
        auto const candidate = StringPrintf("%s/cx%010u", directory_path.c_str(), i);
        if (paths[0] < candidate) {
            *ce_key_path = candidate;
            return true;
        }
    }
    return false;
}

// Discard all keys but the named one; rename it to canonical name.
// No point in acting on errors in this; ignore them.
static void fixate_user_ce_key(const std::string& directory_path, const std::string &to_fix,
                               const std::vector<std::string>& paths) {
    for (auto const other_path: paths) {
        if (other_path != to_fix) {
            android::vold::destroyKey(other_path);
        }
    }
    auto const current_path = get_ce_key_current_path(directory_path);
    if (to_fix != current_path) {
        LOG(DEBUG) << "Renaming " << to_fix << " to " << current_path;
        if (rename(to_fix.c_str(), current_path.c_str()) != 0) {
            PLOG(WARNING) << "Unable to rename " << to_fix << " to " << current_path;
        }
    }
}

static bool read_and_fixate_user_ce_key(userid_t user_id,
                                        const android::vold::KeyAuthentication& auth,
                                        std::string *ce_key) {
    auto const directory_path = get_ce_key_directory_path(user_id);
    auto const paths = get_ce_key_paths(directory_path);
    for (auto const ce_key_path: paths) {
        LOG(DEBUG) << "Trying user CE key " << ce_key_path;
        if (android::vold::retrieveKey(ce_key_path, auth, ce_key)) {
            LOG(DEBUG) << "Successfully retrieved key";
            fixate_user_ce_key(directory_path, ce_key_path, paths);
            return true;
        }
    }
    LOG(ERROR) << "Failed to find working ce key for user " << user_id;
    return false;
}

static bool read_and_install_user_ce_key(userid_t user_id,
                                         const android::vold::KeyAuthentication& auth) {
    if (s_ce_key_raw_refs.count(user_id) != 0) return true;
    std::string ce_key;
    if (!read_and_fixate_user_ce_key(user_id, auth, &ce_key)) return false;
    std::string ce_raw_ref;
    if (!install_key(ce_key, &ce_raw_ref)) return false;
    s_ce_keys[user_id] = ce_key;
    s_ce_key_raw_refs[user_id] = ce_raw_ref;
    LOG(DEBUG) << "Installed ce key for user " << user_id;
    return true;
}

static bool prepare_dir(const std::string& dir, mode_t mode, uid_t uid, gid_t gid) {
    LOG(DEBUG) << "Preparing: " << dir;
    if (fs_prepare_dir(dir.c_str(), mode, uid, gid) != 0) {
        PLOG(ERROR) << "Failed to prepare " << dir;
        return false;
    }
    return true;
}

static bool destroy_dir(const std::string& dir) {
    LOG(DEBUG) << "Destroying: " << dir;
    if (rmdir(dir.c_str()) != 0 && errno != ENOENT) {
        PLOG(ERROR) << "Failed to destroy " << dir;
        return false;
    }
    return true;
}

static bool random_key(std::string* key) {
    if (android::vold::ReadRandomBytes(EXT4_AES_256_XTS_KEY_SIZE, *key) != 0) {
        // TODO status_t plays badly with PLOG, fix it.
        LOG(ERROR) << "Random read failed";
        return false;
    }
    return true;
}

static bool path_exists(const std::string& path) {
    return access(path.c_str(), F_OK) == 0;
}

// NB this assumes that there is only one thread listening for crypt commands, because
// it creates keys in a fixed location.
static bool store_key(const std::string& key_path, const std::string& tmp_path,
                      const android::vold::KeyAuthentication& auth, const std::string& key) {
    if (path_exists(key_path)) {
        LOG(ERROR) << "Already exists, cannot create key at: " << key_path;
        return false;
    }
    if (path_exists(tmp_path)) {
        android::vold::destroyKey(tmp_path);  // May be partially created so ignore errors
    }
    if (!android::vold::storeKey(tmp_path, auth, key)) return false;
    if (rename(tmp_path.c_str(), key_path.c_str()) != 0) {
        PLOG(ERROR) << "Unable to move new key to location: " << key_path;
        return false;
    }
    LOG(DEBUG) << "Created key " << key_path;
    return true;
}

static bool create_and_install_user_keys(userid_t user_id, bool create_ephemeral) {
    std::string de_key, ce_key;
    if (!random_key(&de_key)) return false;
    if (!random_key(&ce_key)) return false;
    if (create_ephemeral) {
        // If the key should be created as ephemeral, don't store it.
        s_ephemeral_users.insert(user_id);
    } else {
        auto const directory_path = get_ce_key_directory_path(user_id);
        if (!prepare_dir(directory_path, 0700, AID_ROOT, AID_ROOT)) return false;
        auto const paths = get_ce_key_paths(directory_path);
        std::string ce_key_path;
        if (!get_ce_key_new_path(directory_path, paths, &ce_key_path)) return false;
        if (!store_key(ce_key_path, user_key_temp,
                kEmptyAuthentication, ce_key)) return false;
        fixate_user_ce_key(directory_path, ce_key_path, paths);
        // Write DE key second; once this is written, all is good.
        if (!store_key(get_de_key_path(user_id), user_key_temp,
                kEmptyAuthentication, de_key)) return false;
    }
    std::string de_raw_ref;
    if (!install_key(de_key, &de_raw_ref)) return false;
    s_de_key_raw_refs[user_id] = de_raw_ref;
    std::string ce_raw_ref;
    if (!install_key(ce_key, &ce_raw_ref)) return false;
    s_ce_keys[user_id] = ce_key;
    s_ce_key_raw_refs[user_id] = ce_raw_ref;
    LOG(DEBUG) << "Created keys for user " << user_id;
    return true;
}

static bool lookup_key_ref(const std::map<userid_t, std::string>& key_map, userid_t user_id,
                           std::string* raw_ref) {
    auto refi = key_map.find(user_id);
    if (refi == key_map.end()) {
        LOG(ERROR) << "Cannot find key for " << user_id;
        return false;
    }
    *raw_ref = refi->second;
    return true;
}

static bool ensure_policy(const std::string& raw_ref, const std::string& path) {
    if (e4crypt_policy_ensure(path.c_str(),
                              raw_ref.data(), raw_ref.size(),
                              cryptfs_get_file_encryption_mode()) != 0) {
        LOG(ERROR) << "Failed to set policy on: " << path;
        return false;
    }
    return true;
}

static bool is_numeric(const char* name) {
    for (const char* p = name; *p != '\0'; p++) {
        if (!isdigit(*p)) return false;
    }
    return true;
}

static bool load_all_de_keys() {
    auto de_dir = user_key_dir + "/de";
    auto dirp = std::unique_ptr<DIR, int (*)(DIR*)>(opendir(de_dir.c_str()), closedir);
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
            if (!android::vold::retrieveKey(key_path, kEmptyAuthentication, &key)) return false;
            std::string raw_ref;
            if (!install_key(key, &raw_ref)) return false;
            s_de_key_raw_refs[user_id] = raw_ref;
            LOG(DEBUG) << "Installed de key for user " << user_id;
        }
    }
    // ext4enc:TODO: go through all DE directories, ensure that all user dirs have the
    // correct policy set on them, and that no rogue ones exist.
    return true;
}

bool e4crypt_initialize_global_de() {
    LOG(INFO) << "e4crypt_initialize_global_de";

    if (s_global_de_initialized) {
        LOG(INFO) << "Already initialized";
        return true;
    }

    std::string mode_filename = std::string("/data") + e4crypt_key_mode;
    std::string mode = cryptfs_get_file_encryption_mode();
    if (!android::base::WriteStringToFile(mode, mode_filename)) {
        PLOG(ERROR) << "Cannot save type";
        return false;
    }

    std::string device_key;
    if (path_exists(device_key_path)) {
        if (!android::vold::retrieveKey(device_key_path,
                kEmptyAuthentication, &device_key)) return false;
    } else {
        LOG(INFO) << "Creating new key";
        if (!random_key(&device_key)) return false;
        if (!store_key(device_key_path, device_key_temp,
                kEmptyAuthentication, device_key)) return false;
    }

    std::string device_key_ref;
    if (!install_key(device_key, &device_key_ref)) {
        LOG(ERROR) << "Failed to install device key";
        return false;
    }

    std::string ref_filename = std::string("/data") + e4crypt_key_ref;
    if (!android::base::WriteStringToFile(device_key_ref, ref_filename)) {
        PLOG(ERROR) << "Cannot save key reference";
        return false;
    }

    s_global_de_initialized = true;
    return true;
}

bool e4crypt_init_user0() {
    LOG(DEBUG) << "e4crypt_init_user0";
    if (e4crypt_is_native()) {
        if (!prepare_dir(user_key_dir, 0700, AID_ROOT, AID_ROOT)) return false;
        if (!prepare_dir(user_key_dir + "/ce", 0700, AID_ROOT, AID_ROOT)) return false;
        if (!prepare_dir(user_key_dir + "/de", 0700, AID_ROOT, AID_ROOT)) return false;
        if (!path_exists(get_de_key_path(0))) {
            if (!create_and_install_user_keys(0, false)) return false;
        }
        // TODO: switch to loading only DE_0 here once framework makes
        // explicit calls to install DE keys for secondary users
        if (!load_all_de_keys()) return false;
    }
    // We can only safely prepare DE storage here, since CE keys are probably
    // entangled with user credentials.  The framework will always prepare CE
    // storage once CE keys are installed.
    if (!e4crypt_prepare_user_storage(nullptr, 0, 0, FLAG_STORAGE_DE)) {
        LOG(ERROR) << "Failed to prepare user 0 storage";
        return false;
    }

    // If this is a non-FBE device that recently left an emulated mode,
    // restore user data directories to known-good state.
    if (!e4crypt_is_native() && !e4crypt_is_emulated()) {
        e4crypt_unlock_user_key(0, 0, "!", "!");
    }

    return true;
}

bool e4crypt_vold_create_user_key(userid_t user_id, int serial, bool ephemeral) {
    LOG(DEBUG) << "e4crypt_vold_create_user_key for " << user_id << " serial " << serial;
    if (!e4crypt_is_native()) {
        return true;
    }
    // FIXME test for existence of key that is not loaded yet
    if (s_ce_key_raw_refs.count(user_id) != 0) {
        LOG(ERROR) << "Already exists, can't e4crypt_vold_create_user_key for " << user_id
                   << " serial " << serial;
        // FIXME should we fail the command?
        return true;
    }
    if (!create_and_install_user_keys(user_id, ephemeral)) {
        return false;
    }
    return true;
}

bool e4crypt_destroy_user_key(userid_t user_id) {
    LOG(DEBUG) << "e4crypt_destroy_user_key(" << user_id << ")";
    if (!e4crypt_is_native()) {
        return true;
    }
    bool success = true;
    s_ce_keys.erase(user_id);
    std::string raw_ref;
    s_ce_key_raw_refs.erase(user_id);
    s_de_key_raw_refs.erase(user_id);
    auto it = s_ephemeral_users.find(user_id);
    if (it != s_ephemeral_users.end()) {
        s_ephemeral_users.erase(it);
    } else {
        for (auto const path: get_ce_key_paths(get_ce_key_directory_path(user_id))) {
            success &= android::vold::destroyKey(path);
        }
        auto de_key_path = get_de_key_path(user_id);
        if (path_exists(de_key_path)) {
            success &= android::vold::destroyKey(de_key_path);
        } else {
            LOG(INFO) << "Not present so not erasing: " << de_key_path;
        }
    }
    return success;
}

static bool emulated_lock(const std::string& path) {
    if (chmod(path.c_str(), 0000) != 0) {
        PLOG(ERROR) << "Failed to chmod " << path;
        return false;
    }
#if EMULATED_USES_SELINUX
    if (setfilecon(path.c_str(), "u:object_r:storage_stub_file:s0") != 0) {
        PLOG(WARNING) << "Failed to setfilecon " << path;
        return false;
    }
#endif
    return true;
}

static bool emulated_unlock(const std::string& path, mode_t mode) {
    if (chmod(path.c_str(), mode) != 0) {
        PLOG(ERROR) << "Failed to chmod " << path;
        // FIXME temporary workaround for b/26713622
        if (e4crypt_is_emulated()) return false;
    }
#if EMULATED_USES_SELINUX
    if (selinux_android_restorecon(path.c_str(), SELINUX_ANDROID_RESTORECON_FORCE) != 0) {
        PLOG(WARNING) << "Failed to restorecon " << path;
        // FIXME temporary workaround for b/26713622
        if (e4crypt_is_emulated()) return false;
    }
#endif
    return true;
}

static bool parse_hex(const char* hex, std::string* result) {
    if (strcmp("!", hex) == 0) {
        *result = "";
        return true;
    }
    if (android::vold::HexToStr(hex, *result) != 0) {
        LOG(ERROR) << "Invalid FBE hex string";  // Don't log the string for security reasons
        return false;
    }
    return true;
}

bool e4crypt_add_user_key_auth(userid_t user_id, int serial, const char* token_hex,
                          const char* secret_hex) {
    LOG(DEBUG) << "e4crypt_add_user_key_auth " << user_id << " serial=" << serial
               << " token_present=" << (strcmp(token_hex, "!") != 0);
    if (!e4crypt_is_native()) return true;
    if (s_ephemeral_users.count(user_id) != 0) return true;
    std::string token, secret;
    if (!parse_hex(token_hex, &token)) return false;
    if (!parse_hex(secret_hex, &secret)) return false;
    auto auth = secret.empty() ? kEmptyAuthentication
                                   : android::vold::KeyAuthentication(token, secret);
    auto it = s_ce_keys.find(user_id);
    if (it == s_ce_keys.end()) {
        LOG(ERROR) << "Key not loaded into memory, can't change for user " << user_id;
        return false;
    }
    auto ce_key = it->second;
    auto const directory_path = get_ce_key_directory_path(user_id);
    auto const paths = get_ce_key_paths(directory_path);
    std::string ce_key_path;
    if (!get_ce_key_new_path(directory_path, paths, &ce_key_path)) return false;
    if (!store_key(ce_key_path, user_key_temp, auth, ce_key)) return false;
    return true;
}

bool e4crypt_fixate_newest_user_key_auth(userid_t user_id) {
    LOG(DEBUG) << "e4crypt_fixate_newest_user_key_auth " << user_id;
    if (!e4crypt_is_native()) return true;
    if (s_ephemeral_users.count(user_id) != 0) return true;
    auto const directory_path = get_ce_key_directory_path(user_id);
    auto const paths = get_ce_key_paths(directory_path);
    if (paths.empty()) {
        LOG(ERROR) << "No ce keys present, cannot fixate for user " << user_id;
        return false;
    }
    fixate_user_ce_key(directory_path, paths[0], paths);
    return true;
}

// TODO: rename to 'install' for consistency, and take flags to know which keys to install
bool e4crypt_unlock_user_key(userid_t user_id, int serial, const char* token_hex,
                             const char* secret_hex) {
    LOG(DEBUG) << "e4crypt_unlock_user_key " << user_id << " serial=" << serial
               << " token_present=" << (strcmp(token_hex, "!") != 0);
    if (e4crypt_is_native()) {
        if (s_ce_key_raw_refs.count(user_id) != 0) {
            LOG(WARNING) << "Tried to unlock already-unlocked key for user " << user_id;
            return true;
        }
        std::string token, secret;
        if (!parse_hex(token_hex, &token)) return false;
        if (!parse_hex(secret_hex, &secret)) return false;
        android::vold::KeyAuthentication auth(token, secret);
        if (!read_and_install_user_ce_key(user_id, auth)) {
            LOG(ERROR) << "Couldn't read key for " << user_id;
            return false;
        }
    } else {
        // When in emulation mode, we just use chmod. However, we also
        // unlock directories when not in emulation mode, to bring devices
        // back into a known-good state.
        if (!emulated_unlock(android::vold::BuildDataSystemCePath(user_id), 0771) ||
            !emulated_unlock(android::vold::BuildDataMiscCePath(user_id), 01771) ||
            !emulated_unlock(android::vold::BuildDataMediaCePath(nullptr, user_id), 0770) ||
            !emulated_unlock(android::vold::BuildDataUserCePath(nullptr, user_id), 0771)) {
            LOG(ERROR) << "Failed to unlock user " << user_id;
            return false;
        }
    }
    return true;
}

// TODO: rename to 'evict' for consistency
bool e4crypt_lock_user_key(userid_t user_id) {
    if (e4crypt_is_native()) {
        // TODO: remove from kernel keyring
    } else if (e4crypt_is_emulated()) {
        // When in emulation mode, we just use chmod
        if (!emulated_lock(android::vold::BuildDataSystemCePath(user_id)) ||
            !emulated_lock(android::vold::BuildDataMiscCePath(user_id)) ||
            !emulated_lock(android::vold::BuildDataMediaCePath(nullptr, user_id)) ||
            !emulated_lock(android::vold::BuildDataUserCePath(nullptr, user_id))) {
            LOG(ERROR) << "Failed to lock user " << user_id;
            return false;
        }
    }

    return true;
}

bool e4crypt_prepare_user_storage(const char* volume_uuid, userid_t user_id, int serial,
        int flags) {
    LOG(DEBUG) << "e4crypt_prepare_user_storage for volume " << escape_null(volume_uuid)
               << ", user " << user_id << ", serial " << serial << ", flags " << flags;

    if (flags & FLAG_STORAGE_DE) {
        // DE_sys key
        auto system_legacy_path = android::vold::BuildDataSystemLegacyPath(user_id);
        auto misc_legacy_path = android::vold::BuildDataMiscLegacyPath(user_id);
        auto profiles_de_path = android::vold::BuildDataProfilesDePath(user_id);
        auto foreign_de_path = android::vold::BuildDataProfilesForeignDexDePath(user_id);

        // DE_n key
        auto system_de_path = android::vold::BuildDataSystemDePath(user_id);
        auto misc_de_path = android::vold::BuildDataMiscDePath(user_id);
        auto user_de_path = android::vold::BuildDataUserDePath(volume_uuid, user_id);

        if (!prepare_dir(system_legacy_path, 0700, AID_SYSTEM, AID_SYSTEM)) return false;
#if MANAGE_MISC_DIRS
        if (!prepare_dir(misc_legacy_path, 0750, multiuser_get_uid(user_id, AID_SYSTEM),
                multiuser_get_uid(user_id, AID_EVERYBODY))) return false;
#endif
        if (!prepare_dir(profiles_de_path, 0771, AID_SYSTEM, AID_SYSTEM)) return false;
        if (!prepare_dir(foreign_de_path, 0773, AID_SYSTEM, AID_SYSTEM)) return false;

        if (!prepare_dir(system_de_path, 0770, AID_SYSTEM, AID_SYSTEM)) return false;
        if (!prepare_dir(misc_de_path, 01771, AID_SYSTEM, AID_MISC)) return false;
        if (!prepare_dir(user_de_path, 0771, AID_SYSTEM, AID_SYSTEM)) return false;

        // For now, FBE is only supported on internal storage
        if (e4crypt_is_native() && volume_uuid == nullptr) {
            std::string de_raw_ref;
            if (!lookup_key_ref(s_de_key_raw_refs, user_id, &de_raw_ref)) return false;
            if (!ensure_policy(de_raw_ref, system_de_path)) return false;
            if (!ensure_policy(de_raw_ref, misc_de_path)) return false;
            if (!ensure_policy(de_raw_ref, user_de_path)) return false;
        }
    }

    if (flags & FLAG_STORAGE_CE) {
        // CE_n key
        auto system_ce_path = android::vold::BuildDataSystemCePath(user_id);
        auto misc_ce_path = android::vold::BuildDataMiscCePath(user_id);
        auto media_ce_path = android::vold::BuildDataMediaCePath(volume_uuid, user_id);
        auto user_ce_path = android::vold::BuildDataUserCePath(volume_uuid, user_id);

        if (!prepare_dir(system_ce_path, 0770, AID_SYSTEM, AID_SYSTEM)) return false;
        if (!prepare_dir(misc_ce_path, 01771, AID_SYSTEM, AID_MISC)) return false;
        if (!prepare_dir(media_ce_path, 0770, AID_MEDIA_RW, AID_MEDIA_RW)) return false;
        if (!prepare_dir(user_ce_path, 0771, AID_SYSTEM, AID_SYSTEM)) return false;

        // For now, FBE is only supported on internal storage
        if (e4crypt_is_native() && volume_uuid == nullptr) {
            std::string ce_raw_ref;
            if (!lookup_key_ref(s_ce_key_raw_refs, user_id, &ce_raw_ref)) return false;
            if (!ensure_policy(ce_raw_ref, system_ce_path)) return false;
            if (!ensure_policy(ce_raw_ref, misc_ce_path)) return false;
            if (!ensure_policy(ce_raw_ref, media_ce_path)) return false;
            if (!ensure_policy(ce_raw_ref, user_ce_path)) return false;

            // Now that credentials have been installed, we can run restorecon
            // over these paths
            // NOTE: these paths need to be kept in sync with libselinux
            android::vold::RestoreconRecursive(system_ce_path);
            android::vold::RestoreconRecursive(misc_ce_path);
        }
    }

    return true;
}

bool e4crypt_destroy_user_storage(const char* volume_uuid, userid_t user_id, int flags) {
    LOG(DEBUG) << "e4crypt_destroy_user_storage for volume " << escape_null(volume_uuid)
               << ", user " << user_id << ", flags " << flags;
    bool res = true;

    if (flags & FLAG_STORAGE_DE) {
        // DE_sys key
        auto system_legacy_path = android::vold::BuildDataSystemLegacyPath(user_id);
        auto misc_legacy_path = android::vold::BuildDataMiscLegacyPath(user_id);
        auto profiles_de_path = android::vold::BuildDataProfilesDePath(user_id);
        auto foreign_de_path = android::vold::BuildDataProfilesForeignDexDePath(user_id);

        // DE_n key
        auto system_de_path = android::vold::BuildDataSystemDePath(user_id);
        auto misc_de_path = android::vold::BuildDataMiscDePath(user_id);
        auto user_de_path = android::vold::BuildDataUserDePath(volume_uuid, user_id);

        if (volume_uuid == nullptr) {
            res &= destroy_dir(system_legacy_path);
#if MANAGE_MISC_DIRS
            res &= destroy_dir(misc_legacy_path);
#endif
            res &= destroy_dir(profiles_de_path);
            res &= destroy_dir(foreign_de_path);
            res &= destroy_dir(system_de_path);
            res &= destroy_dir(misc_de_path);
        }
        res &= destroy_dir(user_de_path);
    }

    if (flags & FLAG_STORAGE_CE) {
        // CE_n key
        auto system_ce_path = android::vold::BuildDataSystemCePath(user_id);
        auto misc_ce_path = android::vold::BuildDataMiscCePath(user_id);
        auto media_ce_path = android::vold::BuildDataMediaCePath(volume_uuid, user_id);
        auto user_ce_path = android::vold::BuildDataUserCePath(volume_uuid, user_id);

        if (volume_uuid == nullptr) {
            res &= destroy_dir(system_ce_path);
            res &= destroy_dir(misc_ce_path);
        }
        res &= destroy_dir(media_ce_path);
        res &= destroy_dir(user_ce_path);
    }

    return res;
}
