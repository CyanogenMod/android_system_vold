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
#include <string>
#include <sstream>

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

    // How long do we store passwords for?
    const int password_max_age_seconds = 60;

    const std::string user_key_dir = std::string() + DATA_MNT_POINT + "/misc/vold/user_keys";

    // How is device encrypted
    struct keys {
        std::string master_key;
        std::string password;
        time_t expiry_time;
    };
    std::map<std::string, keys> s_key_store;
    // Maps the key paths of ephemeral keys to the keys
    std::map<std::string, std::string> s_ephemeral_user_keys;
    // Map user serial numbers to key references
    std::map<int, std::string> s_key_raw_refs;

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

    namespace tag {
        const char* magic = "magic";
        const char* major_version = "major_version";
        const char* minor_version = "minor_version";
        const char* flags = "flags";
        const char* crypt_type = "crypt_type";
        const char* failed_decrypt_count = "failed_decrypt_count";
        const char* crypto_type_name = "crypto_type_name";
        const char* master_key = "master_key";
        const char* salt = "salt";
        const char* kdf_type = "kdf_type";
        const char* N_factor = "N_factor";
        const char* r_factor = "r_factor";
        const char* p_factor = "p_factor";
        const char* keymaster_blob = "keymaster_blob";
        const char* scrypted_intermediate_key = "scrypted_intermediate_key";
    }
}

static std::string e4crypt_install_key(const std::string &key);

static int put_crypt_ftr_and_key(const crypt_mnt_ftr& crypt_ftr,
                                 UnencryptedProperties& props)
{
    SLOGI("Putting crypt footer");

    bool success = props.Set<int>(tag::magic, crypt_ftr.magic)
      && props.Set<int>(tag::major_version, crypt_ftr.major_version)
      && props.Set<int>(tag::minor_version, crypt_ftr.minor_version)
      && props.Set<int>(tag::flags, crypt_ftr.flags)
      && props.Set<int>(tag::crypt_type, crypt_ftr.crypt_type)
      && props.Set<int>(tag::failed_decrypt_count,
                        crypt_ftr.failed_decrypt_count)
      && props.Set<std::string>(tag::crypto_type_name,
                                std::string(reinterpret_cast<const char*>(crypt_ftr.crypto_type_name)))
      && props.Set<std::string>(tag::master_key,
                                std::string((const char*) crypt_ftr.master_key,
                                            crypt_ftr.keysize))
      && props.Set<std::string>(tag::salt,
                                std::string((const char*) crypt_ftr.salt,
                                            SALT_LEN))
      && props.Set<int>(tag::kdf_type, crypt_ftr.kdf_type)
      && props.Set<int>(tag::N_factor, crypt_ftr.N_factor)
      && props.Set<int>(tag::r_factor, crypt_ftr.r_factor)
      && props.Set<int>(tag::p_factor, crypt_ftr.p_factor)
      && props.Set<std::string>(tag::keymaster_blob,
                                std::string((const char*) crypt_ftr.keymaster_blob,
                                            crypt_ftr.keymaster_blob_size))
      && props.Set<std::string>(tag::scrypted_intermediate_key,
                                std::string((const char*) crypt_ftr.scrypted_intermediate_key,
                                            SCRYPT_LEN));
    return success ? 0 : -1;
}

static int get_crypt_ftr_and_key(crypt_mnt_ftr& crypt_ftr,
                                 const UnencryptedProperties& props)
{
    memset(&crypt_ftr, 0, sizeof(crypt_ftr));
    crypt_ftr.magic = props.Get<int>(tag::magic);
    crypt_ftr.major_version = props.Get<int>(tag::major_version);
    crypt_ftr.minor_version = props.Get<int>(tag::minor_version);
    crypt_ftr.ftr_size = sizeof(crypt_ftr);
    crypt_ftr.flags = props.Get<int>(tag::flags);
    crypt_ftr.crypt_type = props.Get<int>(tag::crypt_type);
    crypt_ftr.failed_decrypt_count = props.Get<int>(tag::failed_decrypt_count);
    std::string crypto_type_name = props.Get<std::string>(tag::crypto_type_name);
    strlcpy(reinterpret_cast<char*>(crypt_ftr.crypto_type_name),
            crypto_type_name.c_str(),
            sizeof(crypt_ftr.crypto_type_name));
    std::string master_key = props.Get<std::string>(tag::master_key);
    crypt_ftr.keysize = master_key.size();
    if (crypt_ftr.keysize > sizeof(crypt_ftr.master_key)) {
        SLOGE("Master key size too long");
        return -1;
    }
    memcpy(crypt_ftr.master_key, &master_key[0], crypt_ftr.keysize);
    std::string salt = props.Get<std::string>(tag::salt);
    if (salt.size() != SALT_LEN) {
        SLOGE("Salt wrong length");
        return -1;
    }
    memcpy(crypt_ftr.salt, &salt[0], SALT_LEN);
    crypt_ftr.kdf_type = props.Get<int>(tag::kdf_type);
    crypt_ftr.N_factor = props.Get<int>(tag::N_factor);
    crypt_ftr.r_factor = props.Get<int>(tag::r_factor);
    crypt_ftr.p_factor = props.Get<int>(tag::p_factor);
    std::string keymaster_blob = props.Get<std::string>(tag::keymaster_blob);
    crypt_ftr.keymaster_blob_size = keymaster_blob.size();
    if (crypt_ftr.keymaster_blob_size > sizeof(crypt_ftr.keymaster_blob)) {
        SLOGE("Keymaster blob too long");
        return -1;
    }
    memcpy(crypt_ftr.keymaster_blob, &keymaster_blob[0],
           crypt_ftr.keymaster_blob_size);
    std::string scrypted_intermediate_key = props.Get<std::string>(tag::scrypted_intermediate_key);
    if (scrypted_intermediate_key.size() != SCRYPT_LEN) {
        SLOGE("scrypted intermediate key wrong length");
        return -1;
    }
    memcpy(crypt_ftr.scrypted_intermediate_key, &scrypted_intermediate_key[0],
           SCRYPT_LEN);

    return 0;
}

static UnencryptedProperties GetProps(const char* path)
{
    return UnencryptedProperties(path);
}

static UnencryptedProperties GetAltProps(const char* path)
{
    return UnencryptedProperties((std::string() + path + "/tmp_mnt").c_str());
}

static UnencryptedProperties GetPropsOrAltProps(const char* path)
{
    UnencryptedProperties props = GetProps(path);
    if (props.OK()) {
        return props;
    }
    return GetAltProps(path);
}

int e4crypt_enable(const char* path)
{
    // Already enabled?
    if (s_key_store.find(path) != s_key_store.end()) {
        return 0;
    }

    // Not an encryptable device?
    UnencryptedProperties key_props = GetProps(path).GetChild(properties::key);
    if (!key_props.OK()) {
        return 0;
    }

    if (key_props.Get<std::string>(tag::master_key).empty()) {
        crypt_mnt_ftr ftr;
        if (cryptfs_create_default_ftr(&ftr, key_length)) {
            SLOGE("Failed to create crypto footer");
            return -1;
        }

        // Scrub fields not used by ext4enc
        ftr.persist_data_offset[0] = 0;
        ftr.persist_data_offset[1] = 0;
        ftr.persist_data_size = 0;

        if (put_crypt_ftr_and_key(ftr, key_props)) {
            SLOGE("Failed to write crypto footer");
            return -1;
        }

        crypt_mnt_ftr ftr2;
        if (get_crypt_ftr_and_key(ftr2, key_props)) {
            SLOGE("Failed to read crypto footer back");
            return -1;
        }

        if (memcmp(&ftr, &ftr2, sizeof(ftr)) != 0) {
            SLOGE("Crypto footer not correctly written");
            return -1;
        }
    }

    if (!UnencryptedProperties(path).Remove(properties::ref)) {
        SLOGE("Failed to remove key ref");
        return -1;
    }

    return e4crypt_check_passwd(path, "");
}

int e4crypt_change_password(const char* path, int crypt_type,
                            const char* password)
{
    SLOGI("e4crypt_change_password");
    auto key_props = GetProps(path).GetChild(properties::key);

    crypt_mnt_ftr ftr;
    if (get_crypt_ftr_and_key(ftr, key_props)) {
        SLOGE("Failed to read crypto footer back");
        return -1;
    }

    auto mki = s_key_store.find(path);
    if (mki == s_key_store.end()) {
        SLOGE("No stored master key - can't change password");
        return -1;
    }

    const unsigned char* master_key_bytes
        = reinterpret_cast<const unsigned char*>(&mki->second.master_key[0]);

    if (cryptfs_set_password(&ftr, password, master_key_bytes)) {
        SLOGE("Failed to set password");
        return -1;
    }

    ftr.crypt_type = crypt_type;

    if (put_crypt_ftr_and_key(ftr, key_props)) {
        SLOGE("Failed to write crypto footer");
        return -1;
    }

    if (!UnencryptedProperties(path).Set(properties::is_default,
                            crypt_type == CRYPT_TYPE_DEFAULT)) {
        SLOGE("Failed to update default flag");
        return -1;
    }

    return 0;
}

int e4crypt_crypto_complete(const char* path)
{
    SLOGI("ext4 crypto complete called on %s", path);
    auto key_props = GetPropsOrAltProps(path).GetChild(properties::key);
    if (key_props.Get<std::string>(tag::master_key).empty()) {
        SLOGI("No master key, so not ext4enc");
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

int e4crypt_check_passwd(const char* path, const char* password)
{
    SLOGI("e4crypt_check_password");
    auto props = GetPropsOrAltProps(path);
    auto key_props = props.GetChild(properties::key);

    crypt_mnt_ftr ftr;
    if (get_crypt_ftr_and_key(ftr, key_props)) {
        SLOGE("Failed to read crypto footer back");
        return -1;
    }

    unsigned char master_key_bytes[key_length / 8];
    if (cryptfs_get_master_key (&ftr, password, master_key_bytes)){
        SLOGI("Incorrect password");
        ftr.failed_decrypt_count++;
        if (put_crypt_ftr_and_key(ftr, key_props)) {
            SLOGW("Failed to update failed_decrypt_count");
        }
        return ftr.failed_decrypt_count;
    }

    if (ftr.failed_decrypt_count) {
        ftr.failed_decrypt_count = 0;
        if (put_crypt_ftr_and_key(ftr, key_props)) {
            SLOGW("Failed to reset failed_decrypt_count");
        }
    }
    std::string master_key(reinterpret_cast<char*>(master_key_bytes),
                           sizeof(master_key_bytes));

    struct timespec now;
    clock_gettime(CLOCK_BOOTTIME, &now);
    s_key_store[path] = keys{master_key, password,
                             now.tv_sec + password_max_age_seconds};
    auto raw_ref = e4crypt_install_key(master_key);
    if (raw_ref.empty()) {
        return -1;
    }

    // Save reference to key so we can set policy later
    if (!props.Set(properties::ref, raw_ref)) {
        SLOGE("Cannot save key reference");
        return -1;
    }

    return 0;
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

static int e4crypt_install_key(const ext4_encryption_key &ext4_key, const std::string &ref)
{
    key_serial_t device_keyring = e4crypt_keyring();
    key_serial_t key_id = add_key("logon", ref.c_str(),
                                  (void*)&ext4_key, sizeof(ext4_key),
                                  device_keyring);
    if (key_id == -1) {
        PLOG(ERROR) << "Failed to insert key into keyring " << device_keyring;
        return -1;
    }
    LOG(INFO) << "Added key " << key_id << " (" << ref << ") to keyring "
        << device_keyring << " in process " << getpid();
    return 0;
}

// Install password into global keyring
// Return raw key reference for use in policy
static std::string e4crypt_install_key(const std::string &key)
{
    auto ext4_key = fill_key(key);
    auto raw_ref = generate_key_ref(ext4_key.raw, ext4_key.size);
    auto ref = keyname(raw_ref);
    if (e4crypt_install_key(ext4_key, ref) == -1) {
        return "";
    }
    return raw_ref;
}

int e4crypt_restart(const char* path)
{
    SLOGI("e4crypt_restart");

    int rc = 0;

    SLOGI("ext4 restart called on %s", path);
    property_set("vold.decrypt", "trigger_reset_main");
    SLOGI("Just asked init to shut down class main");
    sleep(2);

    std::string tmp_path = std::string() + path + "/tmp_mnt";

    rc = wait_and_unmount(tmp_path.c_str(), true);
    if (rc) {
        SLOGE("umount %s failed with rc %d, msg %s",
              tmp_path.c_str(), rc, strerror(errno));
        return rc;
    }

    rc = wait_and_unmount(path, true);
    if (rc) {
        SLOGE("umount %s failed with rc %d, msg %s",
              path, rc, strerror(errno));
        return rc;
    }

    return 0;
}

int e4crypt_get_password_type(const char* path)
{
    SLOGI("e4crypt_get_password_type");
    return GetPropsOrAltProps(path).GetChild(properties::key)
      .Get<int>(tag::crypt_type, CRYPT_TYPE_DEFAULT);
}

const char* e4crypt_get_password(const char* path)
{
    SLOGI("e4crypt_get_password");

    auto i = s_key_store.find(path);
    if (i == s_key_store.end()) {
        return 0;
    }

    struct timespec now;
    clock_gettime(CLOCK_BOOTTIME, &now);
    if (i->second.expiry_time < now.tv_sec) {
        e4crypt_clear_password(path);
        return 0;
    }

    return i->second.password.c_str();
}

void e4crypt_clear_password(const char* path)
{
    SLOGI("e4crypt_clear_password");

    auto i = s_key_store.find(path);
    if (i == s_key_store.end()) {
        return;
    }

    memset(&i->second.password[0], 0, i->second.password.size());
    i->second.password = std::string();
}

int e4crypt_get_field(const char* path, const char* fieldname,
                      char* value, size_t len)
{
    auto v = GetPropsOrAltProps(path).GetChild(properties::props)
      .Get<std::string>(fieldname);

    if (v == "") {
        return CRYPTO_GETFIELD_ERROR_NO_FIELD;
    }

    if (v.length() >= len) {
        return CRYPTO_GETFIELD_ERROR_BUF_TOO_SMALL;
    }

    strlcpy(value, v.c_str(), len);
    return 0;
}

int e4crypt_set_field(const char* path, const char* fieldname,
                      const char* value)
{
    return GetPropsOrAltProps(path).GetChild(properties::props)
        .Set(fieldname, std::string(value)) ? 0 : -1;
}

static std::string get_key_path(userid_t user_id) {
    return StringPrintf("%s/user_%d/current", user_key_dir.c_str(), user_id);
}

static bool e4crypt_is_key_ephemeral(const std::string &key_path) {
    return s_ephemeral_user_keys.find(key_path) != s_ephemeral_user_keys.end();
}

static bool read_user_key(userid_t user_id, std::string &key)
{
    const auto key_path = get_key_path(user_id);
    const auto ephemeral_key_it = s_ephemeral_user_keys.find(key_path);
    if (ephemeral_key_it != s_ephemeral_user_keys.end()) {
        key = ephemeral_key_it->second;
        return true;
    }
    if (!android::vold::retrieveKey(key_path, key)) return false;
    if (key.size() != key_length/8) {
        LOG(ERROR) << "Wrong size key " << key.size() << " in " << key_path;
        return false;
    }
    return true;
}

static bool prepare_dir(const std::string &dir, mode_t mode, uid_t uid, gid_t gid) {
    if (fs_prepare_dir(dir.c_str(), mode, uid, gid) != 0) {
        PLOG(ERROR) << "Failed to prepare " << dir;
        return false;
    }
    return true;
}

static bool create_user_key(userid_t user_id, bool create_ephemeral) {
    const auto key_path = get_key_path(user_id);
    std::string key;
    if (android::vold::ReadRandomBytes(key_length / 8, key) != 0) {
        // TODO status_t plays badly with PLOG, fix it.
        LOG(ERROR) << "Random read failed";
        return false;
    }
    if (create_ephemeral) {
        // If the key should be created as ephemeral, store it in memory only.
        s_ephemeral_user_keys[key_path] = key;
    } else {
        if (!prepare_dir(user_key_dir + "/user_" + std::to_string(user_id),
            0700, AID_ROOT, AID_ROOT)) return false;
        if (!android::vold::storeKey(key_path, key)) return false;
    }
    LOG(DEBUG) << "Created key " << key_path;
    return true;
}

static int e4crypt_set_user_policy(userid_t user_id, int serial, std::string& path) {
    LOG(DEBUG) << "e4crypt_set_user_policy for " << user_id << " serial " << serial;
    if (s_key_raw_refs.count(serial) != 1) {
        LOG(ERROR) << "Key unknown, can't e4crypt_set_user_policy for "
            << user_id << " serial " << serial;
        return -1;
    }
    auto raw_ref = s_key_raw_refs[serial];
    return do_policy_set(path.c_str(), raw_ref.data(), raw_ref.size());
}

int e4crypt_init_user0() {
    LOG(DEBUG) << "e4crypt_init_user0";
    if (e4crypt_is_native()) {
        if (!prepare_dir(user_key_dir, 0700, AID_ROOT, AID_ROOT)) return -1;
        std::string user_key;
        if (!read_user_key(0, user_key)) {
            // FIXME if the key exists and we just failed to read it, this destroys it.
            if (!create_user_key(0, false)) {
                return -1;
            }
            if (!read_user_key(0, user_key)) {
                LOG(ERROR) << "Couldn't read just-created key for user 0";
                return -1;
            }
        }
        auto raw_ref = e4crypt_install_key(user_key);
        if (raw_ref.empty()) {
            return -1;
        }
        s_key_raw_refs[0] = raw_ref;
    }
    // Ignore failures. FIXME this is horrid
    e4crypt_prepare_user_storage(nullptr, 0, 0, false);
    return 0;
}

int e4crypt_vold_create_user_key(userid_t user_id, int serial, bool ephemeral) {
    LOG(DEBUG) << "e4crypt_vold_create_user_key for " << user_id << " serial " << serial;
    if (!e4crypt_is_native()) {
        return 0;
    }
    std::string key;
    if (read_user_key(user_id, key)) {
        LOG(ERROR) << "Already exists, can't e4crypt_vold_create_user_key for "
            << user_id << " serial " << serial;
        // FIXME should we fail the command?
        return 0;
    }
    if (!create_user_key(user_id, ephemeral)) {
        return -1;
    }
    if (e4crypt_unlock_user_key(user_id, serial, nullptr) != 0) {
        return -1;
    }
    // TODO: create second key for user_de data
    return 0;
}

static bool evict_user_key(userid_t user_id) {
    auto key_path = get_key_path(user_id);
    std::string key;
    if (!read_user_key(user_id, key)) return false;
    auto ext4_key = fill_key(key);
    auto ref = keyname(generate_key_ref(ext4_key.raw, ext4_key.size));
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
    // TODO: destroy second key for user_de data
    bool evict_success = evict_user_key(user_id);
    auto key_path = get_key_path(user_id);
    if (e4crypt_is_key_ephemeral(key_path)) {
        s_ephemeral_user_keys.erase(key_path);
    } else {
        if (!android::vold::destroyKey(key_path)) {
            return -1;
        }
    }
    return evict_success ? 0 : -1;
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
        std::string user_key;
        if (!read_user_key(user_id, user_key)) {
            LOG(ERROR) << "Couldn't read key for " << user_id;
            return -1;
        }
        auto raw_ref = e4crypt_install_key(user_key);
        if (raw_ref.empty()) {
            return -1;
        }
        s_key_raw_refs[serial] = raw_ref;
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
        if (e4crypt_set_user_policy(user_id, serial, system_ce_path)
                || e4crypt_set_user_policy(user_id, serial, media_ce_path)
                || e4crypt_set_user_policy(user_id, serial, user_ce_path)) {
            return -1;
        }
    }

    return 0;
}
