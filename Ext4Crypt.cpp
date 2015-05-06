#include "Ext4Crypt.h"

#include <iomanip>
#include <map>
#include <fstream>
#include <string>
#include <sstream>

#include <errno.h>
#include <sys/mount.h>
#include <cutils/properties.h>
#include <openssl/sha.h>

#include "unencrypted_properties.h"
#include "key_control.h"
#include "cryptfs.h"

#define LOG_TAG "Ext4Crypt"
#include "cutils/log.h"
#include <cutils/klog.h>

namespace {
    // Key length in bits
    const int key_length = 128;
    static_assert(key_length % 8 == 0,
                  "Key length must be multiple of 8 bits");

    // How long do we store passwords for?
    const int password_max_age_seconds = 60;

    // How is device encrypted
    struct keys {
        std::string master_key;
        std::string password;
        time_t expiry_time;
    };
    std::map<std::string, keys> s_key_store;

    // ext4enc:TODO get these consts from somewhere good
    const int SHA512_LENGTH = 64;
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

    const unsigned char* master_key
        = reinterpret_cast<const unsigned char*>(&mki->second.master_key[0]);

    if (cryptfs_set_password(&ftr, password, master_key)) {
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

static std::string generate_key_ref(const char* key, int length)
{
    SHA512_CTX c;

    SHA512_Init(&c);
    SHA512_Update(&c, key, length);
    unsigned char key_ref1[SHA512_LENGTH];
    SHA512_Final(key_ref1, &c);

    SHA512_Init(&c);
    SHA512_Update(&c, key_ref1, SHA512_LENGTH);
    unsigned char key_ref2[SHA512_LENGTH];
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

    unsigned char master_key[key_length / 8];
    if (cryptfs_get_master_key (&ftr, password, master_key)){
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

    struct timespec now;
    clock_gettime(CLOCK_BOOTTIME, &now);
    s_key_store[path] = keys{std::string(reinterpret_cast<char*>(master_key),
                                         sizeof(master_key)),
                             password,
                             now.tv_sec + password_max_age_seconds};

    // Install password into global keyring
    // ext4enc:TODO Currently raw key is required to be of length
    // sizeof(ext4_key.raw) == EXT4_MAX_KEY_SIZE, so zero pad to
    // this length. Change when kernel bug is fixed.
    ext4_encryption_key ext4_key = {EXT4_ENCRYPTION_MODE_AES_256_XTS,
                                    {0},
                                    sizeof(ext4_key.raw)};
    memset(ext4_key.raw, 0, sizeof(ext4_key.raw));
    static_assert(key_length / 8 <= sizeof(ext4_key.raw),
                  "Key too long!");
    memcpy(ext4_key.raw, master_key, key_length / 8);

    // Get raw keyref - used to make keyname and to pass to ioctl
    auto raw_ref = generate_key_ref(ext4_key.raw, ext4_key.size);

    // Generate keyname
    std::ostringstream o;
    for (auto i = raw_ref.begin(); i != raw_ref.end(); ++i) {
        o << std::hex << std::setw(2) << std::setfill('0') << (int)*i;
    }
    auto ref = std::string("ext4:") + o.str();

    // Find existing keyring
    key_serial_t device_keyring = keyctl_search(KEY_SPEC_SESSION_KEYRING,
                                                "keyring", "e4crypt", 0);

    SLOGI("Found device_keyring - id is %d", device_keyring);

    // Add key ...
    key_serial_t key_id = add_key("logon", ref.c_str(),
                                  (void*)&ext4_key, sizeof(ext4_key),
                                  device_keyring);

    if (key_id == -1) {
        SLOGE("Failed to insert key into keyring with error %s",
              strerror(errno));
        return -1;
    }

    SLOGI("Added key %d (%s) to keyring %d in process %d",
          key_id, ref.c_str(), device_keyring, getpid());

    // Save reference to key so we can set policy later
    if (!props.Set(properties::ref, raw_ref)) {
        SLOGE("Cannot save key reference");
        return -1;
    }

    return 0;
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
