/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include "KeyStorage.h"

#include "Keymaster.h"
#include "Utils.h"

#include <vector>

#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/sha.h>

#include <android-base/file.h>
#include <android-base/logging.h>

#include <keymaster/authorization_set.h>

namespace android {
namespace vold {

static constexpr size_t AES_KEY_BYTES = 32;
static constexpr size_t GCM_NONCE_BYTES = 12;
static constexpr size_t GCM_MAC_BYTES = 16;
// FIXME: better name than "secdiscardable" sought!
static constexpr size_t SECDISCARDABLE_BYTES = 1<<14;

static const char* kRmPath = "/system/bin/rm";
static const char* kSecdiscardPath = "/system/bin/secdiscard";
static const char* kFn_keymaster_key_blob = "keymaster_key_blob";
static const char* kFn_encrypted_key = "encrypted_key";
static const char* kFn_secdiscardable = "secdiscardable";

static bool CheckSize(const std::string& kind, size_t actual, size_t expected) {
    if (actual != expected) {
        LOG(ERROR) << "Wrong number of bytes in " << kind << ", expected " << expected
            << " got " << actual;
        return false;
    }
    return true;
}

static std::string HashSecdiscardable(const std::string &secdiscardable) {
    SHA512_CTX c;

    SHA512_Init(&c);
    // Personalise the hashing by introducing a fixed prefix.
    // Hashing applications should use personalization except when there is a
    // specific reason not to; see section 4.11 of https://www.schneier.com/skein1.3.pdf
    std::string secdiscardable_hashing_prefix = "Android secdiscardable SHA512";
    secdiscardable_hashing_prefix.resize(SHA512_CBLOCK);
    SHA512_Update(&c, secdiscardable_hashing_prefix.data(), secdiscardable_hashing_prefix.size());
    SHA512_Update(&c, secdiscardable.data(), secdiscardable.size());
    std::string res(SHA512_DIGEST_LENGTH, '\0');
    SHA512_Final(reinterpret_cast<uint8_t *>(&res[0]), &c);
    return res;
}

static bool GenerateKeymasterKey(Keymaster &keymaster,
        const keymaster::AuthorizationSet &extra_params,
        std::string &key) {
    keymaster::AuthorizationSetBuilder param_builder;
    param_builder
        .AesEncryptionKey(AES_KEY_BYTES * 8)
        .Authorization(keymaster::TAG_BLOCK_MODE, KM_MODE_GCM)
        .Authorization(keymaster::TAG_MIN_MAC_LENGTH, GCM_MAC_BYTES * 8)
        .Authorization(keymaster::TAG_PADDING, KM_PAD_NONE)
        .Authorization(keymaster::TAG_NO_AUTH_REQUIRED); // FIXME integrate with gatekeeper
    auto params = param_builder.build();
    params.push_back(extra_params);
    return keymaster.GenerateKey(params, key);
}

static bool EncryptWithKeymasterKey(
        Keymaster &keymaster,
        const std::string &key,
        const keymaster::AuthorizationSet &extra_params,
        const std::string &message,
        std::string &ciphertext) {
    // FIXME fix repetition
    keymaster::AuthorizationSetBuilder param_builder;
    param_builder
        .Authorization(keymaster::TAG_BLOCK_MODE, KM_MODE_GCM)
        .Authorization(keymaster::TAG_MAC_LENGTH, GCM_MAC_BYTES * 8)
        .Authorization(keymaster::TAG_PADDING, KM_PAD_NONE);
    auto params = param_builder.build();
    params.push_back(extra_params);
    keymaster::AuthorizationSet out_params;
    auto op_handle = keymaster.Begin(KM_PURPOSE_ENCRYPT, key, params, out_params);
    if (!op_handle) return false;
    keymaster_blob_t nonce_blob;
    if (!out_params.GetTagValue(keymaster::TAG_NONCE, &nonce_blob)) {
        LOG(ERROR) << "GCM encryption but no nonce generated";
        return false;
    }
    // nonce_blob here is just a pointer into existing data, must not be freed
    std::string nonce(reinterpret_cast<const char *>(nonce_blob.data), nonce_blob.data_length);
    if (!CheckSize("nonce", nonce.size(), GCM_NONCE_BYTES)) return false;
    std::string body;
    if (!op_handle.UpdateCompletely(message, body)) return false;

    std::string mac;
    if (!op_handle.FinishWithOutput(mac)) return false;
    if (!CheckSize("mac", mac.size(), GCM_MAC_BYTES)) return false;
    ciphertext = nonce + body + mac;
    return true;
}

static bool DecryptWithKeymasterKey(
        Keymaster &keymaster, const std::string &key,
        const keymaster::AuthorizationSet &extra_params,
        const std::string &ciphertext,
        std::string &message) {
    auto nonce = ciphertext.substr(0, GCM_NONCE_BYTES);
    auto body_mac = ciphertext.substr(GCM_NONCE_BYTES);
    // FIXME fix repetition
    keymaster::AuthorizationSetBuilder param_builder;
    param_builder
        .Authorization(keymaster::TAG_BLOCK_MODE, KM_MODE_GCM)
        .Authorization(keymaster::TAG_MAC_LENGTH, GCM_MAC_BYTES * 8)
        .Authorization(keymaster::TAG_PADDING, KM_PAD_NONE);
    AddStringParam(param_builder, keymaster::TAG_NONCE, nonce);
    auto params = param_builder.build();
    params.push_back(extra_params);

    auto op_handle = keymaster.Begin(KM_PURPOSE_DECRYPT, key, params);
    if (!op_handle) return false;
    if (!op_handle.UpdateCompletely(body_mac, message)) return false;
    if (!op_handle.Finish()) return false;
    return true;
}

bool StoreKey(const std::string &dir, const std::string &key) {
    if (TEMP_FAILURE_RETRY(mkdir(dir.c_str(), 0700)) == -1) {
        PLOG(ERROR) << "key mkdir " << dir;
        return false;
    }
    std::string secdiscardable;
    if (ReadRandomBytes(SECDISCARDABLE_BYTES, secdiscardable) != 0) {
        // TODO status_t plays badly with PLOG, fix it.
        LOG(ERROR) << "Random read failed";
        return false;
    }
    // FIXME create a wrapper around reads and writes which handles error logging
    if (!android::base::WriteStringToFile(secdiscardable, dir + "/" + kFn_secdiscardable)) {
         PLOG(ERROR) << "Unable to write secdiscardable to " << dir;
         return false;
    }
    keymaster::AuthorizationSetBuilder param_builder;
    AddStringParam(param_builder, keymaster::TAG_APPLICATION_ID,
        HashSecdiscardable(secdiscardable));
    auto extra_params = param_builder.build();
    Keymaster keymaster;
    if (!keymaster) return false;
    std::string km_key;
    if (!GenerateKeymasterKey(keymaster, extra_params, km_key)) return false;
    std::string encrypted_key;
    if (!EncryptWithKeymasterKey(
        keymaster, km_key, extra_params, key, encrypted_key)) return false;
    if (!android::base::WriteStringToFile(km_key, dir + "/" + kFn_keymaster_key_blob)) {
        PLOG(ERROR) << "Unable to write keymaster_key_blob to " << dir;
        return false;
    }
    if (!android::base::WriteStringToFile(encrypted_key, dir + "/" + kFn_encrypted_key)) {
        PLOG(ERROR) << "Unable to write encrypted_key to " << dir;
        return false;
    }
    return true;
}

bool RetrieveKey(const std::string &dir, std::string &key) {
    std::string secdiscardable;
    if (!android::base::ReadFileToString(dir + "/" + kFn_secdiscardable, &secdiscardable)) {
         PLOG(ERROR) << "Unable to read secdiscardable from " << dir;
         return false;
    }
    keymaster::AuthorizationSetBuilder param_builder;
    AddStringParam(param_builder, keymaster::TAG_APPLICATION_ID,
        HashSecdiscardable(secdiscardable));
    auto extra_params = param_builder.build();
    std::string km_key;
    if (!android::base::ReadFileToString(dir + "/" + kFn_keymaster_key_blob, &km_key)) {
         PLOG(ERROR) << "Unable to read keymaster_key_blob from " << dir;
         return false;
    }
    std::string encrypted_message;
    if (!android::base::ReadFileToString(dir + "/" + kFn_encrypted_key, &encrypted_message)) {
         PLOG(ERROR) << "Unable to read encrypted_key to " << dir;
         return false;
    }
    Keymaster keymaster;
    if (!keymaster) return false;
    return DecryptWithKeymasterKey(keymaster, km_key, extra_params, encrypted_message, key);
}

static bool DeleteKey(const std::string &dir) {
    std::string km_key;
    if (!android::base::ReadFileToString(dir + "/" + kFn_keymaster_key_blob, &km_key)) {
         PLOG(ERROR) << "Unable to read keymaster_key_blob from " << dir;
         return false;
    }
    Keymaster keymaster;
    if (!keymaster) return false;
    if (!keymaster.DeleteKey(km_key)) return false;
    return true;
}

static bool SecdiscardSecdiscardable(const std::string &dir) {
    if (ForkExecvp(std::vector<std::string> {
            kSecdiscardPath, "--", dir + "/" + kFn_secdiscardable}) != 0) {
        LOG(ERROR) << "secdiscard failed";
        return false;
    }
    return true;
}

static bool RecursiveDeleteKey(const std::string &dir) {
    if (ForkExecvp(std::vector<std::string> {
            kRmPath, "-rf", dir}) != 0) {
        LOG(ERROR) << "recursive delete failed";
        return false;
    }
    return true;
}

bool DestroyKey(const std::string &dir) {
    bool success = true;
    // Try each thing, even if previous things failed.
    success &= DeleteKey(dir);
    success &= SecdiscardSecdiscardable(dir);
    success &= RecursiveDeleteKey(dir);
    return success;
}

}  // namespace vold
}  // namespace android
