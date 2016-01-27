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

static bool checkSize(const std::string& kind, size_t actual, size_t expected) {
    if (actual != expected) {
        LOG(ERROR) << "Wrong number of bytes in " << kind << ", expected " << expected
            << " got " << actual;
        return false;
    }
    return true;
}

static std::string hashSecdiscardable(const std::string &secdiscardable) {
    SHA512_CTX c;

    SHA512_Init(&c);
    // Personalise the hashing by introducing a fixed prefix.
    // Hashing applications should use personalization except when there is a
    // specific reason not to; see section 4.11 of https://www.schneier.com/skein1.3.pdf
    std::string secdiscardableHashingPrefix = "Android secdiscardable SHA512";
    secdiscardableHashingPrefix.resize(SHA512_CBLOCK);
    SHA512_Update(&c, secdiscardableHashingPrefix.data(), secdiscardableHashingPrefix.size());
    SHA512_Update(&c, secdiscardable.data(), secdiscardable.size());
    std::string res(SHA512_DIGEST_LENGTH, '\0');
    SHA512_Final(reinterpret_cast<uint8_t *>(&res[0]), &c);
    return res;
}

static bool generateKeymasterKey(Keymaster &keymaster,
        const keymaster::AuthorizationSet &extraParams,
        std::string &key) {
    auto params = keymaster::AuthorizationSetBuilder()
        .AesEncryptionKey(AES_KEY_BYTES * 8)
        .Authorization(keymaster::TAG_BLOCK_MODE, KM_MODE_GCM)
        .Authorization(keymaster::TAG_MIN_MAC_LENGTH, GCM_MAC_BYTES * 8)
        .Authorization(keymaster::TAG_PADDING, KM_PAD_NONE)
        .Authorization(keymaster::TAG_NO_AUTH_REQUIRED) // FIXME integrate with gatekeeper
        .build();
    params.push_back(extraParams);
    return keymaster.generateKey(params, key);
}

static bool encryptWithKeymasterKey(
        Keymaster &keymaster,
        const std::string &key,
        const keymaster::AuthorizationSet &extraParams,
        const std::string &message,
        std::string &ciphertext) {
    // FIXME fix repetition
    auto params = keymaster::AuthorizationSetBuilder()
        .Authorization(keymaster::TAG_BLOCK_MODE, KM_MODE_GCM)
        .Authorization(keymaster::TAG_MAC_LENGTH, GCM_MAC_BYTES * 8)
        .Authorization(keymaster::TAG_PADDING, KM_PAD_NONE)
        .build();
    params.push_back(extraParams);
    keymaster::AuthorizationSet outParams;
    auto opHandle = keymaster.begin(KM_PURPOSE_ENCRYPT, key, params, outParams);
    if (!opHandle) return false;
    keymaster_blob_t nonceBlob;
    if (!outParams.GetTagValue(keymaster::TAG_NONCE, &nonceBlob)) {
        LOG(ERROR) << "GCM encryption but no nonce generated";
        return false;
    }
    // nonceBlob here is just a pointer into existing data, must not be freed
    std::string nonce(reinterpret_cast<const char *>(nonceBlob.data), nonceBlob.data_length);
    if (!checkSize("nonce", nonce.size(), GCM_NONCE_BYTES)) return false;
    std::string body;
    if (!opHandle.updateCompletely(message, body)) return false;

    std::string mac;
    if (!opHandle.finishWithOutput(mac)) return false;
    if (!checkSize("mac", mac.size(), GCM_MAC_BYTES)) return false;
    ciphertext = nonce + body + mac;
    return true;
}

static bool decryptWithKeymasterKey(
        Keymaster &keymaster, const std::string &key,
        const keymaster::AuthorizationSet &extraParams,
        const std::string &ciphertext,
        std::string &message) {
    auto nonce = ciphertext.substr(0, GCM_NONCE_BYTES);
    auto bodyAndMac = ciphertext.substr(GCM_NONCE_BYTES);
    // FIXME fix repetition
    auto params = addStringParam(keymaster::AuthorizationSetBuilder(), keymaster::TAG_NONCE, nonce)
        .Authorization(keymaster::TAG_BLOCK_MODE, KM_MODE_GCM)
        .Authorization(keymaster::TAG_MAC_LENGTH, GCM_MAC_BYTES * 8)
        .Authorization(keymaster::TAG_PADDING, KM_PAD_NONE)
        .build();
    params.push_back(extraParams);

    auto opHandle = keymaster.begin(KM_PURPOSE_DECRYPT, key, params);
    if (!opHandle) return false;
    if (!opHandle.updateCompletely(bodyAndMac, message)) return false;
    if (!opHandle.finish()) return false;
    return true;
}

static bool readFileToString(const std::string &filename, std::string &result) {
    if (!android::base::ReadFileToString(filename, &result)) {
         PLOG(ERROR) << "Failed to read from " << filename;
         return false;
    }
    return true;
}

static bool writeStringToFile(const std::string &payload, const std::string &filename) {
    if (!android::base::WriteStringToFile(payload, filename)) {
         PLOG(ERROR) << "Failed to write to " << filename;
         return false;
    }
    return true;
}

bool storeKey(const std::string &dir, const std::string &key) {
    if (TEMP_FAILURE_RETRY(mkdir(dir.c_str(), 0700)) == -1) {
        PLOG(ERROR) << "key mkdir " << dir;
        return false;
    }
    std::string secdiscardable;
    if (ReadRandomBytes(SECDISCARDABLE_BYTES, secdiscardable) != OK) {
        // TODO status_t plays badly with PLOG, fix it.
        LOG(ERROR) << "Random read failed";
        return false;
    }
    if (!writeStringToFile(secdiscardable, dir + "/" + kFn_secdiscardable)) return false;
    auto extraParams = addStringParam(keymaster::AuthorizationSetBuilder(),
            keymaster::TAG_APPLICATION_ID, hashSecdiscardable(secdiscardable)).build();
    Keymaster keymaster;
    if (!keymaster) return false;
    std::string kmKey;
    if (!generateKeymasterKey(keymaster, extraParams, kmKey)) return false;
    std::string encryptedKey;
    if (!encryptWithKeymasterKey(
        keymaster, kmKey, extraParams, key, encryptedKey)) return false;
    if (!writeStringToFile(kmKey, dir + "/" + kFn_keymaster_key_blob)) return false;
    if (!writeStringToFile(encryptedKey, dir + "/" + kFn_encrypted_key)) return false;
    return true;
}

bool retrieveKey(const std::string &dir, std::string &key) {
    std::string secdiscardable;
    if (!readFileToString(dir + "/" + kFn_secdiscardable, secdiscardable)) return false;
    auto extraParams = addStringParam(keymaster::AuthorizationSetBuilder(),
            keymaster::TAG_APPLICATION_ID, hashSecdiscardable(secdiscardable)).build();
    std::string kmKey;
    if (!readFileToString(dir + "/" + kFn_keymaster_key_blob, kmKey)) return false;
    std::string encryptedMessage;
    if (!readFileToString(dir + "/" + kFn_encrypted_key, encryptedMessage)) return false;
    Keymaster keymaster;
    if (!keymaster) return false;
    return decryptWithKeymasterKey(keymaster, kmKey, extraParams, encryptedMessage, key);
}

static bool deleteKey(const std::string &dir) {
    std::string kmKey;
    if (!readFileToString(dir + "/" + kFn_keymaster_key_blob, kmKey)) return false;
    Keymaster keymaster;
    if (!keymaster) return false;
    if (!keymaster.deleteKey(kmKey)) return false;
    return true;
}

static bool secdiscardSecdiscardable(const std::string &dir) {
    if (ForkExecvp(std::vector<std::string> {
            kSecdiscardPath, "--", dir + "/" + kFn_secdiscardable}) != 0) {
        LOG(ERROR) << "secdiscard failed";
        return false;
    }
    return true;
}

static bool recursiveDeleteKey(const std::string &dir) {
    if (ForkExecvp(std::vector<std::string> {
            kRmPath, "-rf", dir}) != 0) {
        LOG(ERROR) << "recursive delete failed";
        return false;
    }
    return true;
}

bool destroyKey(const std::string &dir) {
    bool success = true;
    // Try each thing, even if previous things failed.
    success &= deleteKey(dir);
    success &= secdiscardSecdiscardable(dir);
    success &= recursiveDeleteKey(dir);
    return success;
}

}  // namespace vold
}  // namespace android
