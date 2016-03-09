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

#ifndef ANDROID_VOLD_KEYMASTER1_H
#define ANDROID_VOLD_KEYMASTER1_H

#include <string>

#include <hardware/hardware.h>
#include <hardware/keymaster1.h>

#include <keymaster/authorization_set.h>

namespace android {
namespace vold {

using namespace keymaster;

// C++ wrappers to the keymaster1 C interface.
// This is tailored to the needs of KeyStorage, but could be extended to be
// a more general interface.

// Wrapper for a keymaster_operation_handle_t representing an
// ongoing Keymaster operation.  Aborts the operation
// in the destructor if it is unfinished. Methods log failures
// to LOG(ERROR).
class KeymasterOperation {
  public:
    ~KeymasterOperation() {
        if (mDevice) mDevice->abort(mDevice, mOpHandle);
    }
    // Is this instance valid? This is false if creation fails, and becomes
    // false on finish or if an update fails.
    explicit operator bool() { return mDevice != nullptr; }
    // Call "update" repeatedly until all of the input is consumed, and
    // concatenate the output. Return true on success.
    bool updateCompletely(const std::string& input, std::string* output);
    // Finish; pass nullptr for the "output" param.
    bool finish();
    // Finish and write the output to this string.
    bool finishWithOutput(std::string* output);
    // Move constructor
    KeymasterOperation(KeymasterOperation&& rhs) {
        mOpHandle = rhs.mOpHandle;
        mDevice = rhs.mDevice;
        rhs.mDevice = nullptr;
    }

  private:
    KeymasterOperation(keymaster1_device_t* d, keymaster_operation_handle_t h)
        : mDevice{d}, mOpHandle{h} {}
    keymaster1_device_t* mDevice;
    keymaster_operation_handle_t mOpHandle;
    DISALLOW_COPY_AND_ASSIGN(KeymasterOperation);
    friend class Keymaster;
};

// Wrapper for a keymaster1_device_t representing an open connection
// to the keymaster, which is closed in the destructor.
class Keymaster {
  public:
    Keymaster();
    ~Keymaster() {
        if (mDevice) keymaster1_close(mDevice);
    }
    // false if we failed to open the keymaster device.
    explicit operator bool() { return mDevice != nullptr; }
    // Generate a key in the keymaster from the given params.
    bool generateKey(const AuthorizationSet& inParams, std::string* key);
    // If the keymaster supports it, permanently delete a key.
    bool deleteKey(const std::string& key);
    // Begin a new cryptographic operation, collecting output parameters.
    KeymasterOperation begin(keymaster_purpose_t purpose, const std::string& key,
                             const AuthorizationSet& inParams, AuthorizationSet* outParams);
    // Begin a new cryptographic operation; don't collect output parameters.
    KeymasterOperation begin(keymaster_purpose_t purpose, const std::string& key,
                             const AuthorizationSet& inParams);

  private:
    keymaster1_device_t* mDevice;
    DISALLOW_COPY_AND_ASSIGN(Keymaster);
};

template <keymaster_tag_t Tag>
inline AuthorizationSetBuilder& addStringParam(AuthorizationSetBuilder&& params,
                                               TypedTag<KM_BYTES, Tag> tag,
                                               const std::string& val) {
    return params.Authorization(tag, val.data(), val.size());
}

template <keymaster_tag_t Tag>
inline void addStringParam(AuthorizationSetBuilder* params, TypedTag<KM_BYTES, Tag> tag,
                           const std::string& val) {
    params->Authorization(tag, val.data(), val.size());
}

}  // namespace vold
}  // namespace android

#endif
