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

#include "Keymaster.h"

#include <android-base/logging.h>

namespace android {
namespace vold {

bool KeymasterOperation::updateCompletely(const std::string& input, std::string* output) {
    output->clear();
    auto it = input.begin();
    while (it != input.end()) {
        size_t toRead = static_cast<size_t>(input.end() - it);
        keymaster_blob_t inputBlob{reinterpret_cast<const uint8_t*>(&*it), toRead};
        keymaster_blob_t outputBlob;
        size_t inputConsumed;
        auto error = mDevice->update(mDevice, mOpHandle, nullptr, &inputBlob, &inputConsumed,
                                     nullptr, &outputBlob);
        if (error != KM_ERROR_OK) {
            LOG(ERROR) << "update failed, code " << error;
            mDevice = nullptr;
            return false;
        }
        output->append(reinterpret_cast<const char*>(outputBlob.data), outputBlob.data_length);
        free(const_cast<uint8_t*>(outputBlob.data));
        if (inputConsumed > toRead) {
            LOG(ERROR) << "update reported too much input consumed";
            mDevice = nullptr;
            return false;
        }
        it += inputConsumed;
    }
    return true;
}

bool KeymasterOperation::finish() {
    auto error = mDevice->finish(mDevice, mOpHandle, nullptr, nullptr, nullptr, nullptr);
    mDevice = nullptr;
    if (error != KM_ERROR_OK) {
        LOG(ERROR) << "finish failed, code " << error;
        return false;
    }
    return true;
}

bool KeymasterOperation::finishWithOutput(std::string* output) {
    keymaster_blob_t outputBlob;
    auto error = mDevice->finish(mDevice, mOpHandle, nullptr, nullptr, nullptr, &outputBlob);
    mDevice = nullptr;
    if (error != KM_ERROR_OK) {
        LOG(ERROR) << "finish failed, code " << error;
        return false;
    }
    output->assign(reinterpret_cast<const char*>(outputBlob.data), outputBlob.data_length);
    free(const_cast<uint8_t*>(outputBlob.data));
    return true;
}

Keymaster::Keymaster() {
    mDevice = nullptr;
    const hw_module_t* module;
    int ret = hw_get_module_by_class(KEYSTORE_HARDWARE_MODULE_ID, NULL, &module);
    if (ret != 0) {
        LOG(ERROR) << "hw_get_module_by_class returned " << ret;
        return;
    }
    // TODO: This will need to be updated to support keymaster2.
    if (module->module_api_version != KEYMASTER_MODULE_API_VERSION_1_0) {
        LOG(ERROR) << "module_api_version is " << module->module_api_version;
        return;
    }
    ret = keymaster1_open(module, &mDevice);
    if (ret != 0) {
        LOG(ERROR) << "keymaster1_open returned " << ret;
        mDevice = nullptr;
        return;
    }
}

bool Keymaster::generateKey(const keymaster::AuthorizationSet& inParams, std::string* key) {
    keymaster_key_blob_t keyBlob;
    auto error = mDevice->generate_key(mDevice, &inParams, &keyBlob, nullptr);
    if (error != KM_ERROR_OK) {
        LOG(ERROR) << "generate_key failed, code " << error;
        return false;
    }
    key->assign(reinterpret_cast<const char*>(keyBlob.key_material), keyBlob.key_material_size);
    free(const_cast<uint8_t*>(keyBlob.key_material));
    return true;
}

bool Keymaster::deleteKey(const std::string& key) {
    if (mDevice->delete_key == nullptr) return true;
    keymaster_key_blob_t keyBlob{reinterpret_cast<const uint8_t*>(key.data()), key.size()};
    auto error = mDevice->delete_key(mDevice, &keyBlob);
    if (error != KM_ERROR_OK) {
        LOG(ERROR) << "delete_key failed, code " << error;
        return false;
    }
    return true;
}

KeymasterOperation Keymaster::begin(keymaster_purpose_t purpose, const std::string& key,
                                    const keymaster::AuthorizationSet& inParams,
                                    keymaster::AuthorizationSet* outParams) {
    keymaster_key_blob_t keyBlob{reinterpret_cast<const uint8_t*>(key.data()), key.size()};
    keymaster_operation_handle_t mOpHandle;
    keymaster_key_param_set_t outParams_set;
    auto error = mDevice->begin(mDevice, purpose, &keyBlob, &inParams, &outParams_set, &mOpHandle);
    if (error != KM_ERROR_OK) {
        LOG(ERROR) << "begin failed, code " << error;
        return KeymasterOperation(nullptr, mOpHandle);
    }
    outParams->Clear();
    outParams->push_back(outParams_set);
    keymaster_free_param_set(&outParams_set);
    return KeymasterOperation(mDevice, mOpHandle);
}

KeymasterOperation Keymaster::begin(keymaster_purpose_t purpose, const std::string& key,
                                    const keymaster::AuthorizationSet& inParams) {
    keymaster_key_blob_t keyBlob{reinterpret_cast<const uint8_t*>(key.data()), key.size()};
    keymaster_operation_handle_t mOpHandle;
    auto error = mDevice->begin(mDevice, purpose, &keyBlob, &inParams, nullptr, &mOpHandle);
    if (error != KM_ERROR_OK) {
        LOG(ERROR) << "begin failed, code " << error;
        return KeymasterOperation(nullptr, mOpHandle);
    }
    return KeymasterOperation(mDevice, mOpHandle);
}

}  // namespace vold
}  // namespace android
