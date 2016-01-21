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

bool KeymasterOperation::UpdateCompletely(
        const std::string &input,
        std::string &output) {
    output.clear();
    auto it = input.begin();
    while (it != input.end()) {
        size_t to_read = static_cast<size_t>(input.end() - it);
        keymaster_blob_t input_blob {reinterpret_cast<const uint8_t *>(&*it),  to_read};
        keymaster_blob_t output_blob;
        size_t input_consumed;
        auto error = device->update(device, op_handle,
            nullptr, &input_blob, &input_consumed, nullptr, &output_blob);
        if (error != KM_ERROR_OK) {
            LOG(ERROR) << "update failed, code " << error;
            device = nullptr;
            return false;
        }
        output.append(reinterpret_cast<const char *>(output_blob.data), output_blob.data_length);
        free(const_cast<uint8_t *>(output_blob.data));
        if (input_consumed > to_read) {
            LOG(ERROR) << "update reported too much input consumed";
            device = nullptr;
            return false;
        }
        it += input_consumed;
    }
    return true;
}

bool KeymasterOperation::Finish() {
    auto error = device->finish(device, op_handle,
        nullptr, nullptr, nullptr, nullptr);
    device = nullptr;
    if (error != KM_ERROR_OK) {
        LOG(ERROR) << "finish failed, code " << error;
        return false;
    }
    return true;
}

bool KeymasterOperation::FinishWithOutput(std::string &output) {
    keymaster_blob_t output_blob;
    auto error = device->finish(device, op_handle,
        nullptr, nullptr, nullptr, &output_blob);
    device = nullptr;
    if (error != KM_ERROR_OK) {
        LOG(ERROR) << "finish failed, code " << error;
        return false;
    }
    output.assign(reinterpret_cast<const char *>(output_blob.data), output_blob.data_length);
    free(const_cast<uint8_t *>(output_blob.data));
    return true;
}

Keymaster::Keymaster() {
    device = nullptr;
    const hw_module_t *module;
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
    ret = keymaster1_open(module, &device);
    if (ret != 0) {
        LOG(ERROR) << "keymaster1_open returned " << ret;
        device = nullptr;
        return;
    }
}

bool Keymaster::GenerateKey(
        const keymaster::AuthorizationSet &in_params,
        std::string &key) {
    keymaster_key_blob_t key_blob;
    auto error = device->generate_key(device, &in_params, &key_blob, nullptr);
    if (error != KM_ERROR_OK) {
        LOG(ERROR) << "generate_key failed, code " << error;
        return false;
    }
    key.assign(reinterpret_cast<const char *>(key_blob.key_material), key_blob.key_material_size);
    return true;
}

bool Keymaster::DeleteKey(const std::string &key) {
    if (device->delete_key == nullptr) return true;
    keymaster_key_blob_t key_blob { reinterpret_cast<const uint8_t *>(key.data()), key.size() };
    auto error = device->delete_key(device, &key_blob);
    if (error != KM_ERROR_OK) {
        LOG(ERROR) << "delete_key failed, code " << error;
        return false;
    }
    return true;
}

KeymasterOperation Keymaster::Begin(
        keymaster_purpose_t purpose,
        const std::string &key,
        const keymaster::AuthorizationSet &in_params,
        keymaster::AuthorizationSet &out_params) {
    keymaster_key_blob_t key_blob { reinterpret_cast<const uint8_t *>(key.data()), key.size() };
    keymaster_operation_handle_t op_handle;
    keymaster_key_param_set_t out_params_set;
    auto error = device->begin(device, purpose,
        &key_blob, &in_params, &out_params_set, &op_handle);
    if (error != KM_ERROR_OK) {
        LOG(ERROR) << "begin failed, code " << error;
        return KeymasterOperation(nullptr, op_handle);
    }
    out_params.Clear();
    out_params.push_back(out_params_set);
    keymaster_free_param_set(&out_params_set);
    return KeymasterOperation(device, op_handle);
}

KeymasterOperation Keymaster::Begin(
        keymaster_purpose_t purpose,
        const std::string &key,
        const keymaster::AuthorizationSet &in_params) {
    keymaster_key_blob_t key_blob { reinterpret_cast<const uint8_t *>(key.data()), key.size() };
    keymaster_operation_handle_t op_handle;
    auto error = device->begin(device, purpose, 
        &key_blob, &in_params, nullptr, &op_handle);
    if (error != KM_ERROR_OK) {
        LOG(ERROR) << "begin failed, code " << error;
        return KeymasterOperation(nullptr, op_handle);
    }
    return KeymasterOperation(device, op_handle);
}

}  // namespace vold
}  // namespace android
