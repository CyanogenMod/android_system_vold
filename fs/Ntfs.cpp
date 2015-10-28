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

#include "Ntfs.h"
#include "Utils.h"

#include <base/logging.h>
#include <base/stringprintf.h>

#include <vector>
#include <string>

#include <sys/mount.h>

using android::base::StringPrintf;

namespace android {
namespace vold {
namespace ntfs {

static const char* kMkfsPath = "/system/bin/mkntfs";
static const char* kFsckPath = "/system/bin/ntfsfix";
static const char* kMountPath = "/system/bin/ntfs-3g";

bool IsSupported() {
    return access(kMkfsPath, X_OK) == 0
            && access(kFsckPath, X_OK) == 0
            && access(kMountPath, X_OK) == 0
            && IsFilesystemSupported("ntfs");
}

status_t Check(const std::string& source) {
    std::vector<std::string> cmd;
    cmd.push_back(kFsckPath);
    cmd.push_back("-n");
    cmd.push_back(source);

    return ForkExecvp(cmd, sFsckContext);
}

status_t Mount(const std::string& source, const std::string& target) {
    const char* c_source = source.c_str();
    const char* c_target = target.c_str();

    std::vector<std::string> cmd;
    cmd.push_back(kMountPath);
    cmd.push_back("-o");
    cmd.push_back(c_source);
    cmd.push_back(c_target);

    return ForkExecvp(cmd);
}

status_t Format(const std::string& source) {
    std::vector<std::string> cmd;
    cmd.push_back(kMkfsPath);
    cmd.push_back(source);

    return ForkExecvp(cmd);
}

}  // namespace ntfs
}  // namespace vold
}  // namespace android
