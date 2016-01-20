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

#include "F2fs.h"
#include "Utils.h"

#include <base/logging.h>
#include <base/stringprintf.h>
#include <private/android_filesystem_config.h>

#include <vector>
#include <string>

#include <sys/mount.h>
#include <sys/stat.h>

using android::base::StringPrintf;

namespace android {
namespace vold {
namespace f2fs {

static const char* kMkfsPath = "/system/bin/mkfs.f2fs";
static const char* kFsckPath = "/system/bin/fsck.f2fs";

bool IsSupported() {
    return access(kMkfsPath, X_OK) == 0
            && access(kFsckPath, X_OK) == 0
            && IsFilesystemSupported("f2fs");
}

status_t Check(const std::string& source, bool trusted) {
    std::vector<std::string> cmd;
    cmd.push_back(kFsckPath);
    cmd.push_back("-a");
    cmd.push_back(source);

    return ForkExecvp(cmd, trusted ? sFsckContext : sFsckUntrustedContext);
}

status_t Mount(const std::string& source, const std::string& target,
        const std::string& opts /* = "" */, bool trusted, bool portable) {
    std::string data(opts);

    if (portable) {
        if (!data.empty()) {
            data += ",";
        }
        data += "context=u:object_r:sdcard_posix:s0";
    }

    const char* c_source = source.c_str();
    const char* c_target = target.c_str();
    const char* c_data = data.c_str();

    unsigned long flags = MS_NOATIME | MS_NODEV | MS_NOSUID;

    // Only use MS_DIRSYNC if we're not mounting adopted storage
    if (!trusted) {
        flags |= MS_DIRSYNC;
    }

    int res = mount(c_source, c_target, "f2fs", flags, c_data);

    if (portable && res == 0) {
        chown(c_target, AID_MEDIA_RW, AID_MEDIA_RW);
        chmod(c_target, 0755);
    }

    if (res != 0) {
        PLOG(ERROR) << "Failed to mount " << source;
        if (errno == EROFS) {
            res = mount(c_source, c_target, "f2fs", flags | MS_RDONLY, c_data);
            if (res != 0) {
                PLOG(ERROR) << "Failed to mount read-only " << source;
            }
        }
    }

    return res;
}

status_t Format(const std::string& source) {
    std::vector<std::string> cmd;
    cmd.push_back(kMkfsPath);
    cmd.push_back(source);

    return ForkExecvp(cmd);
}

}  // namespace f2fs
}  // namespace vold
}  // namespace android
