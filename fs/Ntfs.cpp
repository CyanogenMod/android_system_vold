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

#ifdef MINIVOLD
static const char* kMkfsPath = "/sbin/mkfs.ntfs";
static const char* kFsckPath = "/sbin/fsck.ntfs";
#ifdef CONFIG_KERNEL_HAVE_NTFS
static const char* kMountPath = "/sbin/mount";
#else
static const char* kMountPath = "/sbin/mount.ntfs";
#endif
#else
static const char* kMkfsPath = "/system/bin/mkfs.ntfs";
static const char* kFsckPath = "/system/bin/fsck.ntfs";
#ifdef CONFIG_KERNEL_HAVE_NTFS
static const char* kMountPath = "/system/bin/mount";
#else
static const char* kMountPath = "/system/bin/mount.ntfs";
#endif
#endif

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

    // Ntfs devices are currently always untrusted
    return ForkExecvp(cmd, sFsckUntrustedContext);
}

status_t Mount(const std::string& source, const std::string& target, bool ro,
        bool remount, bool executable, int ownerUid, int ownerGid, int permMask,
        bool createLost) {
    char mountData[255];

    const char* c_source = source.c_str();
    const char* c_target = target.c_str();

    sprintf(mountData,
#ifdef CONFIG_KERNEL_HAVE_NTFS
            "utf8,uid=%d,gid=%d,fmask=%o,dmask=%o,nodev,nosuid",
#else
            "utf8,uid=%d,gid=%d,fmask=%o,dmask=%o,"
            "shortname=mixed,nodev,nosuid,dirsync",
#endif
            ownerUid, ownerGid, permMask, permMask);

    if (!executable)
        strcat(mountData, ",noexec");
    if (ro)
        strcat(mountData, ",ro");
    if (remount)
        strcat(mountData, ",remount");

    std::vector<std::string> cmd;
    cmd.push_back(kMountPath);
#ifdef CONFIG_KERNEL_HAVE_NTFS
    cmd.push_back("-t");
    cmd.push_back("ntfs");
#endif
    cmd.push_back("-o");
    cmd.push_back(mountData);
    cmd.push_back(c_source);
    cmd.push_back(c_target);

    return ForkExecvp(cmd);
}

status_t Format(const std::string& source, bool wipe) {
    std::vector<std::string> cmd;
    cmd.push_back(kMkfsPath);
    if (wipe)
        cmd.push_back("-f");
    cmd.push_back(source);

    return ForkExecvp(cmd);
}

}  // namespace ntfs
}  // namespace vold
}  // namespace android
