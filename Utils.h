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

#ifndef ANDROID_VOLD_UTILS_H
#define ANDROID_VOLD_UTILS_H

#include <utils/Errors.h>
#include <cutils/multiuser.h>
#include <selinux/selinux.h>

#include <vector>
#include <string>

// DISALLOW_COPY_AND_ASSIGN disallows the copy and operator= functions. It goes in the private:
// declarations in a class.
#if !defined(DISALLOW_COPY_AND_ASSIGN)
#define DISALLOW_COPY_AND_ASSIGN(TypeName) \
    TypeName(const TypeName&) = delete;  \
    void operator=(const TypeName&) = delete
#endif

struct DIR;

namespace android {
namespace vold {

/* SELinux contexts used depending on the block device type */
extern security_context_t sBlkidContext;
extern security_context_t sBlkidUntrustedContext;
extern security_context_t sFsckContext;
extern security_context_t sFsckUntrustedContext;

status_t CreateDeviceNode(const std::string& path, dev_t dev);
status_t DestroyDeviceNode(const std::string& path);

/* fs_prepare_dir wrapper that creates with SELinux context */
status_t PrepareDir(const std::string& path, mode_t mode, uid_t uid, gid_t gid);

/* Really unmounts the path, killing active processes along the way */
status_t ForceUnmount(const std::string& path, bool detach = false);

/* Kills any processes using given path */
status_t KillProcessesUsingPath(const std::string& path);

/* Creates bind mount from source to target */
status_t BindMount(const std::string& source, const std::string& target);

/* Reads filesystem metadata from device at path */
status_t ReadMetadata(const std::string& path, std::string& fsType,
        std::string& fsUuid, std::string& fsLabel);

/* Reads filesystem metadata from untrusted device at path */
status_t ReadMetadataUntrusted(const std::string& path, std::string& fsType,
        std::string& fsUuid, std::string& fsLabel);

/* Returns either WEXITSTATUS() status, or a negative errno */
status_t ForkExecvp(const std::vector<std::string>& args);
status_t ForkExecvp(const std::vector<std::string>& args, security_context_t context);

status_t ForkExecvp(const std::vector<std::string>& args,
        std::vector<std::string>& output);
status_t ForkExecvp(const std::vector<std::string>& args,
        std::vector<std::string>& output, security_context_t context);

pid_t ForkExecvpAsync(const std::vector<std::string>& args);

status_t ReadRandomBytes(size_t bytes, std::string& out);

/* Converts hex string to raw bytes, ignoring [ :-] */
status_t HexToStr(const std::string& hex, std::string& str);
/* Converts raw bytes to hex string */
status_t StrToHex(const std::string& str, std::string& hex);
/* Normalize given hex string into consistent format */
status_t NormalizeHex(const std::string& in, std::string& out);

uint64_t GetFreeBytes(const std::string& path);
uint64_t GetTreeBytes(const std::string& path);

bool IsFilesystemSupported(const std::string& fsType);

/* Wipes contents of block device at given path */
status_t WipeBlockDevice(const std::string& path);

std::string BuildKeyPath(const std::string& partGuid);

std::string BuildDataSystemLegacyPath(userid_t userid);
std::string BuildDataSystemCePath(userid_t userid);
std::string BuildDataSystemDePath(userid_t userid);
std::string BuildDataMiscLegacyPath(userid_t userid);
std::string BuildDataMiscCePath(userid_t userid);
std::string BuildDataMiscDePath(userid_t userid);
std::string BuildDataProfilesDePath(userid_t userid);
std::string BuildDataProfilesForeignDexDePath(userid_t userid);

std::string BuildDataPath(const char* volumeUuid);
std::string BuildDataMediaCePath(const char* volumeUuid, userid_t userid);
std::string BuildDataUserCePath(const char* volumeUuid, userid_t userid);
std::string BuildDataUserDePath(const char* volumeUuid, userid_t userid);

dev_t GetDevice(const std::string& path);

std::string DefaultFstabPath();

status_t RestoreconRecursive(const std::string& path);

status_t SaneReadLinkAt(int dirfd, const char* path, char* buf, size_t bufsiz);

class ScopedFd {
    const int fd_;
public:
    ScopedFd(int fd);
    ~ScopedFd();
    int get() const { return fd_; }

    DISALLOW_COPY_AND_ASSIGN(ScopedFd);
};

class ScopedDir {
    DIR* const dir_;
public:
    ScopedDir(DIR* dir);
    ~ScopedDir();
    DIR* get() const { return dir_; }

    DISALLOW_COPY_AND_ASSIGN(ScopedDir);
};

/* Checks if Android is running in QEMU */
bool IsRunningInEmulator();

}  // namespace vold
}  // namespace android

#endif
