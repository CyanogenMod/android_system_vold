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

#define LOG_TAG "Vold"

#include "sehandle.h"
#include "Utils.h"
#include "Process.h"

#include <cutils/fs.h>
#include <cutils/log.h>
#include <utils/file.h>
#include <utils/stringprintf.h>
#include <private/android_filesystem_config.h>

#include <fcntl.h>
#include <linux/fs.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#ifndef UMOUNT_NOFOLLOW
#define UMOUNT_NOFOLLOW    0x00000008  /* Don't follow symlink on umount */
#endif

namespace android {
namespace vold {

status_t CreateDeviceNode(const std::string& path, dev_t dev) {
    const char* cpath = path.c_str();
    status_t res = 0;

    char* secontext = nullptr;
    if (sehandle) {
        if (!selabel_lookup(sehandle, &secontext, cpath, S_IFBLK)) {
            setfscreatecon(secontext);
        }
    }

    mode_t mode = 0660 | S_IFBLK;
    if (mknod(cpath, mode, dev) < 0) {
        if (errno != EEXIST) {
            ALOGW("Failed to create device node for %ud:%ud at %s: %s",
                    major(dev), minor(dev), cpath, strerror(errno));
            res = -errno;
        }
    }

    if (secontext) {
        setfscreatecon(nullptr);
        freecon(secontext);
    }

    return res;
}

status_t DestroyDeviceNode(const std::string& path) {
    const char* cpath = path.c_str();
    if (TEMP_FAILURE_RETRY(unlink(cpath))) {
        return -errno;
    } else {
        return OK;
    }
}

status_t ForceUnmount(const std::string& path) {
    const char* cpath = path.c_str();
    if (!umount2(cpath, UMOUNT_NOFOLLOW) || errno == EINVAL || errno == ENOENT) {
        return OK;
    }
    ALOGW("Failed to unmount %s (%s), sending SIGTERM", cpath, strerror(errno));
    Process::killProcessesWithOpenFiles(cpath, SIGTERM);
    sleep(1);

    if (!umount2(cpath, UMOUNT_NOFOLLOW) || errno == EINVAL || errno == ENOENT) {
        return OK;
    }
    ALOGW("Failed to unmount %s (%s), sending SIGKILL", cpath, strerror(errno));
    Process::killProcessesWithOpenFiles(cpath, SIGKILL);
    sleep(1);

    if (!umount2(cpath, UMOUNT_NOFOLLOW) || errno == EINVAL || errno == ENOENT) {
        return OK;
    }
    ALOGW("Failed to unmount %s (%s)", cpath, strerror(errno));
    return -errno;
}

}  // namespace vold
}  // namespace android
