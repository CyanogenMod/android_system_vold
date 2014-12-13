/*
 * Copyright (C) 2012 The Android Open Source Project
 * Copyright (C) 2014 The CyanogenMod Project
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

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/wait.h>

#include <linux/kdev_t.h>
#include <logwrap/logwrap.h>
#include "VoldUtil.h"

#define LOG_TAG "Vold"
#include <cutils/log.h>
#include <cutils/properties.h>

#include <private/android_filesystem_config.h>

#include "F2FS.h"

static char F2FS_FSCK[] = "/system/bin/fsck.f2fs";
static char F2FS_MKFS[] = "/system/bin/mkfs.f2fs";

int F2FS::doMount(const char *fsPath, const char *mountPoint, bool ro, bool
        remount, bool executable, bool sdcard) {
    int rc;
    unsigned long flags;
    char data[255]  = "inline_xattr,background_gc=off,active_logs=2";

    flags = MS_NOATIME | MS_NODEV | MS_NOSUID | MS_DIRSYNC;

    flags |= (executable ? 0 : MS_NOEXEC);
    flags |= (ro ? MS_RDONLY : 0);
    flags |= (remount ? MS_REMOUNT : 0);

    if (sdcard) {
        // Mount external volumes with forced context
        strcat(data, ",context=u:object_r:sdcard_posix:s0");
    }

    rc = mount(fsPath, mountPoint, "f2fs", flags, data);

    if (sdcard && rc == 0) {
        // Write access workaround
        chown(mountPoint, AID_MEDIA_RW, AID_MEDIA_RW);
        chmod(mountPoint, 0755);
    }

    if (rc && errno == EROFS) {
        SLOGE("%s appears to be a read only filesystem - retrying mount RO", fsPath);
        flags |= MS_RDONLY;
        rc = mount(fsPath, mountPoint, "f2fs", flags, data);
    }

    return rc;
}

int F2FS::check(const char *fsPath) {

    int rc = -1;
    int status;

    if (access(F2FS_FSCK, X_OK)) {
        SLOGW("Skipping fs checks, fsck.f2fs not found.\n");
        return 0;
    }

    do {
        const char *args[3];
        args[0] = F2FS_FSCK;
        args[1] = fsPath;
        args[2] = NULL;

        rc = android_fork_execvp(ARRAY_SIZE(args), (char **)args, &status, false,
            true);

        switch(rc) {
        case 0:
            SLOGI("F2FS filesystem check completed OK.\n");
            return 0;
        case 1:
            SLOGI("F2FS filesystem check completed, errors corrected OK.\n");
            return 0;
        case 2:
            SLOGE("F2FS filesystem check completed, errors corrected, need reboot.\n");
            return 0;
        case 4:
            SLOGE("F2FS filesystem errors left uncorrected.\n");
            return 0;
        case 8:
            SLOGE("F2FS.fsck operational error.\n");
            errno = EIO;
            return -1;
        default:
            SLOGE("F2FS filesystem check failed (unknown exit code %d).\n", rc);
            errno = EIO;
            return -1;
        }
    } while (0);

    return 0;
}

int F2FS::format(const char *fsPath) {

    const char *args[3];
    int rc = -1;
    int status;

    if (access(F2FS_MKFS, X_OK)) {
        SLOGE("Unable to format, mkfs.f2fs not found.");
        return -1;
    }

    args[0] = F2FS_MKFS;
    args[1] = fsPath;
    args[2] = NULL;

    rc = android_fork_execvp(ARRAY_SIZE(args), (char **)args, &status, false,
            true);

    if (rc == 0) {
        SLOGI("Filesystem (F2FS) formatted OK");
        return 0;
    } else {
        SLOGE("Format (F2FS) failed (unknown exit code %d)", rc);
        errno = EIO;
        return -1;
    }
    return 0;
}
