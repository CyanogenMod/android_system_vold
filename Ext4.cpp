/*
 * Copyright (C) 2012 The Android Open Source Project
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
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/mount.h>

#include <linux/kdev_t.h>
#include <linux/fs.h>

#define LOG_TAG "Vold"

#include <cutils/log.h>
#include <cutils/properties.h>

#include "Ext4.h"

static char E2FSCK_PATH[] = "/system/bin/e2fsck";
static char MKEXT4FS_PATH[] = "/system/bin/make_ext4fs";
static char STORAGE_DAEMON_PATH[] = "/system/bin/storage";

extern "C" int logwrap(int argc, const char **argv, int background);

int Ext4::isExt4(const char *fsPath) {
    if (access(E2FSCK_PATH, X_OK)) {
        SLOGW("Skipping fs checks\n");
        return -1;
    }

    int rc = 0;
    const char *args[3];
    args[0] = E2FSCK_PATH;
    args[1] = "-n";
    args[2] = fsPath;

    rc = logwrap(3, args, 1);

    if (rc >= 0 && rc <= 2) {
        // Looks like we've found a ext4 filesystem
        return true;
    } else {
        SLOGI("Filesystem type of %s is not ext4, return code(%d)", fsPath, rc);
        return false;
    }

    return false;
}

int Ext4::check(const char *fsPath) {
    bool rw = true;
    if (access(E2FSCK_PATH, X_OK)) {
        SLOGW("Skipping fs checks\n");
        return 0;
    }

    int pass = 1;
    int rc = 0;
    do {
        const char *args[5];
        args[0] = E2FSCK_PATH;
        args[1] = "-p";
        args[2] = "-f";
        args[3] = fsPath;
        args[4] = NULL;

        rc = logwrap(5, args, 1);

        switch(rc) {
        case 0:
            SLOGI("Filesystem check completed OK");
            return 0;
        case 1:
            SLOGI("Filesystem check completed, errors corrected OK");
            return 0;
        case 2:
            SLOGE("Filesystem check completed, errors corrected, need reboot");
            return 0;
        case 4:
            SLOGE("Filesystem errors left uncorrected");
            errno = EIO;
            return -1;
        case 8:
            SLOGE("Operational error");
            errno = EIO;
            return -1;
        default:
            SLOGE("Filesystem check failed (unknown exit code %d)", rc);
            errno = EIO;
            return -1;
        }
    } while (0);

    return 0;
}

int Ext4::doMount(const char *fsPath, char *mountPoint, bool ro, bool remount,
        bool executable) {
    int rc;
    unsigned long flags;

    flags = MS_NOATIME | MS_NODEV | MS_NOSUID | MS_DIRSYNC;

    flags |= (executable ? 0 : MS_NOEXEC);
    flags |= (ro ? MS_RDONLY : 0);
    flags |= (remount ? MS_REMOUNT : 0);

    rc = mount(fsPath, mountPoint, "ext4", flags, NULL);

    if (rc && errno == EROFS) {
        SLOGE("%s appears to be a read only filesystem - retrying mount RO", fsPath);
        flags |= MS_RDONLY;
        rc = mount(fsPath, mountPoint, "ext4", flags, NULL);
    }

    return rc;
}

int Ext4::doFuse(char *src, const char *dst) {
    int rc = 0;
    const char *args[5];
    args[0] = STORAGE_DAEMON_PATH;
    args[1] = src;
    args[2] = dst;
    args[3] = "1023";
    args[4] = "1023";

    rc = logwrap(5, args, 1);
    return rc;
}

int Ext4::format(const char *fsPath) {
    int fd;
    const char *args[4];
    int rc;

    args[0] = MKEXT4FS_PATH;
    args[1] = "-J";
    args[2] = fsPath;
    args[3] = NULL;
    rc = logwrap(3, args, 1);

    if (rc == 0) {
        SLOGI("Filesystem (ext4) formatted OK");
        return 0;
    } else {
        SLOGE("Format (ext4) failed (unknown exit code %d)", rc);
        errno = EIO;
        return -1;
    }
    return 0;
}
