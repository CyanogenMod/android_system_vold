/*
 * Copyright (C) 2012 The Android Open Source Project
 * Copyright (C) 2013 The CyanogenMod Project
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
#include <sys/wait.h>

#include <linux/kdev_t.h>
#include <logwrap/logwrap.h>
#include "VoldUtil.h"

#define LOG_TAG "Vold"

#include <cutils/log.h>
#include <cutils/properties.h>

#include "Exfat.h"

static char EXFAT_FSCK[] = "/system/bin/fsck.exfat";
static char EXFAT_MKFS[] = "/system/bin/mkfs.exfat";
static char EXFAT_MOUNT[] = "/system/bin/mount.exfat";

int Exfat::doMount(const char *fsPath, const char *mountPoint,
                 bool ro, bool remount, bool executable,
                 int ownerUid, int ownerGid, int permMask) {

    int rc = -1;
    char mountData[255];
    const char *args[6];
    int status;

    if (access(EXFAT_MOUNT, X_OK)) {
        SLOGE("Unable to mount, exFAT FUSE helper not found!");
        return rc;
    }

    sprintf(mountData,
            "noatime,nodev,nosuid,dirsync,uid=%d,gid=%d,fmask=%o,dmask=%o,%s,%s",
            ownerUid, ownerGid, permMask, permMask,
            (executable ? "exec" : "noexec"),
            (ro ? "ro" : "rw"));

    args[0] = EXFAT_MOUNT;
    args[1] = "-o";
    args[2] = mountData;
    args[3] = fsPath;
    args[4] = mountPoint;
    args[5] = NULL;

    SLOGW("Executing exFAT mount (%s) -> (%s)", fsPath, mountPoint);

    rc = android_fork_execvp(ARRAY_SIZE(args), (char **)args, &status, false,
            true);

    if (rc && errno == EROFS) {
        SLOGE("%s appears to be a read only filesystem - retrying mount RO", fsPath);
        strcat(mountData, ",ro");
        rc = android_fork_execvp(ARRAY_SIZE(args), (char **)args, &status, false,
            true);
    }

    return rc;
}

int Exfat::check(const char *fsPath) {

    bool rw = true;
    int rc = -1;
    int status;

    if (access(EXFAT_FSCK, X_OK)) {
        SLOGW("Skipping fs checks, exfatfsck not found.\n");
        return 0;
    }

    do {
        const char *args[3];
        args[0] = EXFAT_FSCK;
        args[1] = fsPath;
        args[2] = NULL;

        rc = android_fork_execvp(ARRAY_SIZE(args), (char **)args, &status, false,
            true);

        switch(rc) {
        case 0:
            SLOGI("exFAT filesystem check completed OK.\n");
            return 0;
        case 1:
            SLOGI("exFAT filesystem check completed, errors corrected OK.\n");
            return 0;
        case 2:
            SLOGE("exFAT filesystem check completed, errors corrected, need reboot.\n");
            return 0;
        case 4:
            SLOGE("exFAT filesystem errors left uncorrected.\n");
            return 0;
        case 8:
            SLOGE("exfatfsck operational error.\n");
            errno = EIO;
            return -1;
        default:
            SLOGE("exFAT filesystem check failed (unknown exit code %d).\n", rc);
            errno = EIO;
            return -1;
        }
    } while (0);

    return 0;
}

int Exfat::format(const char *fsPath) {

    int fd;
    const char *args[3];
    int rc = -1;
    int status;

    if (access(EXFAT_MKFS, X_OK)) {
        SLOGE("Unable to format, mkexfatfs not found.");
        return -1;
    }

    args[0] = EXFAT_MKFS;
    args[1] = fsPath;
    args[2] = NULL;

    rc = android_fork_execvp(ARRAY_SIZE(args), (char **)args, &status, false,
            true);

    if (rc == 0) {
        SLOGI("Filesystem (exFAT) formatted OK");
        return 0;
    } else {
        SLOGE("Format (exFAT) failed (unknown exit code %d)", rc);
        errno = EIO;
        return -1;
    }
    return 0;
}
