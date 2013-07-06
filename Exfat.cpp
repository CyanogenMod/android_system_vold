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

#define LOG_TAG "Vold"

#include <cutils/log.h>
#include <cutils/properties.h>

#include "Exfat.h"

static char EXFATFSCK_PATH[] = "/system/bin/exfatfsck";
static char MKEXFATFS_PATH[] = "/system/bin/mkexfatfs";
static char EXFAT_FUSE_PATH[] = "/system/bin/exfat-fuse";

extern "C" int logwrap(int argc, const char **argv, int background);


int Exfat::doMount(const char *fsPath, const char *mountPoint,
                 bool ro, bool remount, bool executable,
                 int ownerUid, int ownerGid, int permMask) {

    int rc = 0;
    unsigned long flags;
    char mountData[255];
    pid_t pid;

    flags = MS_NOATIME | MS_NODEV | MS_NOSUID | MS_DIRSYNC;

    sprintf(mountData,
            "uid=%d,gid=%d,fmask=%o,dmask=%o",
            ownerUid, ownerGid, permMask, permMask);
        

    flags |= (executable ? 0 : MS_NOEXEC);
    flags |= (ro ? MS_RDONLY : 0);
    flags |= (remount ? MS_REMOUNT : 0);

    const char* const args[] = { EXFAT_FUSE_PATH, "-o", mountData, fsPath, mountPoint, NULL };

    pid = fork();

    if (pid == 0) {
        SLOGW("Executing exfat mount (%s) -> (%s)", fsPath, mountPoint);
        if ((rc = execv(EXFAT_FUSE_PATH, (char* const*)args)) == -1) {
            SLOGE("Failed to invoke FUSE exfat helper!");
        }
    } else if (pid > 0) {
        SLOGI("Wait for %d", pid);
        wait(&rc);
    } else {
        SLOGE("Fork failed!");
    }

    return rc;
}

int Exfat::check(const char *fsPath) {
    bool rw = true;
    if (access(EXFATFSCK_PATH, X_OK)) {
        SLOGW("Skipping fs checks.\n");
        return 0;
    }

    int rc = -1;
    do {
        const char *args[3];
        args[0] = EXFATFSCK_PATH;
        args[1] = fsPath;
        args[2] = NULL;

        rc = logwrap(3, args, 1);

        switch(rc) {
        case 0:
            SLOGI("Exfat Filesystem check completed OK.\n");
            return 0;
        case 1:
            SLOGI("Exfat Filesystem check completed, errors corrected OK.\n");
            return 0;
        case 2:
            SLOGE("Exfat Filesystem check completed, errors corrected, need reboot.\n");
            return 0;
        case 4:
            SLOGE("Exfat Filesystem errors left uncorrected.\n");
            return 0;
        case 8:
            SLOGE("EXFATFSCK Operational error.\n");
            errno = EIO;
            return -1;
        default:
            SLOGE("Exfat Filesystem check failed (unknown exit code %d).\n", rc);
            errno = EIO;
            return -1;
        }
    } while (0);

    return 0;
}

int Exfat::format(const char *fsPath) {
    int fd;
    const char *args[3];
    int rc;

    args[0] = MKEXFATFS_PATH;
    args[1] = fsPath;
    args[2] = NULL;
    rc = logwrap(3, args, 1);

    if (rc == 0) {
        SLOGI("Filesystem (exfat) formatted OK");
        return 0;
    } else {
        SLOGE("Format (exfat) failed (unknown exit code %d)", rc);
        errno = EIO;
        return -1;
    }
    return 0;
}
