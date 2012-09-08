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

#define MAX_BUFFER 1024

static char BLKID_PATH[] = "/system/xbin/blkid";
static char E2FSCK_PATH[] = "/system/bin/e2fsck";
static char MKEXT4FS_PATH[] = "/system/bin/make_ext4fs";

extern "C" int logwrap(int argc, const char **argv, int background);

int Ext4::isExt4(const char *fsPath) {
    if (access(BLKID_PATH, X_OK)) {
        SLOGW("Skipping EXT4 test.\n");
        return -1;
    }

    FILE *pipe_reader;
    char pipe_buff[MAX_BUFFER];
    char fstype[] = "ext4";
    void *strptr = NULL;
    char* blkid = (char*) malloc(strlen(BLKID_PATH) + strlen(fsPath) + 1);
    sprintf(blkid, "%s %s", BLKID_PATH, fsPath);

    if ((pipe_reader = popen(blkid, "r")) != NULL) {
        while(1)
        {
            if(fgets(pipe_buff, MAX_BUFFER, pipe_reader) == NULL)
            break;
        }
        pclose(pipe_reader);
    } else {
        SLOGI("Determining of filesystem type for %s failed.\n", fsPath);
        return false;
    }

    strptr = strstr(pipe_buff, fstype);
    if (strptr == NULL) {
        SLOGI("Filesystem type of %s is not EXT4.\n", fsPath);
        return false;
    } else {
        SLOGI("%s contains a EXT4 filesystem.\n", fsPath);
        return true;
    }

    return false;
}

int Ext4::check(const char *fsPath) {
    bool rw = true;
    if (access(E2FSCK_PATH, X_OK)) {
        SLOGW("Skipping fs checks.\n");
        return 0;
    }

    int rc = -1;
    do {
        const char *args[5];
        args[0] = E2FSCK_PATH;
        args[1] = "-p";
        args[2] = "-f";
        args[3] = fsPath;
        args[4] = NULL;

        rc = logwrap(4, args, 1);

        switch(rc) {
        case 0:
            SLOGI("EXT4 Filesystem check completed OK.\n");
            return 0;
        case 1:
            SLOGI("EXT4 Filesystem check completed, errors corrected OK.\n");
            return 0;
        case 2:
            SLOGE("EXT4 Filesystem check completed, errors corrected, need reboot.\n");
            return 0;
        case 4:
            SLOGE("EXT4 Filesystem errors left uncorrected.\n");
            return 0;
        case 8:
            SLOGE("E2FSCK Operational error.\n");
            errno = EIO;
            return -1;
        default:
            SLOGE("EXT4 Filesystem check failed (unknown exit code %d).\n", rc);
            errno = EIO;
            return -1;
        }
    } while (0);

    return 0;
}

int Ext4::doMount(const char *fsPath, char *mountPoint,
                  bool ro, bool remount, bool executable) {
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

int Ext4::format(const char *fsPath) {
    int fd;
    int rc;
    const char *args[4];

    args[0] = MKEXT4FS_PATH;
    args[1] = "-J";
    args[2] = fsPath;
    args[3] = NULL;
    rc = logwrap(4, args, 1);

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
