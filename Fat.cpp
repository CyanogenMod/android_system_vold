/*
 * Copyright (C) 2008 The Android Open Source Project
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

#include "Fat.h"

#define MAX_BUFFER 1024

static char BLKID_PATH[] = "/system/xbin/blkid";
static char FSCK_MSDOS_PATH[] = "/system/bin/fsck_msdos";
static char MKDOSFS_PATH[] = "/system/bin/newfs_msdos";

extern "C" int logwrap(int argc, const char **argv, int background);
extern "C" int mount(const char *, const char *, const char *, unsigned long, const void *);

int Fat::isFat(const char *fsPath) {
    if (access(BLKID_PATH, X_OK)) {
        SLOGW("Skipping FAT test.\n");
        return -1;
    }

    int rc = false;
    FILE *pipe_reader;
    char pipe_buff[MAX_BUFFER];
    char fstype[] = "vfat";
    void *strptr = NULL;
    char* blkid = (char*) malloc(strlen(BLKID_PATH) + strlen(fsPath) + 2);
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
        SLOGI("Filesystem type of %s is not FAT.\n", fsPath);
        return false;
    } else {
        SLOGI("%s contains a FAT filesystem.\n", fsPath);
        return true;
    }

    return false;
}

int Fat::check(const char *fsPath) {
    bool rw = true;
    if (access(FSCK_MSDOS_PATH, X_OK)) {
        SLOGW("Skipping fs checks.\n");
        return 0;
    }

    int pass = 1;
    int rc = -1;
    do {
        const char *args[5];
        args[0] = FSCK_MSDOS_PATH;
        args[1] = "-p";
        args[2] = "-f";
        args[3] = fsPath;
        args[4] = NULL;

        rc = logwrap(4, args, 1);

        switch(rc) {
        case 0:
            SLOGI("FAT Filesystem check completed OK.\n");
            return 0;

        case 2:
            SLOGE("Filesystem check failed (not a FAT filesystem).\n");
            errno = ENODATA;
            return -1;

        case 4:
            if (pass++ <= 3) {
                SLOGW("FAT Filesystem modified - rechecking (pass %d).\n",
                        pass);
                continue;
            }
            SLOGE("FAT Failing check after too many rechecks.\n");
            errno = EIO;
            return -1;

        default:
            SLOGE("FAT Filesystem check failed (unknown exit code %d).\n", rc);
            errno = EIO;
            return -1;
        }
    } while (0);

    return 0;
}

int Fat::doMount(const char *fsPath, const char *mountPoint,
                 bool ro, bool remount, bool executable,
                 int ownerUid, int ownerGid, int permMask, bool createLost) {
    int rc;
    unsigned long flags;
    char mountData[255];

    flags = MS_NODEV | MS_NOSUID | MS_DIRSYNC;

    flags |= (executable ? 0 : MS_NOEXEC);
    flags |= (ro ? MS_RDONLY : 0);
    flags |= (remount ? MS_REMOUNT : 0);

    /*
     * Note: This is a temporary hack. If the sampling profiler is enabled,
     * we make the SD card world-writable so any process can write snapshots.
     *
     * TODO: Remove this code once we have a drop box in system_server.
     */
    char value[PROPERTY_VALUE_MAX];
    property_get("persist.sampling_profiler", value, "");
    if (value[0] == '1') {
        SLOGW("The SD card is world-writable because the"
            " 'persist.sampling_profiler' system property is set to '1'.");
        permMask = 0;
    }

    sprintf(mountData,
            "utf8,uid=%d,gid=%d,fmask=%o,dmask=%o,shortname=mixed",
            ownerUid, ownerGid, permMask, permMask);

    rc = mount(fsPath, mountPoint, "vfat", flags, mountData);

    if (rc && errno == EROFS) {
        SLOGE("%s appears to be a read only filesystem - retrying mount RO", fsPath);
        flags |= MS_RDONLY;
        rc = mount(fsPath, mountPoint, "vfat", flags, mountData);
    }

    if (rc == 0 && createLost) {
        char *lost_path;
        asprintf(&lost_path, "%s/LOST.DIR", mountPoint);
        if (access(lost_path, F_OK)) {
            /*
             * Create a LOST.DIR in the root so we have somewhere to put
             * lost cluster chains (fsck_msdos doesn't currently do this)
             */
            if (mkdir(lost_path, 0755)) {
                SLOGE("Unable to create LOST.DIR (%s)", strerror(errno));
            }
        }
        free(lost_path);
    }

    return rc;
}

int Fat::format(const char *fsPath, unsigned int numSectors) {
    int fd;
    const char *args[11];
    int rc;

    args[0] = MKDOSFS_PATH;
    args[1] = "-F";
    args[2] = "32";
    args[3] = "-O";
    args[4] = "android";
    args[5] = "-c";
    args[6] = "8";

    if (numSectors) {
        char tmp[32];
        snprintf(tmp, sizeof(tmp), "%u", numSectors);
        const char *size = tmp;
        args[7] = "-s";
        args[8] = size;
        args[9] = fsPath;
        args[10] = NULL;
        rc = logwrap(11, args, 1);
    } else {
        args[7] = fsPath;
        args[8] = NULL;
        rc = logwrap(9, args, 1);
    }

    if (rc == 0) {
        SLOGI("Filesystem formatted OK");
        return 0;
    } else {
        SLOGE("Format failed (unknown exit code %d)", rc);
        errno = EIO;
        return -1;
    }
    return 0;
}
