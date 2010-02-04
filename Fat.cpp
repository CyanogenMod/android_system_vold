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

#define LOG_TAG "Vold"

#include <cutils/log.h>
#include <cutils/properties.h>

#include "Fat.h"

static char FSCK_MSDOS_PATH[] = "/system/bin/fsck_msdos";
static char MKDOSFS_PATH[] = "/system/bin/newfs_msdos";
extern "C" int logwrap(int argc, const char **argv, int background);
extern "C" int mount(const char *, const char *, const char *, unsigned long, const void *);

int Fat::check(const char *fsPath) {
    bool rw = true;
    if (access(FSCK_MSDOS_PATH, X_OK)) {
        LOGW("Skipping fs checks\n");
        return 0;
    }

    int pass = 1;
    int rc = 0;
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
            LOGI("Filesystem check completed OK");
            return 0;

        case 2:
            LOGE("Filesystem check failed (not a FAT filesystem)");
            errno = ENODATA;
            return -1;

        case 4:
            if (pass++ <= 3) {
                LOGW("Filesystem modified - rechecking (pass %d)",
                        pass);
                continue;
            }
            LOGE("Failing check after too many rechecks");
            errno = EIO;
            return -1;

        default:
            LOGE("Filesystem check failed (unknown exit code %d)", rc);
            errno = EIO;
            return -1;
        }
    } while (0);

    return 0;
}

int Fat::doMount(const char *fsPath, const char *mountPoint,
                 bool ro, bool remount, int ownerUid, int ownerGid,
                 int permMask, bool createLost) {
    int rc;
    unsigned long flags;
    char mountData[255];

    flags = MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_DIRSYNC;

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
        LOGW("The SD card is world-writable because the"
            " 'persist.sampling_profiler' system property is set to '1'.");
        permMask = 0;
    }

    sprintf(mountData,
            "utf8,uid=%d,gid=%d,fmask=%o,dmask=%o,shortname=mixed",
            ownerUid, ownerGid, permMask, permMask);

    rc = mount(fsPath, mountPoint, "vfat", flags, mountData);

    if (rc && errno == EROFS) {
        LOGE("%s appears to be a read only filesystem - retrying mount RO", fsPath);
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
                LOGE("Unable to create LOST.DIR (%s)", strerror(errno));
            }
        }
        free(lost_path);
    }

    return rc;
}

int Fat::format(const char *fsPath) {
    unsigned int nr_sec;
    int fd;

    if ((fd = open(fsPath, O_RDWR)) < 0) {
        LOGE("Error opening disk file (%s)", strerror(errno));
        return -1;
    }

    if (ioctl(fd, BLKGETSIZE, &nr_sec)) {
        LOGE("Unable to get device size (%s)", strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);

    const char *args[9];
    int rc;
    args[0] = MKDOSFS_PATH;
    args[1] = "-F";
    args[2] = "32";
    args[3] = "-O";
    args[4] = "android";
    args[5] = "-c";
    args[6] = "8";
    args[7] = fsPath;
    args[8] = NULL;
    rc = logwrap(7, args, 1);

    if (rc == 0) {
        LOGI("Filesystem formatted OK");
        return 0;
    } else {
        LOGE("Format failed (unknown exit code %d)", rc);
        errno = EIO;
        return -1;
    }
    return 0;
}
