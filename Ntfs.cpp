/*
 * Copyright (C) 2008 The Android Open Source Project
 * Copyright (C) 2012 Freescale Semiconductor, Inc.
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
#include <logwrap/logwrap.h>
#include "VoldUtil.h"

#define LOG_TAG "Vold"

#include <cutils/log.h>
#include <cutils/properties.h>

#include "Ntfs.h"

static char NTFS_FIX_PATH[] = "/system/bin/ntfsfix";
static char NTFS_MOUNT_PATH[] = "/system/bin/ntfs-3g";
static char MKNTFS_PATH[] = "/system/bin/mkntfs";

int Ntfs::check(const char *fsPath) {

    if (access(NTFS_FIX_PATH, X_OK)) {
        SLOGW("Skipping fs checks\n");
        return 0;
    }

    int rc = 0;
    int status;
    const char *args[4];
    /* we first use -n to do ntfs detection */
    args[0] = NTFS_FIX_PATH;
    args[1] = "-n";
    args[2] = fsPath;
    args[3] = NULL;

    rc = android_fork_execvp(ARRAY_SIZE(args), (char **)args, &status, false,
            true);
    if (rc) {
        errno = ENODATA;
        return -1;
    }

    SLOGI("Ntfs filesystem existed");

    /* do the real fix */
    /* redo the ntfsfix without -n to fix problems */
    args[1] = fsPath;
    args[2] = NULL;

    rc = android_fork_execvp(ARRAY_SIZE(args), (char **)args, &status, false,
            true);
    if (rc) {
        errno = EIO;
        SLOGE("Filesystem check failed (unknown exit code %d)", rc);
        return -1;
    }

    SLOGI("Ntfs filesystem check completed OK");
    return 0;
}

int Ntfs::doMount(const char *fsPath, const char *mountPoint,
                 bool ro, bool remount, bool executable,
                 int ownerUid, int ownerGid, int permMask, bool createLost) {
    int rc;
    char mountData[255];
    const char *args[6];
    int status;

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
            "utf8,uid=%d,gid=%d,fmask=%o,dmask=%o,"
	    "shortname=mixed,nodev,nosuid,dirsync",
            ownerUid, ownerGid, permMask, permMask);

    if (!executable)
        strcat(mountData, ",noexec");
    if (ro)
        strcat(mountData, ",ro");
    if (remount)
        strcat(mountData, ",remount");

    SLOGD("Mounting ntfs with options:%s\n", mountData);

    args[0] = NTFS_MOUNT_PATH;
    args[1] = "-o";
    args[2] = mountData;
    args[3] = fsPath;
    args[4] = mountPoint;
    args[5] = NULL;

    rc = android_fork_execvp(ARRAY_SIZE(args), (char **)args, &status, false,
            true);

    if (rc && errno == EROFS) {
        SLOGE("%s appears to be a read only filesystem - retrying mount RO", fsPath);
        strcat(mountData, ",ro");
        rc = android_fork_execvp(ARRAY_SIZE(args), (char **)args, &status, false,
            true);

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

int Ntfs::format(const char *fsPath, bool wipe) {

    const char *args[4];
    int rc = -1;
    int status;

    if (access(MKNTFS_PATH, X_OK)) {
        SLOGE("Unable to format, mkntfs not found.");
        return -1;
    }

    args[0] = MKNTFS_PATH;
    if (wipe) {
        args[1] = fsPath;
        args[2] = NULL;
    } else {
        args[1] = "-f";
        args[2] = fsPath;
        args[3] = NULL;
    }

    rc = android_fork_execvp(ARRAY_SIZE(args), (char **)args, &status, false,
            true);

    if (rc == 0) {
        SLOGI("Filesystem (NTFS) formatted OK");
        return 0;
    } else {
        SLOGE("Format (NTFS) failed (unknown exit code %d)", rc);
        errno = EIO;
        return -1;
    }
    return 0;
}
