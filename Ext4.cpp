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
#include <sys/wait.h>

#include <linux/kdev_t.h>

#define LOG_TAG "Vold"

#include <cutils/log.h>
#include <cutils/properties.h>

#include <logwrap/logwrap.h>

#include "Ext4.h"
#include "VoldUtil.h"

static char E2FSCK_PATH[] = "/system/bin/e2fsck";
static char RESIZE2FS_PATH[] = "/system/bin/resize2fs";
static char MKEXT4FS_PATH[] = "/system/bin/make_ext4fs";
static char MKE2FS_PATH[] = "/system/bin/mke2fs";

int Ext4::doMount(const char *fsPath, const char *mountPoint, bool ro, bool remount,
        bool executable, bool sdcard, const char *mountOpts) {
    int rc;
    unsigned long flags;
    char data[1024];

    data[0] = '\0';
    if (mountOpts)
        strlcat(data, mountOpts, sizeof(data));

    flags = MS_NOATIME | MS_NODEV | MS_NOSUID | MS_DIRSYNC;

    flags |= (executable ? 0 : MS_NOEXEC);
    flags |= (ro ? MS_RDONLY : 0);
    flags |= (remount ? MS_REMOUNT : 0);

    if (sdcard) {
        // Mount external volumes with forced context
        if (data[0])
            strlcat(data, ",", sizeof(data));
        strlcat(data, "context=u:object_r:sdcard_posix:s0", sizeof(data));
    }

    rc = mount(fsPath, mountPoint, "ext4", flags, data);

    if (rc && errno == EROFS) {
        SLOGE("%s appears to be a read only filesystem - retrying mount RO", fsPath);
        flags |= MS_RDONLY;
        rc = mount(fsPath, mountPoint, "ext4", flags, data);
    }

    return rc;
}

int Ext4::check(const char *fsPath) {
    bool rw = true;
    if (access(E2FSCK_PATH, X_OK)) {
        SLOGW("Skipping fs checks.\n");
        return 0;
    }

    int rc = -1;
    int status;
    do {
        const char *args[5];
        args[0] = E2FSCK_PATH;
        args[1] = "-p";
        args[2] = "-f";
        args[3] = fsPath;
        args[4] = NULL;

        rc = android_fork_execvp(ARRAY_SIZE(args), (char **)args, &status, false,
            true);

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

int Ext4::resize(const char *fspath, unsigned int numSectors) {
    const char *args[4];
    char* size_str;
    int rc;
    int status;

    args[0] = RESIZE2FS_PATH;
    args[1] = "-f";
    args[2] = fspath;
    if (asprintf(&size_str, "%ds", numSectors) < 0)
    {
      SLOGE("Filesystem (ext4) resize failed to set size");
      return -1;
    }
    args[3] = size_str;
    rc = android_fork_execvp(ARRAY_SIZE(args), (char **)args, &status, false,
            true);
    free(size_str);
    if (rc != 0) {
        SLOGE("Filesystem (ext4) resize failed due to logwrap error");
        errno = EIO;
        return -1;
    }

    if (!WIFEXITED(status)) {
        SLOGE("Filesystem (ext4) resize did not exit properly");
        errno = EIO;
        return -1;
    }

    status = WEXITSTATUS(status);

    if (status == 0) {
        SLOGI("Filesystem (ext4) resized OK");
        return 0;
    } else {
        SLOGE("Resize (ext4) failed (unknown exit code %d)", status);
        errno = EIO;
        return -1;
    }
    return 0;
}

int Ext4::format(const char *fsPath, unsigned int numSectors, const char *mountpoint) {
    int fd;
    const char *args[7];
    int rc;
    int status;

    if (mountpoint == NULL) {
        args[0] = MKE2FS_PATH;
        args[1] = "-j";
        args[2] = "-T";
        args[3] = "ext4";
        args[4] = fsPath;
        rc = android_fork_execvp(5, (char **)args, &status, false, true);
    } else {
        args[0] = MKEXT4FS_PATH;
        args[1] = "-J";
        args[2] = "-a";
        args[3] = mountpoint;
        if (numSectors) {
            char tmp[32];
            snprintf(tmp, sizeof(tmp), "%u", numSectors * 512);
            const char *size = tmp;
            args[4] = "-l";
            args[5] = size;
            args[6] = fsPath;
            rc = android_fork_execvp(ARRAY_SIZE(args), (char **)args, &status, false, true);
        } else {
            args[4] = fsPath;
            rc = android_fork_execvp(5, (char **)args, &status, false, true);
        }
    }

    if (rc != 0) {
        SLOGE("Filesystem (ext4) format failed due to logwrap error");
        errno = EIO;
        return -1;
    }

    if (!WIFEXITED(status)) {
        SLOGE("Filesystem (ext4) format did not exit properly");
        errno = EIO;
        return -1;
    }

    status = WEXITSTATUS(status);

    if (status == 0) {
        SLOGI("Filesystem (ext4) formatted OK");
        return 0;
    } else {
        SLOGE("Format (ext4) failed (unknown exit code %d)", status);
        errno = EIO;
        return -1;
    }
    return 0;
}
