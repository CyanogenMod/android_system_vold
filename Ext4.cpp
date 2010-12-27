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

#include "Ext4.h"

extern "C" int logwrap(int argc, const char **argv, int background);
extern "C" int mount(const char *, const char *, const char *, unsigned long, const void *);

int Ext4::check(const char *fsPath) {
    bool rw = true;
    SLOGE("Check SKIPPED (check not yet implemented in ext4)");
    //@@@ Need e2fsck
    return 0;
}

int Ext4::doMount(const char *fsPath, const char *mountPoint,
                 bool ro, bool remount, bool executable,
                 int ownerUid, int ownerGid, int permMask, bool createLost) {
    int rc;
    unsigned long flags;

    flags = MS_NODEV | MS_NOSUID | MS_NOATIME;

    flags |= (executable ? 0 : MS_NOEXEC);
    flags |= (ro ? MS_RDONLY : 0);
    flags |= (remount ? MS_REMOUNT : 0);

    const char *mountData = "noauto_da_alloc";

    rc = mount(fsPath, mountPoint, "ext4", flags, mountData);
    SLOGE("Ext4 Mount %s %d", fsPath, rc);

    if (rc && errno == EROFS) {
        SLOGE("%s appears to be a read only filesystem - retrying mount RO", fsPath);
        flags |= MS_RDONLY;
        rc = mount(fsPath, mountPoint, "ext4", flags, mountData);
    }
    return rc;
}



//@@@ Not tested!
int Ext4::format(const char *fsPath, unsigned int numSectors) {
    int fd;
    const char *args[11];
    int rc;

    args[0] = "/system/bin/make_ext4fs";
    args[1] = fsPath;
    args[2] = NULL;
    rc = logwrap(3, args, 1);

    if (rc == 0) {
        SLOGI("Ext4 Filesystem formatted OK");
        return 0;
    } else {
        SLOGE("Ext4 Format failed (unknown exit code %d)", rc);
        errno = EIO;
        return -1;
    }
    return 0;
}
