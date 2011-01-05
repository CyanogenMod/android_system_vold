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
#include <stdlib.h>
#include <limits.h>
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
#include <semaphore.h>

#define LOG_TAG "Vold"

#include <cutils/log.h>
#include <cutils/properties.h>

#include <sys/types.h>
#include <sys/wait.h>

#include "Ext4.h"

extern "C" int logwrap(int argc, const char **argv, int background);
extern "C" int mount(const char *, const char *, const char *, unsigned long, const void *);

int Ext4::check(const char *fsPath) {
    bool rw = true;
    SLOGE("Check SKIPPED (check not yet implemented in ext4)");
    //@@@ Need e2fsck
    return 0;
}

static sem_t mutex;

void sig_action_function(int sig)
{
    sem_post(&mutex);
}

// Make a temp mount point from path.  Mountpoint must be at least PATH_MAX
const char *mntDir = "/mnt/obb/ext4_";
void make_tmp_mount_path(char *mountPoint, const char *path) {
    strcpy(mountPoint, mntDir);
    strcat(mountPoint, path);
    char *p = mountPoint+strlen(mntDir);
    p = strchr(p, '/');
    while(p) {
        *p++ = '_';
        p = strchr(p, '/');
    }
    SLOGI("Ext4 tmp mount point %s", mountPoint);
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
    char tmpDirName[PATH_MAX+1];
    make_tmp_mount_path(tmpDirName, mountPoint);
    rc = mkdir(tmpDirName, 0666);
    if(rc) {
        if(errno != EEXIST) {
            SLOGI("Error %d creating ext4 mount point %s", rc, tmpDirName);
            return rc;
        }
    }
    SLOGI("mounting ext4 on temp: %s", tmpDirName);

    const char *mountData = "noauto_da_alloc,journal_async_commit,commit=120,barrier=0";
    
    rc = mount(fsPath, tmpDirName, "ext4", flags, mountData);
    // If the mount failed as BUSY and we are not remounting, try a remount
    if (rc && remount == false && errno == EBUSY) {
        SLOGE("%s appears to be busy - trying a remount", fsPath);
        flags |= MS_REMOUNT;
        rc = mount(fsPath, tmpDirName, "ext4", flags, mountData);
    }
    if (rc && errno == EROFS) {
        SLOGE("%s appears to be a read only filesystem - retrying mount RO", fsPath);
        flags |= MS_RDONLY;
        rc = mount(fsPath, mountPoint, "ext4", flags, mountData);
    }
    if (rc)
        return rc;
    sem_init(&mutex, 0, 0);
    signal(SIGUSR1,sig_action_function);
    if (!fork()) {
        execl("/system/bin/sdcard", "sdcard", tmpDirName, "0", "0", mountPoint, NULL);
        SLOGE("Error %s executing sdcard", strerror(errno));
        kill(getppid(), SIGUSR1);
        exit(0);
    }
    else {
        struct timespec req;
        req.tv_sec = time(NULL)+4;
        req.tv_nsec = 0;
        rc = sem_timedwait(&mutex, &req);
        if(rc)
            SLOGE("Error %s waiting for sem", strerror(errno));
    }
    sem_destroy(&mutex);
    return rc;
}

void Ext4::cleanupUnmount(const char *mountPoint)
{
    char tmpDirName[PATH_MAX+1];
    make_tmp_mount_path(tmpDirName, mountPoint);
    if (umount(tmpDirName) )
        SLOGE("Ext4::cleanupUnmount(%s) [%s] unmount failed: %s", mountPoint, tmpDirName, strerror(errno));
    // Fall through from above - still try to cleanup temp directory.
    if(rmdir(tmpDirName))
        SLOGE("Ext4::cleanupUnmount(%s) [%s] failed: %s", mountPoint, tmpDirName, strerror(errno));
}


//@@@ Not tested!
int Ext4::format(const char *fsPath, unsigned int numSectors) {
    int fd;
    const char *args[11];
    int rc;

#if 0    
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
#else
    SLOGE("Ext4 Format failed (not yet implemented)");
    return -1;
#endif    
}
