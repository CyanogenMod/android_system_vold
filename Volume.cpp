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

#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>

#define LOG_TAG "Vold"

#include <cutils/log.h>

#include "Volume.h"

extern "C" int logwrap(int argc, const char **argv, int background);

static char FSCK_MSDOS_PATH[] = "/system/bin/fsck_msdos";

Volume::Volume(const char *label, const char *mount_point) {
    mLabel = strdup(label);
    mMountpoint = strdup(mount_point);
    mState = Volume::State_Init;
}

Volume::~Volume() {
    free(mLabel);
    free(mMountpoint);
}

int Volume::handleBlockEvent(NetlinkEvent *evt) {
    errno = ENOSYS;
    return -1;
}

void Volume::setState(int state) {
    LOGD("Volume %s state changing %d -> %d", mLabel, mState, state);
    mState = state;
}

int Volume::createDeviceNode(const char *path, int major, int minor) {
    mode_t mode = 0660 | S_IFBLK;
    dev_t dev = (major << 8) | minor;
    if (mknod(path, mode, dev) < 0) {
        if (errno != EEXIST) {
            return -1;
        }
    }
    return 0;
}

int Volume::mount() {
    char nodepath[255];
    int major = -1, minor = -1;

    if (prepareToMount(&major, &minor)) {
        LOGE("Volume failed to prepare: %s", strerror(errno));
        return -1;
    }

    sprintf(nodepath, "/dev/block/vold/%d:%d", major, minor);

    LOGD("nodepath = %s\n", nodepath);

    /* Create device nodes */
    if (createDeviceNode(nodepath, major, minor)) {
        LOGE("Error making device nodes for '%s' (%s)", nodepath,
             strerror(errno));
        // XXX: cleanup will be needed eventually
        return -1;
    }

    /* Run disk checker */
    if (checkFilesystem(nodepath)) {
        LOGE("Error checking filesystem (%s)", strerror(errno));
        setState(Volume::State_Idle);
        return -1;
    }

    

    setState(Volume::State_Idle);
    return 0;
}

int Volume::checkFilesystem(const char *nodepath) {

    bool rw = true;
    if (access(FSCK_MSDOS_PATH, X_OK)) {
        LOGW("Skipping fs checks\n");
        return 0;
    }

    setState(Volume::State_Checking);
    int pass = 1;
    int rc = 0;
    do {
        const char *args[5];
        args[0] = FSCK_MSDOS_PATH;
        args[1] = "-p";
        args[2] = "-f";
        args[3] = nodepath;
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

int Volume::unmount() {
    return 0;
}
