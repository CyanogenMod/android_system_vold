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
#include <sys/mount.h>

#include <linux/kdev_t.h>

#include <cutils/properties.h>

#include "diskmbr.h"

#define LOG_TAG "Vold"

#include <cutils/log.h>

#include "Volume.h"
#include "VolumeManager.h"
#include "ResponseCode.h"
#include "Fat.h"

extern "C" void KillProcessesWithOpenFiles(const char *, int, int, int);
extern "C" void dos_partition_dec(void const *pp, struct dos_partition *d);
extern "C" void dos_partition_enc(void *pp, struct dos_partition *d);

static const char *stateToStr(int state) {
    if (state == Volume::State_Init)
        return "Initializing";
    else if (state == Volume::State_NoMedia)
        return "No-Media";
    else if (state == Volume::State_Idle)
        return "Idle-Unmounted";
    else if (state == Volume::State_Pending)
        return "Pending";
    else if (state == Volume::State_Mounted)
        return "Mounted";
    else if (state == Volume::State_Unmounting)
        return "Unmounting";
    else if (state == Volume::State_Checking)
        return "Checking";
    else if (state == Volume::State_Formatting)
        return "Formatting";
    else if (state == Volume::State_Shared)
        return "Shared-Unmounted";
    else if (state == Volume::State_SharedMnt)
        return "Shared-Mounted";
    else
        return "Unknown-Error";
}

Volume::Volume(VolumeManager *vm, const char *label, const char *mount_point) {
    mVm = vm;
    mLabel = strdup(label);
    mMountpoint = strdup(mount_point);
    mState = Volume::State_Init;
    mCurrentlyMountedKdev = -1;
}

Volume::~Volume() {
    free(mLabel);
    free(mMountpoint);
}

dev_t Volume::getDiskDevice() {
    return MKDEV(0, 0);
};

void Volume::handleVolumeShared() {
}

void Volume::handleVolumeUnshared() {
}

int Volume::handleBlockEvent(NetlinkEvent *evt) {
    errno = ENOSYS;
    return -1;
}

void Volume::setState(int state) {
    char msg[255];
    int oldState = mState;

    if (oldState == state) {
        LOGW("Duplicate state (%d)\n", state);
        return;
    }

    mState = state;

    LOGD("Volume %s state changing %d (%s) -> %d (%s)", mLabel,
         oldState, stateToStr(oldState), mState, stateToStr(mState));
    snprintf(msg, sizeof(msg),
             "Volume %s %s state changed from %d (%s) to %d (%s)", getLabel(),
             getMountpoint(), oldState, stateToStr(oldState), mState,
             stateToStr(mState));

    mVm->getBroadcaster()->sendBroadcast(ResponseCode::VolumeStateChange,
                                         msg, false);
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

int Volume::formatVol() {

    if (getState() == Volume::State_NoMedia) {
        errno = ENODEV;
        return -1;
    } else if (getState() != Volume::State_Idle) {
        errno = EBUSY;
        return -1;
    }

    if (isMountpointMounted(getMountpoint())) {
        LOGW("Volume is idle but appears to be mounted - fixing");
        setState(Volume::State_Mounted);
        // mCurrentlyMountedKdev = XXX
        errno = EBUSY;
        return -1;
    }

    char devicePath[255];
    dev_t diskNode = getDiskDevice();
    dev_t partNode = MKDEV(MAJOR(diskNode), 1); // XXX: Hmmm

    sprintf(devicePath, "/dev/block/vold/%d:%d",
            MAJOR(diskNode), MINOR(diskNode));

    LOGI("Volume %s (%s) MBR being initialized", getLabel(), devicePath);

    if (initializeMbr(devicePath)) {
        LOGE("Failed to initialize MBR (%s)", strerror(errno));
        goto err;
    }

    sprintf(devicePath, "/dev/block/vold/%d:%d",
            MAJOR(partNode), MINOR(partNode));

    LOGI("Volume %s (%s) being formatted", getLabel(), devicePath);

    if (Fat::format(devicePath)) {
        LOGE("Failed to format (%s)", strerror(errno));
        goto err;
    }

    LOGI("Volume %s (%s) formatted sucessfully", getLabel(), devicePath);
    return 0;
err:
    return -1;
}

bool Volume::isMountpointMounted(const char *path) {
    char device[256];
    char mount_path[256];
    char rest[256];
    FILE *fp;
    char line[1024];

    if (!(fp = fopen("/proc/mounts", "r"))) {
        LOGE("Error opening /proc/mounts (%s)", strerror(errno));
        return false;
    }

    while(fgets(line, sizeof(line), fp)) {
        line[strlen(line)-1] = '\0';
        sscanf(line, "%255s %255s %255s\n", device, mount_path, rest);
        if (!strcmp(mount_path, path)) {
            fclose(fp);
            return true;
        }

    }

    fclose(fp);
    return false;
}

int Volume::mountVol() {
    dev_t deviceNodes[4];
    int n, i, rc = 0;
    char errmsg[255];

    if (getState() == Volume::State_NoMedia) {
        snprintf(errmsg, sizeof(errmsg),
                 "Volume %s %s mount failed - no media",
                 getLabel(), getMountpoint());
        mVm->getBroadcaster()->sendBroadcast(
                                         ResponseCode::VolumeMountFailedNoMedia,
                                         errmsg, false);
        errno = ENODEV;
        return -1;
    } else if (getState() != Volume::State_Idle) {
        errno = EBUSY;
        return -1;
    }

    if (isMountpointMounted(getMountpoint())) {
        LOGW("Volume is idle but appears to be mounted - fixing");
        setState(Volume::State_Mounted);
        // mCurrentlyMountedKdev = XXX
        return 0;
    }

    n = getDeviceNodes((dev_t *) &deviceNodes, 4);
    if (!n) {
        LOGE("Failed to get device nodes (%s)\n", strerror(errno));
        return -1;
    }

    for (i = 0; i < n; i++) {
        char devicePath[255];

        sprintf(devicePath, "/dev/block/vold/%d:%d", MAJOR(deviceNodes[i]),
                MINOR(deviceNodes[i]));

        LOGI("%s being considered for volume %s\n", devicePath, getLabel());

        errno = 0;
        setState(Volume::State_Checking);

        if ((rc = Fat::check(devicePath))) {
            if (errno == ENODATA) {
                LOGW("%s does not contain a FAT filesystem\n", devicePath);
                continue;
            } else {
                /* Badness - abort the mount */
                LOGE("%s failed FS checks (%s)", devicePath, strerror(errno));
                snprintf(errmsg, sizeof(errmsg),
                         "Volume %s %s mount failed - filesystem check failed",
                         getLabel(), getMountpoint());
                mVm->getBroadcaster()->sendBroadcast(
                                         ResponseCode::VolumeMountFailedDamaged,
                                         errmsg, false);
                setState(Volume::State_Idle);
                goto out;
            }
        }

        LOGI("%s checks out - attempting to mount\n", devicePath);
        errno = 0;
        if (!(rc = Fat::doMount(devicePath, getMountpoint(), false, false,
                                1000, 1015, 0702, true))) {
            LOGI("%s sucessfully mounted for volume %s\n", devicePath,
                 getLabel());
            setState(Volume::State_Mounted);
            mCurrentlyMountedKdev = deviceNodes[i];
            goto out;
        }

        LOGW("%s failed to mount via VFAT (%s)\n", devicePath, strerror(errno));
    }

    // XXX: Doesn't handle multiple partitions properly
    if (errno == ENODATA) {
        snprintf(errmsg, sizeof(errmsg),
                 "Volume %s %s mount failed - no supported file-systems",
                 getLabel(), getMountpoint());
        mVm->getBroadcaster()->sendBroadcast(
                                 ResponseCode::VolumeMountFailedBlank,
                                 errmsg, false);
    }
   

    LOGE("Volume %s found no suitable devices for mounting :(\n", getLabel());
    setState(Volume::State_Idle);

out:
    return rc;
}

int Volume::unmountVol() {
    int i, rc;

    if (getState() != Volume::State_Mounted) {
        LOGE("Volume %s unmount request when not mounted", getLabel());
        errno = EINVAL;
        return -1;
    }

    setState(Volume::State_Unmounting);
    for (i = 0; i < 10; i++) {
        rc = umount(getMountpoint());
        if (!rc)
            break;

        if (rc && (errno == EINVAL || errno == ENOENT)) {
            rc = 0;
            break;
        }

        LOGW("Volume %s unmount attempt %d failed (%s)",
             getLabel(), i + 1, strerror(errno));

        if (i < 5) {
            usleep(1000 * 250);
        } else {
            KillProcessesWithOpenFiles(getMountpoint(),
                                       (i < 7 ? 0 : 1),
                                       NULL, 0);
            usleep(1000 * 250);
        }
    }

    if (!rc) {
        LOGI("Volume %s unmounted sucessfully", getLabel());
        setState(Volume::State_Idle);
        mCurrentlyMountedKdev = -1;
        return 0;
    }

    LOGE("Volume %s failed to unmount (%s)\n", getLabel(), strerror(errno));
    setState(Volume::State_Mounted);
    return -1;
}

int Volume::initializeMbr(const char *deviceNode) {
    int fd, rc;
    unsigned char block[512];
    struct dos_partition part;
    unsigned int nr_sec;

    if ((fd = open(deviceNode, O_RDWR)) < 0) {
        LOGE("Error opening disk file (%s)", strerror(errno));
        return -1;
    }

    if (ioctl(fd, BLKGETSIZE, &nr_sec)) {
        LOGE("Unable to get device size (%s)", strerror(errno));
        close(fd);
        return -1;
    }

    memset(&part, 0, sizeof(part));
    part.dp_flag = 0x80;
    part.dp_typ = 0xc;
    part.dp_start = ((1024 * 64) / 512) + 1;
    part.dp_size = nr_sec - part.dp_start;

    memset(block, 0, sizeof(block));
    block[0x1fe] = 0x55;
    block[0x1ff] = 0xaa;

    dos_partition_enc(block + DOSPARTOFF, &part);

    if (write(fd, block, sizeof(block)) < 0) {
        LOGE("Error writing MBR (%s)", strerror(errno));
        close(fd);
        return -1;
    }

    if (ioctl(fd, BLKRRPART, NULL) < 0) {
        LOGE("Error re-reading partition table (%s)", strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}
