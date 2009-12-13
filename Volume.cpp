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

extern "C" int logwrap(int argc, const char **argv, int background);
extern "C" int mount(const char *, const char *, const char *, unsigned long, const void *);
extern "C" void KillProcessesWithOpenFiles(const char *, int, int, int);
extern "C" void dos_partition_dec(void const *pp, struct dos_partition *d);
extern "C" void dos_partition_enc(void *pp, struct dos_partition *d);

static char FSCK_MSDOS_PATH[] = "/system/bin/fsck_msdos";
static char MKDOSFS_PATH[] = "/system/bin/newfs_msdos";

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

    if (doFormatVfat(devicePath)) {
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
        if ((rc = checkFilesystem(devicePath))) {
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
        if (!(rc = doMountVfat(devicePath, getMountpoint()))) {
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


int Volume::doMountVfat(const char *deviceNode, const char *mountPoint)
{
    int rc;
    unsigned long flags;

    flags = MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_DIRSYNC;

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
        rc = mount(deviceNode, mountPoint, (const char *) "vfat", (unsigned long) flags,
                (const void *) "utf8,uid=1000,gid=1015,fmask=000,dmask=000,shortname=mixed");
    } else {
        /*
         * The mount masks restrict access so that:
         * 1. The 'system' user cannot access the SD card at all -
         *    (protects system_server from grabbing file references)
         * 2. Group users can RWX
         * 3. Others can only RX
         */
        rc = mount(deviceNode, mountPoint, "vfat", flags,
                "utf8,uid=1000,gid=1015,fmask=702,dmask=702,shortname=mixed");
    }

    if (rc && errno == EROFS) {
        LOGE("%s appears to be a read only filesystem - retrying mount RO",
             deviceNode);
        flags |= MS_RDONLY;
        rc = mount(deviceNode, mountPoint, "vfat", flags,
                   "utf8,uid=1000,gid=1015,fmask=702,dmask=702,shortname=mixed");
    }

    if (rc == 0) {
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

int Volume::doFormatVfat(const char *deviceNode) {
    unsigned int nr_sec;
    int fd;

    if ((fd = open(deviceNode, O_RDWR)) < 0) {
        LOGE("Error opening disk file (%s)", strerror(errno));
        return -1;
    }

    if (ioctl(fd, BLKGETSIZE, &nr_sec)) {
        LOGE("Unable to get device size (%s)", strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);

    const char *args[7];
    int rc;
    args[0] = MKDOSFS_PATH;
    args[1] = "-F";
    if ((nr_sec * 512) <= ((unsigned int) (1024*1024*1024) * 2)) 
            args[2] = "16";
    else
            args[2] = "32";

    args[3] = "-O";
    args[4] = "android";
    args[5] = deviceNode;
    args[6] = NULL;
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
