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
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>

#include <linux/kdev_t.h>

#define LOG_TAG "Vold"

#include <cutils/log.h>

#include <sysutils/NetlinkEvent.h>

#include "VolumeManager.h"
#include "DirectVolume.h"
#include "ResponseCode.h"
#include "Loop.h"
#include "Fat.h"

VolumeManager *VolumeManager::sInstance = NULL;

VolumeManager *VolumeManager::Instance() {
    if (!sInstance)
        sInstance = new VolumeManager();
    return sInstance;
}

VolumeManager::VolumeManager() {
    mBlockDevices = new BlockDeviceCollection();
    mVolumes = new VolumeCollection();
    mBroadcaster = NULL;
    mUsbMassStorageConnected = false;
}

VolumeManager::~VolumeManager() {
    delete mBlockDevices;
}

int VolumeManager::start() {
    return 0;
}

int VolumeManager::stop() {
    return 0;
}

int VolumeManager::addVolume(Volume *v) {
    mVolumes->push_back(v);
    return 0;
}

void VolumeManager::notifyUmsConnected(bool connected) {
    char msg[255];

    if (connected) {
        mUsbMassStorageConnected = true;
    } else {
        mUsbMassStorageConnected = false;
    }
    snprintf(msg, sizeof(msg), "Share method ums now %s",
             (connected ? "available" : "unavailable"));

    getBroadcaster()->sendBroadcast(ResponseCode::ShareAvailabilityChange,
                                    msg, false);
}

void VolumeManager::handleSwitchEvent(NetlinkEvent *evt) {
    const char *devpath = evt->findParam("DEVPATH");
    const char *name = evt->findParam("SWITCH_NAME");
    const char *state = evt->findParam("SWITCH_STATE");

    if (!name || !state) {
        LOGW("Switch %s event missing name/state info", devpath);
        return;
    }

    if (!strcmp(name, "usb_mass_storage")) {

        if (!strcmp(state, "online"))  {
            notifyUmsConnected(true);
        } else {
            notifyUmsConnected(false);
        }
    } else {
        LOGW("Ignoring unknown switch '%s'", name);
    }
}

void VolumeManager::handleBlockEvent(NetlinkEvent *evt) {
    const char *devpath = evt->findParam("DEVPATH");

    /* Lookup a volume to handle this device */
    VolumeCollection::iterator it;
    bool hit = false;
    for (it = mVolumes->begin(); it != mVolumes->end(); ++it) {
        if (!(*it)->handleBlockEvent(evt)) {
#ifdef NETLINK_DEBUG
            LOGD("Device '%s' event handled by volume %s\n", devpath, (*it)->getLabel());
#endif
            hit = true;
            break;
        }
    }

    if (!hit) {
#ifdef NETLINK_DEBUG
        LOGW("No volumes handled block event for '%s'", devpath);
#endif
    }
}

int VolumeManager::listVolumes(SocketClient *cli) {
    VolumeCollection::iterator i;

    for (i = mVolumes->begin(); i != mVolumes->end(); ++i) {
        char *buffer;
        asprintf(&buffer, "%s %s %d",
                 (*i)->getLabel(), (*i)->getMountpoint(),
                 (*i)->getState());
        cli->sendMsg(ResponseCode::VolumeListResult, buffer, false);
        free(buffer);
    }
    cli->sendMsg(ResponseCode::CommandOkay, "Volumes listed.", false);
    return 0;
}

int VolumeManager::formatVolume(const char *label) {
    Volume *v = lookupVolume(label);

    if (!v) {
        errno = ENOENT;
        return -1;
    }

    return v->formatVol();
}

int VolumeManager::getAsecMountPath(const char *id, char *buffer, int maxlen) {
    char mountPoint[255];

    snprintf(mountPoint, sizeof(mountPoint), "/asec/%s", id);

    if (!isMountpointMounted(mountPoint)) {
        errno = ENOENT;
        return -1;
    } 
    snprintf(buffer, maxlen, "/asec/%s", id);
    return 0;
}

int VolumeManager::createAsec(const char *id, int sizeMb,
                              const char *fstype, const char *key, int ownerUid) {

    mkdir("/sdcard/android_secure", 0777);

    if (lookupVolume(id)) {
        LOGE("ASEC volume '%s' currently exists", id);
        errno = EADDRINUSE;
        return -1;
    }

    char asecFileName[255];
    snprintf(asecFileName, sizeof(asecFileName),
             "/sdcard/android_secure/%s.asec", id);

    if (!access(asecFileName, F_OK)) {
        LOGE("ASEC file '%s' currently exists - destroy it first! (%s)",
             asecFileName, strerror(errno));
        errno = EADDRINUSE;
        return -1;
    }

    if (Loop::createImageFile(asecFileName, sizeMb)) {
        LOGE("ASEC image file creation failed (%s)", strerror(errno));
        return -1;
    }

    char loopDevice[255];
    if (Loop::getNextAvailable(loopDevice, sizeof(loopDevice))) {
        unlink(asecFileName);
        return -1;
    }

    if (Loop::create(loopDevice, asecFileName)) {
        LOGE("ASEC loop device creation failed (%s)", strerror(errno));
        unlink(asecFileName);
        return -1;
    }

    /* XXX: Start devmapper */

    if (Fat::format(loopDevice)) {
        LOGE("ASEC FAT format failed (%s)", strerror(errno));
        Loop::destroyByDevice(loopDevice);
        unlink(asecFileName);
        return -1;
    }

    char mountPoint[255];

    snprintf(mountPoint, sizeof(mountPoint), "/asec/%s", id);
    if (mkdir(mountPoint, 0777)) {
        LOGE("Mountpoint creation failed (%s)", strerror(errno));
        Loop::destroyByDevice(loopDevice);
        unlink(asecFileName);
        return -1;
    }

    if (Fat::doMount(loopDevice, mountPoint, false, false)) {
        LOGE("ASEC FAT mount failed (%s)", strerror(errno));
        Loop::destroyByDevice(loopDevice);
        unlink(asecFileName);
        return -1;
    }
    
    return 0;
}

int VolumeManager::finalizeAsec(const char *id) {
    char asecFileName[255];
    char loopDevice[255];
    char mountPoint[255];

    snprintf(asecFileName, sizeof(asecFileName),
             "/sdcard/android_secure/%s.asec", id);

    if (Loop::lookupActive(asecFileName, loopDevice, sizeof(loopDevice))) {
        LOGE("Unable to finalize %s (%s)", id, strerror(errno));
        return -1;
    }

    snprintf(mountPoint, sizeof(mountPoint), "/asec/%s", id);
    if (Fat::doMount(loopDevice, mountPoint, true, true)) {
        LOGE("ASEC finalize mount failed (%s)", strerror(errno));
        return -1;
    }

    LOGD("ASEC %s finalized", id);
    return 0;
}

int VolumeManager::destroyAsec(const char *id) {
    char asecFileName[255];
    char mountPoint[255];

    snprintf(asecFileName, sizeof(asecFileName),
             "/sdcard/android_secure/%s.asec", id);
    snprintf(mountPoint, sizeof(mountPoint), "/asec/%s", id);

    if (isMountpointMounted(mountPoint)) {
        int i, rc;
        for (i = 0; i < 10; i++) {
            rc = umount(mountPoint);
            if (!rc) {
                break;
            }
            if (rc && (errno == EINVAL || errno == ENOENT)) {
                rc = 0;
                break;
            }
            LOGW("ASEC %s unmount attempt %d failed (%s)",
                  id, i +1, strerror(errno));
            usleep(1000 * 250);
        }
        if (rc) {
            LOGE("Failed to unmount ASEC %s for destroy", id);
            return -1;
        }
    }

    char loopDevice[255];
    if (!Loop::lookupActive(asecFileName, loopDevice, sizeof(loopDevice))) {
        Loop::destroyByDevice(loopDevice);
    }

    unlink(asecFileName);

    LOGD("ASEC %s destroyed", id);
    return 0;
}

int VolumeManager::mountAsec(const char *id, const char *key, int ownerUid) {
    char asecFileName[255];
    char mountPoint[255];

    snprintf(asecFileName, sizeof(asecFileName),
             "/sdcard/android_secure/%s.asec", id);
    snprintf(mountPoint, sizeof(mountPoint), "/asec/%s", id);

    if (isMountpointMounted(mountPoint)) {
        LOGE("ASEC %s already mounted", id);
        errno = EBUSY;
        return -1;
    }

    char loopDevice[255];
    if (Loop::lookupActive(asecFileName, loopDevice, sizeof(loopDevice))) {
        if (Loop::getNextAvailable(loopDevice, sizeof(loopDevice))) {
            LOGE("Unable to find loop device for ASEC mount");
            return -1;
        }

        if (Loop::create(loopDevice, asecFileName)) {
            LOGE("ASEC loop device creation failed (%s)", strerror(errno));
            return -1;
        }
    }

    if (mkdir(mountPoint, 0777)) {
        LOGE("Mountpoint creation failed (%s)", strerror(errno));
        return -1;
    }

    if (Fat::doMount(loopDevice, mountPoint, true, false)) {
        LOGE("ASEC mount failed (%s)", strerror(errno));
        return -1;
    }

    LOGD("ASEC %s mounted", id);
    return 0;
}

int VolumeManager::mountVolume(const char *label) {
    Volume *v = lookupVolume(label);

    if (!v) {
        errno = ENOENT;
        return -1;
    }

    return v->mountVol();
}

int VolumeManager::shareAvailable(const char *method, bool *avail) {

    if (strcmp(method, "ums")) {
        errno = ENOSYS;
        return -1;
    }

    if (mUsbMassStorageConnected)
        *avail = true;
    else
        *avail = false;
    return 0;
}

int VolumeManager::simulate(const char *cmd, const char *arg) {

    if (!strcmp(cmd, "ums")) {
        if (!strcmp(arg, "connect")) {
            notifyUmsConnected(true);
        } else if (!strcmp(arg, "disconnect")) {
            notifyUmsConnected(false);
        } else {
            errno = EINVAL;
            return -1;
        }
    } else {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

int VolumeManager::shareVolume(const char *label, const char *method) {
    Volume *v = lookupVolume(label);

    if (!v) {
        errno = ENOENT;
        return -1;
    }

    /*
     * Eventually, we'll want to support additional share back-ends,
     * some of which may work while the media is mounted. For now,
     * we just support UMS
     */
    if (strcmp(method, "ums")) {
        errno = ENOSYS;
        return -1;
    }

    if (v->getState() == Volume::State_NoMedia) {
        errno = ENODEV;
        return -1;
    }

    if (v->getState() != Volume::State_Idle) {
        // You need to unmount manually befoe sharing
        errno = EBUSY;
        return -1;
    }

    dev_t d = v->getDiskDevice();
    if ((MAJOR(d) == 0) && (MINOR(d) == 0)) {
        // This volume does not support raw disk access
        errno = EINVAL;
        return -1;
    }

    int fd;
    char nodepath[255];
    snprintf(nodepath,
             sizeof(nodepath), "/dev/block/vold/%d:%d",
             MAJOR(d), MINOR(d));

    if ((fd = open("/sys/devices/platform/usb_mass_storage/lun0/file",
                   O_WRONLY)) < 0) {
        LOGE("Unable to open ums lunfile (%s)", strerror(errno));
        return -1;
    }

    if (write(fd, nodepath, strlen(nodepath)) < 0) {
        LOGE("Unable to write to ums lunfile (%s)", strerror(errno));
        close(fd);
        return -1;
    }

    close(fd);
    v->handleVolumeShared();
    return 0;
}

int VolumeManager::unshareVolume(const char *label, const char *method) {
    Volume *v = lookupVolume(label);

    if (!v) {
        errno = ENOENT;
        return -1;
    }

    if (strcmp(method, "ums")) {
        errno = ENOSYS;
        return -1;
    }

    if (v->getState() != Volume::State_Shared) {
        errno = EINVAL;
        return -1;
    }

    dev_t d = v->getDiskDevice();

    int fd;
    char nodepath[255];
    snprintf(nodepath,
             sizeof(nodepath), "/dev/block/vold/%d:%d",
             MAJOR(d), MINOR(d));

    if ((fd = open("/sys/devices/platform/usb_mass_storage/lun0/file", O_WRONLY)) < 0) {
        LOGE("Unable to open ums lunfile (%s)", strerror(errno));
        return -1;
    }

    char ch = 0;
    if (write(fd, &ch, 1) < 0) {
        LOGE("Unable to write to ums lunfile (%s)", strerror(errno));
        close(fd);
        return -1;
    }

    close(fd);
    v->handleVolumeUnshared();
    return 0;
}

int VolumeManager::unmountVolume(const char *label) {
    Volume *v = lookupVolume(label);

    if (!v) {
        errno = ENOENT;
        return -1;
    }

    if (v->getState() == Volume::State_NoMedia) {
        errno = ENODEV;
        return -1;
    }

    if (v->getState() != Volume::State_Mounted) {
        LOGW("Attempt to unmount volume which isn't mounted (%d)\n",
             v->getState());
        errno = EBUSY;
        return -1;
    }

    return v->unmountVol();
}

/*
 * Looks up a volume by it's label or mount-point
 */
Volume *VolumeManager::lookupVolume(const char *label) {
    VolumeCollection::iterator i;

    for (i = mVolumes->begin(); i != mVolumes->end(); ++i) {
        if (label[0] == '/') {
            if (!strcmp(label, (*i)->getMountpoint()))
                return (*i);
        } else {
            if (!strcmp(label, (*i)->getLabel()))
                return (*i);
        }
    }
    return NULL;
}

bool VolumeManager::isMountpointMounted(const char *mp)
{
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
        if (!strcmp(mount_path, mp)) {
            fclose(fp);
            return true;
        }

    }

    fclose(fp);
    return false;
}

