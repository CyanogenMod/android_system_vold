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
#include "Devmapper.h"

extern "C" void KillProcessesWithOpenFiles(const char *, int, int, int);

VolumeManager *VolumeManager::sInstance = NULL;

VolumeManager *VolumeManager::Instance() {
    if (!sInstance)
        sInstance = new VolumeManager();
    return sInstance;
}

VolumeManager::VolumeManager() {
    mBlockDevices = new BlockDeviceCollection();
    mVolumes = new VolumeCollection();
    mActiveContainers = new AsecIdCollection();
    mBroadcaster = NULL;
    mUsbMassStorageConnected = false;
}

VolumeManager::~VolumeManager() {
    delete mBlockDevices;
    delete mVolumes;
    delete mActiveContainers;
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
    snprintf(buffer, maxlen, "/asec/%s", id);
    return 0;
}

int VolumeManager::createAsec(const char *id, unsigned int numSectors,
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

    if (Loop::createImageFile(asecFileName, numSectors)) {
        LOGE("ASEC image file creation failed (%s)", strerror(errno));
        return -1;
    }

    char loopDevice[255];
    if (Loop::create(asecFileName, loopDevice, sizeof(loopDevice))) {
        LOGE("ASEC loop device creation failed (%s)", strerror(errno));
        unlink(asecFileName);
        return -1;
    }

    char dmDevice[255];
    bool cleanupDm = false;

    if (strcmp(key, "none")) {
        if (Devmapper::create(id, loopDevice, key, numSectors, dmDevice,
                             sizeof(dmDevice))) {
            LOGE("ASEC device mapping failed (%s)", strerror(errno));
            Loop::destroyByDevice(loopDevice);
            unlink(asecFileName);
            return -1;
        }
        cleanupDm = true;
    } else {
        strcpy(dmDevice, loopDevice);
    }

    if (Fat::format(dmDevice)) {
        LOGE("ASEC FAT format failed (%s)", strerror(errno));
        if (cleanupDm) {
            Devmapper::destroy(id);
        }
        Loop::destroyByDevice(loopDevice);
        unlink(asecFileName);
        return -1;
    }

    char mountPoint[255];

    snprintf(mountPoint, sizeof(mountPoint), "/asec/%s", id);
    if (mkdir(mountPoint, 0777)) {
        if (errno != EEXIST) {
            LOGE("Mountpoint creation failed (%s)", strerror(errno));
            if (cleanupDm) {
                Devmapper::destroy(id);
            }
            Loop::destroyByDevice(loopDevice);
            unlink(asecFileName);
            return -1;
        }
    }

    if (Fat::doMount(dmDevice, mountPoint, false, false, ownerUid,
                     0, 0000, false)) {
//                     0, 0007, false)) {
        LOGE("ASEC FAT mount failed (%s)", strerror(errno));
        if (cleanupDm) {
            Devmapper::destroy(id);
        }
        Loop::destroyByDevice(loopDevice);
        unlink(asecFileName);
        return -1;
    }

    mActiveContainers->push_back(strdup(id));
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
    // XXX:
    if (Fat::doMount(loopDevice, mountPoint, true, true, 0, 0, 0227, false)) {
        LOGE("ASEC finalize mount failed (%s)", strerror(errno));
        return -1;
    }

    LOGD("ASEC %s finalized", id);
    return 0;
}

int VolumeManager::unmountAsec(const char *id) {
    char asecFileName[255];
    char mountPoint[255];

    snprintf(asecFileName, sizeof(asecFileName),
             "/sdcard/android_secure/%s.asec", id);
    snprintf(mountPoint, sizeof(mountPoint), "/asec/%s", id);

    if (!isMountpointMounted(mountPoint)) {
        LOGE("Unmount request for ASEC %s when not mounted", id);
        errno = EINVAL;
        return -1;
    }

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

        if (i >= 5) {
            KillProcessesWithOpenFiles(mountPoint, (i < 7 ? 0 : 1),
                                       NULL, 0);
        }
        usleep(1000 * 250);
    }

    if (rc) {
        LOGE("Failed to unmount ASEC %s", id);
        return -1;
    }

    unlink(mountPoint);

    if (Devmapper::destroy(id) && errno != ENXIO) {
        LOGE("Failed to destroy devmapper instance (%s)", strerror(errno));
    }

    char loopDevice[255];
    if (!Loop::lookupActive(asecFileName, loopDevice, sizeof(loopDevice))) {
        Loop::destroyByDevice(loopDevice);
    }

    AsecIdCollection::iterator it;
    for (it = mActiveContainers->begin(); it != mActiveContainers->end(); ++it) {
        if (!strcmp(*it, id)) {
            free(*it);
            mActiveContainers->erase(it);
            break;
        }
    }
    if (it == mActiveContainers->end()) {
        LOGW("mActiveContainers is inconsistent!");
    }
    return 0;
}

int VolumeManager::destroyAsec(const char *id) {
    char asecFileName[255];
    char mountPoint[255];

    snprintf(asecFileName, sizeof(asecFileName),
             "/sdcard/android_secure/%s.asec", id);
    snprintf(mountPoint, sizeof(mountPoint), "/asec/%s", id);

    if (isMountpointMounted(mountPoint)) {
        LOGD("Unmounting container before destroy");
        if (unmountAsec(id)) {
            LOGE("Failed to unmount asec %s for destroy (%s)", id, strerror(errno));
            return -1;
        }
    }

    if (unlink(asecFileName)) {
        LOGE("Failed to unlink asec '%s' (%s)", asecFileName, strerror(errno));
        return -1;
    }

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
        if (Loop::create(asecFileName, loopDevice, sizeof(loopDevice))) {
            LOGE("ASEC loop device creation failed (%s)", strerror(errno));
            return -1;
        }
        LOGD("New loop device created at %s", loopDevice);
    } else {
        LOGD("Found active loopback for %s at %s", asecFileName, loopDevice);
    }

    char dmDevice[255];
    bool cleanupDm = false;
    if (strcmp(key, "none")) {
        if (Devmapper::lookupActive(id, dmDevice, sizeof(dmDevice))) {
            unsigned int nr_sec = 0;
            int fd;

            if ((fd = open(loopDevice, O_RDWR)) < 0) {
                LOGE("Failed to open loopdevice (%s)", strerror(errno));
                Loop::destroyByDevice(loopDevice);
                return -1;
            }

            if (ioctl(fd, BLKGETSIZE, &nr_sec)) {
                LOGE("Failed to get loop size (%s)", strerror(errno));
                Loop::destroyByDevice(loopDevice);
                close(fd);
                return -1;
            }
            close(fd);
            if (Devmapper::create(id, loopDevice, key, nr_sec,
                                  dmDevice, sizeof(dmDevice))) {
                LOGE("ASEC device mapping failed (%s)", strerror(errno));
                Loop::destroyByDevice(loopDevice);
                return -1;
            }
            LOGD("New devmapper instance created at %s", dmDevice);
        } else {
            LOGD("Found active devmapper for %s at %s", asecFileName, dmDevice);
        }
        cleanupDm = true;
    } else {
        strcpy(dmDevice, loopDevice);
    }

    if (mkdir(mountPoint, 0777)) {
        if (errno != EEXIST) {
            LOGE("Mountpoint creation failed (%s)", strerror(errno));
            if (cleanupDm) {
                Devmapper::destroy(id);
            }
            Loop::destroyByDevice(loopDevice);
            return -1;
        }
    }

    if (Fat::doMount(dmDevice, mountPoint, true, false, ownerUid, 0,
                     0222, false)) {
//                     0227, false)) {
        LOGE("ASEC mount failed (%s)", strerror(errno));
        if (cleanupDm) {
            Devmapper::destroy(id);
        }
        Loop::destroyByDevice(loopDevice);
        return -1;
    }

    mActiveContainers->push_back(strdup(id));
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

    while(mActiveContainers->size()) {
        AsecIdCollection::iterator it = mActiveContainers->begin();
        LOGI("Unmounting ASEC %s (dependant on %s)", *it, v->getMountpoint());
        if (unmountAsec(*it)) {
            LOGE("Failed to unmount ASEC %s (%s) - unmount of %s may fail!", *it,
                 strerror(errno), v->getMountpoint());
        }
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

