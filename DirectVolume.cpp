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

#include <linux/kdev_t.h>

#define LOG_TAG "DirectVolume"

#include <cutils/log.h>
#include <sysutils/NetlinkEvent.h>

#include "DirectVolume.h"
#include "VolumeManager.h"
#include "ResponseCode.h"

// #define PARTITION_DEBUG

DirectVolume::DirectVolume(VolumeManager *vm, const char *label,
                           const char *mount_point, int partIdx) :
              Volume(vm, label, mount_point) {
    mPartIdx = partIdx;

    mPaths = new PathCollection();
    for (int i = 0; i < MAX_PARTITIONS; i++)
        mPartMinors[i] = -1;
    mPendingPartMap = 0;
    mDiskMajor = -1;
    mDiskMinor = -1;
    mDiskNumParts = 0;

    setState(Volume::State_NoMedia);
}

DirectVolume::~DirectVolume() {
    PathCollection::iterator it;

    for (it = mPaths->begin(); it != mPaths->end(); ++it)
        free(*it);
    delete mPaths;
}

int DirectVolume::addPath(const char *path) {
    mPaths->push_back(strdup(path));
    return 0;
}

dev_t DirectVolume::getDiskDevice() {
    return MKDEV(mDiskMajor, mDiskMinor);
}

void DirectVolume::handleVolumeShared() {
    setState(Volume::State_Shared);
}

void DirectVolume::handleVolumeUnshared() {
    setState(Volume::State_Idle);
}

int DirectVolume::handleBlockEvent(NetlinkEvent *evt) {
    const char *dp = evt->findParam("DEVPATH");

    PathCollection::iterator  it;
    for (it = mPaths->begin(); it != mPaths->end(); ++it) {
        if (!strncmp(dp, *it, strlen(*it))) {
            /* We can handle this disk */
            int action = evt->getAction();
            const char *devtype = evt->findParam("DEVTYPE");

            if (action == NetlinkEvent::NlActionAdd) {
                int major = atoi(evt->findParam("MAJOR"));
                int minor = atoi(evt->findParam("MINOR"));
                char nodepath[255];

                snprintf(nodepath,
                         sizeof(nodepath), "/dev/block/vold/%d:%d",
                         major, minor);
                if (createDeviceNode(nodepath, major, minor)) {
                    SLOGE("Error making device node '%s' (%s)", nodepath,
                                                               strerror(errno));
                }
                if (!strcmp(devtype, "disk")) {
                    handleDiskAdded(dp, evt);
                } else {
                    handlePartitionAdded(dp, evt);
                }
            } else if (action == NetlinkEvent::NlActionRemove) {
                if (!strcmp(devtype, "disk")) {
                    handleDiskRemoved(dp, evt);
                } else {
                    handlePartitionRemoved(dp, evt);
                }
            } else if (action == NetlinkEvent::NlActionChange) {
                if (!strcmp(devtype, "disk")) {
                    handleDiskChanged(dp, evt);
                } else {
                    handlePartitionChanged(dp, evt);
                }
            } else {
                    SLOGW("Ignoring non add/remove/change event");
            }

            return 0;
        }
    }
    errno = ENODEV;
    return -1;
}

void DirectVolume::handleDiskAdded(const char *devpath, NetlinkEvent *evt) {
    mDiskMajor = atoi(evt->findParam("MAJOR"));
    mDiskMinor = atoi(evt->findParam("MINOR"));

    const char *tmp = evt->findParam("NPARTS");
    if (tmp) {
        mDiskNumParts = atoi(tmp);
    } else {
        SLOGW("Kernel block uevent missing 'NPARTS'");
        mDiskNumParts = 1;
    }

    char msg[255];

    int partmask = 0;
    int i;
    for (i = 1; i <= mDiskNumParts; i++) {
        partmask |= (1 << i);
    }
    mPendingPartMap = partmask;

    if (mDiskNumParts == 0) {
#ifdef PARTITION_DEBUG
        SLOGD("Dv::diskIns - No partitions - good to go son!");
#endif
        setState(Volume::State_Idle);
    } else {
#ifdef PARTITION_DEBUG
        SLOGD("Dv::diskIns - waiting for %d partitions (mask 0x%x)",
             mDiskNumParts, mPendingPartMap);
#endif
        setState(Volume::State_Pending);
    }

    snprintf(msg, sizeof(msg), "Volume %s %s disk inserted (%d:%d)",
             getLabel(), getMountpoint(), mDiskMajor, mDiskMinor);
    mVm->getBroadcaster()->sendBroadcast(ResponseCode::VolumeDiskInserted,
                                             msg, false);
}

void DirectVolume::handlePartitionAdded(const char *devpath, NetlinkEvent *evt) {
    int major = atoi(evt->findParam("MAJOR"));
    int minor = atoi(evt->findParam("MINOR"));

    int part_num;

    const char *tmp = evt->findParam("PARTN");

    if (tmp) {
        part_num = atoi(tmp);
    } else {
        SLOGW("Kernel block uevent missing 'PARTN'");
        part_num = 1;
    }

    if (part_num > mDiskNumParts) {
        mDiskNumParts = part_num;
    }

    if (major != mDiskMajor) {
        SLOGE("Partition '%s' has a different major than its disk!", devpath);
        return;
    }
#ifdef PARTITION_DEBUG
    SLOGD("Dv:partAdd: part_num = %d, minor = %d\n", part_num, minor);
#endif
    mPartMinors[part_num -1] = minor;

    mPendingPartMap &= ~(1 << part_num);
    if (!mPendingPartMap) {
#ifdef PARTITION_DEBUG
        SLOGD("Dv:partAdd: Got all partitions - ready to rock!");
#endif
        if (getState() != Volume::State_Formatting) {
            setState(Volume::State_Idle);
        }
    } else {
#ifdef PARTITION_DEBUG
        SLOGD("Dv:partAdd: pending mask now = 0x%x", mPendingPartMap);
#endif
    }
}

void DirectVolume::handleDiskChanged(const char *devpath, NetlinkEvent *evt) {
    int major = atoi(evt->findParam("MAJOR"));
    int minor = atoi(evt->findParam("MINOR"));

    if ((major != mDiskMajor) || (minor != mDiskMinor)) {
        return;
    }

    SLOGI("Volume %s disk has changed", getLabel());
    const char *tmp = evt->findParam("NPARTS");
    if (tmp) {
        mDiskNumParts = atoi(tmp);
    } else {
        SLOGW("Kernel block uevent missing 'NPARTS'");
        mDiskNumParts = 1;
    }

    int partmask = 0;
    int i;
    for (i = 1; i <= mDiskNumParts; i++) {
        partmask |= (1 << i);
    }
    mPendingPartMap = partmask;

    if (getState() != Volume::State_Formatting) {
        if (mDiskNumParts == 0) {
            setState(Volume::State_Idle);
        } else {
            setState(Volume::State_Pending);
        }
    }
}

void DirectVolume::handlePartitionChanged(const char *devpath, NetlinkEvent *evt) {
    int major = atoi(evt->findParam("MAJOR"));
    int minor = atoi(evt->findParam("MINOR"));
    SLOGD("Volume %s %s partition %d:%d changed\n", getLabel(), getMountpoint(), major, minor);
}

void DirectVolume::handleDiskRemoved(const char *devpath, NetlinkEvent *evt) {
    int major = atoi(evt->findParam("MAJOR"));
    int minor = atoi(evt->findParam("MINOR"));
    char msg[255];

    SLOGD("Volume %s %s disk %d:%d removed\n", getLabel(), getMountpoint(), major, minor);
    snprintf(msg, sizeof(msg), "Volume %s %s disk removed (%d:%d)",
             getLabel(), getMountpoint(), major, minor);
    mVm->getBroadcaster()->sendBroadcast(ResponseCode::VolumeDiskRemoved,
                                             msg, false);
    setState(Volume::State_NoMedia);
}

void DirectVolume::handlePartitionRemoved(const char *devpath, NetlinkEvent *evt) {
    int major = atoi(evt->findParam("MAJOR"));
    int minor = atoi(evt->findParam("MINOR"));
    char msg[255];

    SLOGD("Volume %s %s partition %d:%d removed\n", getLabel(), getMountpoint(), major, minor);

    /*
     * The framework doesn't need to get notified of
     * partition removal unless it's mounted. Otherwise
     * the removal notification will be sent on the Disk
     * itself
     */
    if (getState() != Volume::State_Mounted) {
        return;
    }
        
    if ((dev_t) MKDEV(major, minor) == mCurrentlyMountedKdev) {
        /*
         * Yikes, our mounted partition is going away!
         */

        snprintf(msg, sizeof(msg), "Volume %s %s bad removal (%d:%d)",
                 getLabel(), getMountpoint(), major, minor);
        mVm->getBroadcaster()->sendBroadcast(ResponseCode::VolumeBadRemoval,
                                             msg, false);

	if (mVm->cleanupAsec(this, true)) {
            SLOGE("Failed to cleanup ASEC - unmount will probably fail!");
        }

        if (Volume::unmountVol(true)) {
            SLOGE("Failed to unmount volume on bad removal (%s)", 
                 strerror(errno));
            // XXX: At this point we're screwed for now
        } else {
            SLOGD("Crisis averted");
        }
    }
}

/*
 * Called from base to get a list of devicenodes for mounting
 */
int DirectVolume::getDeviceNodes(dev_t *devs, int max) {

    if (mPartIdx == -1) {
        // If the disk has no partitions, try the disk itself
        if (!mDiskNumParts) {
            devs[0] = MKDEV(mDiskMajor, mDiskMinor);
            return 1;
        }

        int i;
        for (i = 0; i < mDiskNumParts; i++) {
            if (i == max)
                break;
            devs[i] = MKDEV(mDiskMajor, mPartMinors[i]);
        }
        return mDiskNumParts;
    }
    devs[0] = MKDEV(mDiskMajor, mPartMinors[mPartIdx -1]);
    return 1;
}
