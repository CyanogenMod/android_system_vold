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

#define LOG_TAG "Vold"

#include <cutils/log.h>
#include <sysutils/NetlinkEvent.h>

#include "DeviceVolume.h"

DeviceVolume::DeviceVolume(const char *label, const char *mount_point, int partIdx) :
              Volume(label, mount_point) {
    mPartIdx = partIdx;
  
    mPaths = new PathCollection();
}

DeviceVolume::~DeviceVolume() {
    PathCollection::iterator it;

    for (it = mPaths->begin(); it != mPaths->end(); ++it)
        free(*it);
    delete mPaths;
}

int DeviceVolume::addPath(const char *path) {
    mPaths->push_back(strdup(path));
    return 0;
}

int DeviceVolume::handleBlockEvent(NetlinkEvent *evt) {
    const char *dp = evt->findParam("DEVPATH");

    PathCollection::iterator  it;
    for (it = mPaths->begin(); it != mPaths->end(); ++it) {
        if (!strncmp(dp, *it, strlen(*it))) {
            /* We can handle this disk */
            int action = evt->getAction();
            const char *devtype = evt->findParam("DEVTYPE");

            if (!strcmp(devtype, "disk")) {
                if (action == NetlinkEvent::NlActionAdd)
                    handleDiskAdded(dp, evt);
                else if (action == NetlinkEvent::NlActionRemove)
                    handleDiskRemoved(dp, evt);
                else
                    LOGD("Ignoring non add/remove event");
            } else {
                if (action == NetlinkEvent::NlActionAdd)
                    handlePartitionAdded(dp, evt);
                else if (action == NetlinkEvent::NlActionRemove)
                    handlePartitionRemoved(dp, evt);
                else
                    LOGD("Ignoring non add/remove event");
            }

            return 0;
        }
    }
    errno = ENODEV;
    return -1;
}

void DeviceVolume::handleDiskAdded(const char *devpath, NetlinkEvent *evt) {
    mDiskMaj = atoi(evt->findParam("MAJOR"));
    mDiskNumParts = atoi(evt->findParam("NPARTS"));

    int partmask = 0;
    int i;
    for (i = 1; i <= mDiskNumParts; i++) {
        partmask |= (1 << i);
    }
    mPendingPartMap = partmask;

    if (mDiskNumParts == 0) {
        LOGD("Dv::diskIns - No partitions - good to go son!");
        setState(Volume::State_Idle);
    } else {
        LOGD("Dv::diskIns - waiting for %d partitions (mask 0x%x)",
             mDiskNumParts, mPendingPartMap);
        setState(Volume::State_Pending);
    }
}

void DeviceVolume::handlePartitionAdded(const char *devpath, NetlinkEvent *evt) {
    int major = atoi(evt->findParam("MAJOR"));
    int minor = atoi(evt->findParam("MINOR"));
    int part_num = atoi(evt->findParam("PARTN"));

    mPendingPartMap &= ~(1 << part_num);
    if (!mPendingPartMap) {
        LOGD("Dv:partAdd: Got all partitions - ready to rock!");
        setState(Volume::State_Idle);
    } else {
        LOGD("Dv:partAdd: pending mask now = 0x%x", mPendingPartMap);
    }
}

void DeviceVolume::handleDiskRemoved(const char *devpath, NetlinkEvent *evt) {
}

void DeviceVolume::handlePartitionRemoved(const char *devpath, NetlinkEvent *evt) {
}
