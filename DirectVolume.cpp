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

#include "DirectVolume.h"

DirectVolume::DirectVolume(const char *label, const char *mount_point, int partIdx) :
              Volume(label, mount_point) {
    mPartIdx = partIdx;
  
    mPaths = new PathCollection();
    for (int i = 0; i < MAX_PARTITIONS; i++)
        mPartMinors[i] = -1;
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

int DirectVolume::handleBlockEvent(NetlinkEvent *evt) {
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

void DirectVolume::handleDiskAdded(const char *devpath, NetlinkEvent *evt) {
    mDiskMajor = atoi(evt->findParam("MAJOR"));
    mDiskMinor = atoi(evt->findParam("MAJOR"));
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

void DirectVolume::handlePartitionAdded(const char *devpath, NetlinkEvent *evt) {
    int major = atoi(evt->findParam("MAJOR"));
    int minor = atoi(evt->findParam("MINOR"));
    int part_num = atoi(evt->findParam("PARTN"));

    if (major != mDiskMajor) {
        LOGE("Partition '%s' has a different major than its disk!", devpath);
        return;
    }
    mPartMinors[part_num -1] = minor;

    mPendingPartMap &= ~(1 << part_num);
    if (!mPendingPartMap) {
        LOGD("Dv:partAdd: Got all partitions - ready to rock!");
        setState(Volume::State_Idle);
    } else {
        LOGD("Dv:partAdd: pending mask now = 0x%x", mPendingPartMap);
    }
}

void DirectVolume::handleDiskRemoved(const char *devpath, NetlinkEvent *evt) {
}

void DirectVolume::handlePartitionRemoved(const char *devpath, NetlinkEvent *evt) {
}

/*
 * Called from Volume to determine the major/minor numbers
 * to be used for mounting
 */
int DirectVolume::prepareToMount(int *major, int *minor) {
    *major = mDiskMajor;

    if (mPartIdx == -1) {
        /* No specific partition specified */

        if (!mDiskNumParts) {
            *minor = mDiskMinor;
            return 0;
        }

        /* 
         * XXX: Use first partition for now.
         * The right thing to do would be to choose
         * this based on the partition type.
         *
         */
  
        *minor = mPartMinors[0];
        return 0;
    }

    if (mPartIdx - 1 > mDiskNumParts) {
        errno = EINVAL;
        return -1;
    }

    *minor = mPartMinors[mPartIdx-1];
    return 0;
}
