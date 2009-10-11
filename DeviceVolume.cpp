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
#include <errno.h>
#include <string.h>

#define LOG_TAG "Vold"

#include <cutils/log.h>

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

int DeviceVolume::handleDiskInsertion(const char *dp, int maj, int min,
                                      int nr_parts) {
    PathCollection::iterator  it;

    LOGD("Dv::diskInsertion - %s %d %d %d", dp, maj, min, nr_parts);
    for (it = mPaths->begin(); it != mPaths->end(); ++it) {
        LOGD("Dv::chk %s", *it);
        if (!strncmp(dp, *it, strlen(*it))) {
            /*
             * We can handle this disk. If there are no partitions then we're 
             * good to go son!
             */
            mDiskMaj = maj;
            mDiskNumParts = nr_parts;
            if (nr_parts == 0) {
                LOGD("Dv::diskIns - No partitions - good to go");
                setState(Volume::State_Idle);
            } else {
                LOGD("Dv::diskIns - waiting for %d partitions", nr_parts);
                setState(Volume::State_Pending);
            }
            return 0;
        }
    }
    errno = ENODEV;
    return -1;
}
