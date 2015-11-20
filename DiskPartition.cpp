/*
 * Copyright (C) 2015 Cyanogen, Inc.
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

#include "DiskPartition.h"
#include "PublicVolume.h"
#include "PrivateVolume.h"
#include "Utils.h"
#include "VolumeBase.h"
#include "VolumeManager.h"
#include "ResponseCode.h"

#include <base/file.h>
#include <base/stringprintf.h>
#include <base/logging.h>
#include <diskconfig/diskconfig.h>

#include <vector>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>

using android::base::ReadFileToString;
using android::base::WriteStringToFile;
using android::base::StringPrintf;

namespace android {
namespace vold {

DiskPartition::DiskPartition(const std::string& eventPath, dev_t device,
            const std::string& nickname, int flags, int partnum) :
        Disk(eventPath, device, nickname, flags),
        mPartNum(partnum) {
    // Override disk ID so that we don't reference our unpublished disk
    // in the VolumeCreated message.
    mId = "";
}

DiskPartition::~DiskPartition() {
}

status_t DiskPartition::create() {
    CHECK(!mCreated);
    mCreated = true;
    dev_t partDevice = makedev(major(mDevice), minor(mDevice) + mPartNum);
    createPublicVolume(partDevice);
    return OK;
}

status_t DiskPartition::destroy() {
    CHECK(mCreated);
    destroyAllVolumes();
    mCreated = false;
    return OK;
}

}  // namespace vold
}  // namespace android
