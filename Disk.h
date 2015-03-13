/*
 * Copyright (C) 2015 The Android Open Source Project
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

#ifndef ANDROID_VOLD_DISK_H
#define ANDROID_VOLD_DISK_H

#include "Utils.h"

#include <utils/Errors.h>

#include <vector>

namespace android {
namespace vold {

class VolumeBase;

// events:
// disk_created 127:4
// disk_meta 127:4 [size] [label]
// disk_destroyed 127:4

// commands:
// disk partition_public 127:4
// disk partition_private 127:4
// disk partition_mixed 127:4 50

/*
 * Representation of detected physical media.
 *
 * Knows how to create volumes based on the partition tables found, and also
 * how to repartition itself.
 */
class Disk {
public:
    Disk(const std::string& eventPath, dev_t device);
    virtual ~Disk();

    const std::string& getId() { return mId; }
    const std::string& getSysPath() { return mSysPath; }
    const std::string& getDevPath() { return mDevPath; }
    dev_t getDevice() { return mDevice; }
    uint64_t getSize() { return mSize; }
    const std::string& getLabel() { return mLabel; }

    std::shared_ptr<VolumeBase> findVolume(const std::string& id);

    status_t readMetadata();
    status_t readPartitions();

    status_t partitionPublic();
    status_t partitionPrivate();
    status_t partitionMixed(int8_t ratio);

private:
    /* ID that uniquely references this disk */
    std::string mId;
    /* Device path under sysfs */
    std::string mSysPath;
    /* Device path under dev */
    std::string mDevPath;
    /* Kernel device representing disk */
    dev_t mDevice;
    /* Size of disk, in bytes */
    uint64_t mSize;
    /* User-visible label, such as manufacturer */
    std::string mLabel;
    /* Current partitions on disk */
    std::vector<std::shared_ptr<VolumeBase>> mParts;

    int getMaxMinors();

    DISALLOW_COPY_AND_ASSIGN(Disk);
};

}  // namespace vold
}  // namespace android

#endif
