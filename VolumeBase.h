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

#ifndef ANDROID_VOLD_VOLUME_BASE_H
#define ANDROID_VOLD_VOLUME_BASE_H

#include "Utils.h"

#include <utils/Errors.h>

#include <sys/types.h>
#include <list>
#include <string>

namespace android {
namespace vold {

enum class VolumeState {
    kUnmounted,
    kMounting,
    kMounted,
    kCorrupt,
    kFormatting,
    kUnmounting,
};

enum class VolumeType {
    kPublic,
    kPrivate,
    kEmulated,
    kAsec,
    kObb,
};

// events:
// volume_created private:127:4
// volume_state private:127:4 mounted
// volume_meta private:127:4 [fsGuid] [label]
// volume_destroyed public:127:4

// commands:
// volume mount public:127:4 [primary]
// volume unmount public:127:4
// volume bind_user public:127:4 [userId]
// volume unbind_user public:127:4 [userId]
// volume bind_package private:4:1 [userId] [package]
// volume unbind_package private:4:1 [userId] [package]

/*
 * Representation of a mounted volume ready for presentation.
 *
 * Various subclasses handle the different mounting prerequisites, such as
 * encryption details, etc.  Volumes can also be "stacked" above other
 * volumes to help communicate dependencies.  For example, an ASEC volume
 * can be stacked on a vfat volume.
 *
 * Mounted volumes can be asked to manage bind mounts to present themselves
 * to specific users on the device.
 *
 * When an unmount is requested, the volume recursively unmounts any stacked
 * volumes and removes any bind mounts before finally unmounting itself.
 */
class VolumeBase {
public:
    virtual ~VolumeBase();

    VolumeType getType() { return mType; }
    const std::string& getId() { return mId; }
    VolumeState getState() { return mState; }

    void stackVolume(const std::shared_ptr<VolumeBase>& volume);
    void unstackVolume(const std::shared_ptr<VolumeBase>& volume);

    status_t mount();
    status_t unmount();
    status_t format();

protected:
    explicit VolumeBase(VolumeType type);

    /* ID that uniquely references this disk */
    std::string mId;

    /* Manage bind mounts for this volume */
    status_t mountBind(const std::string& source, const std::string& target);
    status_t unmountBind(const std::string& target);

    virtual status_t doMount() = 0;
    virtual status_t doUnmount() = 0;
    virtual status_t doFormat();

private:
    /* Volume type */
    VolumeType mType;
    /* Current state of volume */
    VolumeState mState;

    /* Volumes stacked on top of this volume */
    std::list<std::shared_ptr<VolumeBase>> mStacked;
    /* Currently active bind mounts */
    std::list<std::string> mBindTargets;

    void setState(VolumeState state);

    DISALLOW_COPY_AND_ASSIGN(VolumeBase);
};

}  // namespace vold
}  // namespace android

#endif
