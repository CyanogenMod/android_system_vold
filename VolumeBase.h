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

#include <cutils/multiuser.h>
#include <utils/Errors.h>

#include <sys/types.h>
#include <list>
#include <string>

namespace android {
namespace vold {

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

    enum class Type {
        kPublic = 0,
        kPrivate,
        kEmulated,
        kAsec,
        kObb,
    };

    enum Flags {
        /* Flag that volume is primary external storage */
        kPrimary = 1 << 0,
        /* Flag that volume is visible to normal apps */
        kVisible = 1 << 1,
    };

    enum class State {
        /* Next states: mounting, formatting */
        kUnmounted = 0,
        /* Next states: mounted, unmountable */
        kMounting,
        /* Next states: unmounting */
        kMounted,
        /* Next states: unmounted */
        kFormatting,
        /* Next states: unmounted */
        kUnmounting,
        /* Next states: mounting, formatting */
        kUnmountable,
    };

    const std::string& getId() { return mId; }
    Type getType() { return mType; }
    int getFlags() { return mFlags; }
    userid_t getUser() { return mUser; }
    State getState() { return mState; }
    const std::string& getPath() { return mPath; }

    status_t setFlags(int flags);
    status_t setUser(userid_t user);
    status_t setSilent(bool silent);

    void addVolume(const std::shared_ptr<VolumeBase>& volume);
    void removeVolume(const std::shared_ptr<VolumeBase>& volume);

    std::shared_ptr<VolumeBase> findVolume(const std::string& id);

    status_t create();
    status_t destroy();
    status_t mount();
    status_t unmount();
    status_t format();

protected:
    explicit VolumeBase(Type type);

    virtual status_t doCreate();
    virtual status_t doDestroy();
    virtual status_t doMount() = 0;
    virtual status_t doUnmount() = 0;
    virtual status_t doFormat();

    status_t setId(const std::string& id);
    status_t setPath(const std::string& path);

    void notifyEvent(int msg);
    void notifyEvent(int msg, const std::string& value);

private:
    /* ID that uniquely references volume while alive */
    std::string mId;
    /* Volume type */
    Type mType;
    /* Flags applicable to volume */
    int mFlags;
    /* User that owns this volume, otherwise -1 */
    userid_t mUser;
    /* Flag indicating object is created */
    bool mCreated;
    /* Current state of volume */
    State mState;
    /* Path to mounted volume */
    std::string mPath;
    /* Flag indicating that volume should emit no events */
    bool mSilent;

    /* Volumes stacked on top of this volume */
    std::list<std::shared_ptr<VolumeBase>> mVolumes;

    void setState(State state);

    DISALLOW_COPY_AND_ASSIGN(VolumeBase);
};

}  // namespace vold
}  // namespace android

#endif
