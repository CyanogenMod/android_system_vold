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

#include "Utils.h"
#include "VolumeBase.h"
#include "VolumeManager.h"
#include "ResponseCode.h"

#include <base/stringprintf.h>
#include <base/logging.h>

#include <fcntl.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>

using android::base::StringPrintf;

#define DEBUG 1

namespace android {
namespace vold {

VolumeBase::VolumeBase(Type type) :
        mType(type), mMountFlags(0), mMountUserId(-1), mCreated(false), mState(
                State::kUnmounted), mSilent(false) {
}

VolumeBase::~VolumeBase() {
    CHECK(!mCreated);
}

void VolumeBase::setState(State state) {
    mState = state;
    notifyEvent(ResponseCode::VolumeStateChanged, StringPrintf("%d", mState));
}

status_t VolumeBase::setDiskId(const std::string& diskId) {
    if (mCreated) {
        LOG(WARNING) << getId() << " diskId change requires destroyed";
        return -EBUSY;
    }

    mDiskId = diskId;
    return OK;
}

status_t VolumeBase::setPartGuid(const std::string& partGuid) {
    if (mCreated) {
        LOG(WARNING) << getId() << " partGuid change requires destroyed";
        return -EBUSY;
    }

    mPartGuid = partGuid;
    return OK;
}

status_t VolumeBase::setMountFlags(int mountFlags) {
    if ((mState != State::kUnmounted) && (mState != State::kUnmountable)) {
        LOG(WARNING) << getId() << " flags change requires state unmounted or unmountable";
        return -EBUSY;
    }

    mMountFlags = mountFlags;
    return OK;
}

status_t VolumeBase::setMountUserId(userid_t mountUserId) {
    if ((mState != State::kUnmounted) && (mState != State::kUnmountable)) {
        LOG(WARNING) << getId() << " user change requires state unmounted or unmountable";
        return -EBUSY;
    }

    mMountUserId = mountUserId;
    return OK;
}

status_t VolumeBase::setSilent(bool silent) {
    if (mCreated) {
        LOG(WARNING) << getId() << " silence change requires destroyed";
        return -EBUSY;
    }

    mSilent = silent;
    return OK;
}

status_t VolumeBase::setId(const std::string& id) {
    if (mCreated) {
        LOG(WARNING) << getId() << " id change requires not created";
        return -EBUSY;
    }

    mId = id;
    return OK;
}

status_t VolumeBase::setPath(const std::string& path) {
    if (mState != State::kChecking) {
        LOG(WARNING) << getId() << " path change requires state checking";
        return -EBUSY;
    }

    mPath = path;
    notifyEvent(ResponseCode::VolumePathChanged, mPath);
    return OK;
}

status_t VolumeBase::setInternalPath(const std::string& internalPath) {
    if (mState != State::kChecking) {
        LOG(WARNING) << getId() << " internal path change requires state checking";
        return -EBUSY;
    }

    mInternalPath = internalPath;
    notifyEvent(ResponseCode::VolumeInternalPathChanged, mInternalPath);
    return OK;
}

void VolumeBase::notifyEvent(int event) {
    if (mSilent) return;
    VolumeManager::Instance()->getBroadcaster()->sendBroadcast(event,
            getId().c_str(), false);
}

void VolumeBase::notifyEvent(int event, const std::string& value) {
    if (mSilent) return;
    VolumeManager::Instance()->getBroadcaster()->sendBroadcast(event,
            StringPrintf("%s %s", getId().c_str(), value.c_str()).c_str(), false);
}

void VolumeBase::addVolume(const std::shared_ptr<VolumeBase>& volume) {
    mVolumes.push_back(volume);
}

void VolumeBase::removeVolume(const std::shared_ptr<VolumeBase>& volume) {
    mVolumes.remove(volume);
}

std::shared_ptr<VolumeBase> VolumeBase::findVolume(const std::string& id) {
    for (auto vol : mVolumes) {
        if (vol->getId() == id) {
            return vol;
        }
    }
    return nullptr;
}

status_t VolumeBase::create() {
    CHECK(!mCreated);

    mCreated = true;
    notifyEvent(ResponseCode::VolumeCreated,
            StringPrintf("%d \"%s\" \"%s\"", mType, mDiskId.c_str(), mPartGuid.c_str()));
    status_t res = doCreate();
    setState(State::kUnmounted);
    return res;
}

status_t VolumeBase::doCreate() {
    return OK;
}

status_t VolumeBase::destroy() {
    CHECK(mCreated);

    if (mState == State::kMounted) {
        unmount();
        setState(State::kBadRemoval);
    } else {
        setState(State::kRemoved);
    }

    notifyEvent(ResponseCode::VolumeDestroyed);
    status_t res = doDestroy();
    mCreated = false;
    return res;
}

status_t VolumeBase::doDestroy() {
    return OK;
}

status_t VolumeBase::mount() {
    if ((mState != State::kUnmounted) && (mState != State::kUnmountable)) {
        LOG(WARNING) << getId() << " mount requires state unmounted or unmountable";
        return -EBUSY;
    }

    setState(State::kChecking);
    status_t res = doMount();
    if (res == OK) {
        setState(State::kMounted);
    } else {
        setState(State::kUnmountable);
    }

    return res;
}

status_t VolumeBase::unmount(bool detach /* = false */) {
    if (mState != State::kMounted) {
        LOG(WARNING) << getId() << " unmount requires state mounted";
        return -EBUSY;
    }

    setState(State::kEjecting);
    for (auto vol : mVolumes) {
        if (vol->destroy()) {
            LOG(WARNING) << getId() << " failed to destroy " << vol->getId()
                    << " stacked above";
        }
    }
    mVolumes.clear();

    status_t res = doUnmount(detach);
    setState(State::kUnmounted);
    return res;
}

status_t VolumeBase::format(const std::string& fsType) {
    if (mState == State::kMounted) {
        unmount();
    }

    if ((mState != State::kUnmounted) && (mState != State::kUnmountable)) {
        LOG(WARNING) << getId() << " format requires state unmounted or unmountable";
        return -EBUSY;
    }

    setState(State::kFormatting);
    status_t res = doFormat(fsType);
    setState(State::kUnmounted);
    return res;
}

status_t VolumeBase::doFormat(const std::string& fsType) {
    return -ENOTSUP;
}

}  // namespace vold
}  // namespace android
