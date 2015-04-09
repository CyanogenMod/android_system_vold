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
        mType(type), mFlags(0), mUser(-1), mCreated(false), mState(
                State::kUnmounted), mSilent(false) {
}

VolumeBase::~VolumeBase() {
    CHECK(!mCreated);
}

void VolumeBase::setState(State state) {
    mState = state;
    notifyEvent(ResponseCode::VolumeStateChanged, StringPrintf("%d", mState));
}

status_t VolumeBase::setFlags(int flags) {
    if (mState != State::kUnmounted) {
        LOG(WARNING) << getId() << " flags change requires state unmounted";
        return -EBUSY;
    }

    mFlags = flags;
    return OK;
}

status_t VolumeBase::setUser(userid_t user) {
    if (mState != State::kUnmounted) {
        LOG(WARNING) << getId() << " user change requires state unmounted";
        return -EBUSY;
    }

    mUser = user;
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
    if (mState != State::kMounting) {
        LOG(WARNING) << getId() << " path change requires state mounting";
        return -EBUSY;
    }

    mPath = path;
    notifyEvent(ResponseCode::VolumePathChanged, mPath);
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
    status_t res = doCreate();
    notifyEvent(ResponseCode::VolumeCreated, StringPrintf("%d", mType));
    return res;
}

status_t VolumeBase::doCreate() {
    return OK;
}

status_t VolumeBase::destroy() {
    CHECK(mCreated);

    if (mState == State::kMounted) {
        unmount();
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

    setState(State::kMounting);
    status_t res = doMount();
    if (res == OK) {
        setState(State::kMounted);
    } else {
        setState(State::kUnmountable);
    }

    return res;
}

status_t VolumeBase::unmount() {
    if (mState != State::kMounted) {
        LOG(WARNING) << getId() << " unmount requires state mounted";
        return -EBUSY;
    }

    setState(State::kUnmounting);

    for (auto vol : mVolumes) {
        if (vol->unmount()) {
            LOG(WARNING) << getId() << " failed to unmount " << vol->getId()
                    << " stacked above";
        }
    }
    mVolumes.clear();

    status_t res = doUnmount();
    setState(State::kUnmounted);
    return res;
}

status_t VolumeBase::format() {
    if (mState == State::kMounted) {
        unmount();
    }

    if ((mState != State::kUnmounted) && (mState != State::kUnmountable)) {
        LOG(WARNING) << getId() << " format requires state unmounted or unmountable";
        return -EBUSY;
    }

    setState(State::kFormatting);
    status_t res = doFormat();
    setState(State::kUnmounted);
    return res;
}

status_t VolumeBase::doFormat() {
    return -ENOTSUP;
}

}  // namespace vold
}  // namespace android
