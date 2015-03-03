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

#define LOG_TAG "Vold"

#include "Utils.h"
#include "VolumeBase.h"

#include <cutils/log.h>

#include <fcntl.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>

namespace android {
namespace vold {

VolumeBase::VolumeBase(VolumeType type) :
        mType(type), mState(VolumeState::kUnmounted) {
}

VolumeBase::~VolumeBase() {
}

void VolumeBase::setState(VolumeState state) {
    mState = state;

    // TODO: publish state up to framework
}

void VolumeBase::stackVolume(const std::shared_ptr<VolumeBase>& volume) {
    mStacked.push_back(volume);
}

void VolumeBase::unstackVolume(const std::shared_ptr<VolumeBase>& volume) {
    mStacked.remove(volume);
}

status_t VolumeBase::mount() {
    if (getState() != VolumeState::kUnmounted) {
        SLOGE("Must be unmounted to mount %s", getId().c_str());
        return -EBUSY;
    }

    setState(VolumeState::kMounting);
    status_t res = doMount();
    if (!res) {
        setState(VolumeState::kMounted);
    } else {
        setState(VolumeState::kCorrupt);
    }

    return res;
}

status_t VolumeBase::unmount() {
    if (getState() != VolumeState::kMounted) {
        SLOGE("Must be mounted to unmount %s", getId().c_str());
        return -EBUSY;
    }

    setState(VolumeState::kUnmounting);

    for (std::string target : mBindTargets) {
        ForceUnmount(target);
    }
    mBindTargets.clear();

    for (std::shared_ptr<VolumeBase> v : mStacked) {
        if (v->unmount()) {
            ALOGW("Failed to unmount %s stacked above %s", v->getId().c_str(),
                    getId().c_str());
        }
    }
    mStacked.clear();

    status_t res = doUnmount();
    setState(VolumeState::kUnmounted);
    return res;
}

status_t VolumeBase::format() {
    if (getState() != VolumeState::kUnmounted
            || getState() != VolumeState::kCorrupt) {
        SLOGE("Must be unmounted or corrupt to format %s", getId().c_str());
        return -EBUSY;
    }

    setState(VolumeState::kFormatting);
    status_t res = doFormat();
    setState(VolumeState::kUnmounted);
    return res;
}

status_t VolumeBase::doFormat() {
    return -ENOTSUP;
}

status_t VolumeBase::mountBind(const std::string& source, const std::string& target) {
    if (::mount(source.c_str(), target.c_str(), "", MS_BIND, NULL)) {
        SLOGE("Failed to bind mount %s to %s: %s", source.c_str(),
                target.c_str(), strerror(errno));
        return -errno;
    }
    mBindTargets.push_back(target);
    return OK;
}

status_t VolumeBase::unmountBind(const std::string& target) {
    ForceUnmount(target);
    mBindTargets.remove(target);
    return OK;
}

}  // namespace vold
}  // namespace android
