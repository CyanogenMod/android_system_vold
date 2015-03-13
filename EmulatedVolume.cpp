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

#include "EmulatedVolume.h"
#include "Utils.h"

#include <cutils/fs.h>
#include <cutils/log.h>
#include <utils/file.h>
#include <utils/stringprintf.h>
#include <private/android_filesystem_config.h>

#include <fcntl.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

namespace android {
namespace vold {

static const char* kFusePath = "/system/bin/sdcard";

static const char* kUserMountPath = "/mnt/user";

EmulatedVolume::EmulatedVolume(const std::string& rawPath, const std::string& nickname) :
        VolumeBase(VolumeType::kEmulated), mFusePid(0), mPrimary(false) {
    mRawPath = rawPath;
    mFusePath = StringPrintf("/mnt/media_rw/emulated_fuse_%s", nickname.c_str());
}

EmulatedVolume::~EmulatedVolume() {
}

status_t EmulatedVolume::doMount() {
    if (fs_prepare_dir(mFusePath.c_str(), 0770, AID_MEDIA_RW, AID_MEDIA_RW)) {
        SLOGE("Failed to create mount point %s: %s", mFusePath.c_str(), strerror(errno));
        return -errno;
    }

    if (!(mFusePid = fork())) {
        if (execl(kFusePath,
                "-u", "1023", // AID_MEDIA_RW
                "-g", "1023", // AID_MEDIA_RW
                "-d",
                mRawPath.c_str(),
                mFusePath.c_str())) {
            SLOGE("Failed to exec: %s", strerror(errno));
        }
        _exit(1);
    }

    if (mFusePid == -1) {
        SLOGE("Failed to fork: %s", strerror(errno));
        return -errno;
    }

    return OK;
}

status_t EmulatedVolume::doUnmount() {
    if (mFusePid > 0) {
        kill(mFusePid, SIGTERM);
        TEMP_FAILURE_RETRY(waitpid(mFusePid, nullptr, 0));
        mFusePid = 0;
    }

    ForceUnmount(mFusePath);

    TEMP_FAILURE_RETRY(unlink(mFusePath.c_str()));

    return OK;
}

status_t EmulatedVolume::doFormat() {
    return -ENOTSUP;
}

status_t EmulatedVolume::bindUser(userid_t user) {
    return bindUserInternal(user, true);
}

status_t EmulatedVolume::unbindUser(userid_t user) {
    return bindUserInternal(user, false);
}

status_t EmulatedVolume::bindUserInternal(userid_t user, bool bind) {
    if (!mPrimary) {
        // Emulated volumes are only bound when primary
        return OK;
    }

    std::string fromPath(StringPrintf("%s/%ud", mFusePath.c_str(), user));
    std::string toPath(StringPrintf("%s/%ud/primary", kUserMountPath, user));

    if (bind) {
        mountBind(fromPath, toPath);
    } else {
        unmountBind(toPath);
    }

    return OK;
}

void EmulatedVolume::setPrimary(bool primary) {
    if (getState() != VolumeState::kUnmounted) {
        SLOGE("Primary state change requires %s to be unmounted", getId().c_str());
        return;
    }

    mPrimary = primary;
}

}  // namespace vold
}  // namespace android
