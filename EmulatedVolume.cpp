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

#include "EmulatedVolume.h"
#include "Utils.h"

#include <base/stringprintf.h>
#include <base/logging.h>
#include <cutils/fs.h>
#include <private/android_filesystem_config.h>

#include <fcntl.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

using android::base::StringPrintf;

namespace android {
namespace vold {

static const char* kFusePath = "/system/bin/sdcard";

EmulatedVolume::EmulatedVolume(const std::string& rawPath,
        const std::string& fsUuid) : VolumeBase(Type::kEmulated), mFusePid(0) {
    if (fsUuid.empty()) {
        setId("emulated");
    } else {
        setId(StringPrintf("emulated:%s", fsUuid.c_str()));
    }

    mRawPath = rawPath;
    mFusePath = StringPrintf("/storage/%s", getId().c_str());
}

EmulatedVolume::~EmulatedVolume() {
}

status_t EmulatedVolume::doMount() {
    if (fs_prepare_dir(mFusePath.c_str(), 0700, AID_ROOT, AID_ROOT)) {
        PLOG(ERROR) << getId() << " failed to create mount point " << mFusePath;
        return -errno;
    }

    setPath(mFusePath);

    if (!(mFusePid = fork())) {
        if (execl(kFusePath, kFusePath,
                "-u", "1023", // AID_MEDIA_RW
                "-g", "1023", // AID_MEDIA_RW
                "-l",
                mRawPath.c_str(),
                mFusePath.c_str(),
                NULL)) {
            PLOG(ERROR) << "Failed to exec";
        }

        PLOG(DEBUG) << "FUSE exiting";
        _exit(1);
    }

    if (mFusePid == -1) {
        PLOG(ERROR) << getId() << " failed to fork";
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
    ForceUnmount(mRawPath);

    if (TEMP_FAILURE_RETRY(rmdir(mFusePath.c_str()))) {
        PLOG(ERROR) << getId() << " failed to rmdir mount point " << mFusePath;
        return -errno;
    }

    return OK;
}

}  // namespace vold
}  // namespace android
