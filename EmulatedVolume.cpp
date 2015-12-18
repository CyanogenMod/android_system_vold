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
#include "ResponseCode.h"

#include <android-base/stringprintf.h>
#include <android-base/logging.h>
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

#ifdef MINIVOLD
static const char* kFusePath = "/sbin/sdcard";
#else
static const char* kFusePath = "/system/bin/sdcard";
#endif

EmulatedVolume::EmulatedVolume(const std::string& rawPath) :
        VolumeBase(Type::kEmulated), mFusePid(0) {
    setId("emulated");
    mRawPath = rawPath;
    mLabel = "emulated";
}

EmulatedVolume::EmulatedVolume(const std::string& rawPath, dev_t device,
        const std::string& fsUuid) : VolumeBase(Type::kEmulated), mFusePid(0) {
    setId(StringPrintf("emulated:%u_%u", major(device), minor(device)));
    mRawPath = rawPath;
    mLabel = fsUuid;
}

EmulatedVolume::~EmulatedVolume() {
}

status_t EmulatedVolume::doCreate() {
    if (mLabel.size() > 0) {
        notifyEvent(ResponseCode::VolumeFsLabelChanged, mLabel);
    }
    return OK;
}

status_t EmulatedVolume::doMount() {
    // We could have migrated storage to an adopted private volume, so always
    // call primary storage "emulated" to avoid media rescans.
    std::string label = mLabel;
    if (getMountFlags() & MountFlags::kPrimary) {
        label = "emulated";
    }

    mFuseDefault = StringPrintf("/mnt/runtime/default/%s", label.c_str());
    mFuseRead = StringPrintf("/mnt/runtime/read/%s", label.c_str());
    mFuseWrite = StringPrintf("/mnt/runtime/write/%s", label.c_str());

    setInternalPath(mRawPath);
    setPath(StringPrintf("/storage/%s", label.c_str()));

    if (fs_prepare_dir(mFuseDefault.c_str(), 0700, AID_ROOT, AID_ROOT) ||
            fs_prepare_dir(mFuseRead.c_str(), 0700, AID_ROOT, AID_ROOT) ||
            fs_prepare_dir(mFuseWrite.c_str(), 0700, AID_ROOT, AID_ROOT)) {
        PLOG(ERROR) << getId() << " failed to create mount points";
        return -errno;
    }

    dev_t before = GetDevice(mFuseWrite);

    if (!(mFusePid = fork())) {
        if (execl(kFusePath, kFusePath,
                "-u", "1023", // AID_MEDIA_RW
                "-g", "1023", // AID_MEDIA_RW
                "-m",
                "-w",
                mRawPath.c_str(),
                label.c_str(),
                NULL)) {
            PLOG(ERROR) << "Failed to exec";
        }

        LOG(ERROR) << "FUSE exiting";
        _exit(1);
    }

    if (mFusePid == -1) {
        PLOG(ERROR) << getId() << " failed to fork";
        return -errno;
    }

    while (before == GetDevice(mFuseWrite)) {
        LOG(VERBOSE) << "Waiting for FUSE to spin up...";
        usleep(50000); // 50ms
    }

    return OK;
}

status_t EmulatedVolume::doUnmount(bool detach /* = false */) {
    // Unmount the storage before we kill the FUSE process. If we kill
    // the FUSE process first, most file system operations will return
    // ENOTCONN until the unmount completes. This is an exotic and unusual
    // error code and might cause broken behaviour in applications.
    KillProcessesUsingPath(getPath());
    ForceUnmount(mFuseDefault);
    ForceUnmount(mFuseRead);
    ForceUnmount(mFuseWrite);

    if (mFusePid > 0) {
        kill(mFusePid, SIGTERM);
        TEMP_FAILURE_RETRY(waitpid(mFusePid, nullptr, 0));
        mFusePid = 0;
    }

    rmdir(mFuseDefault.c_str());
    rmdir(mFuseRead.c_str());
    rmdir(mFuseWrite.c_str());

    mFuseDefault.clear();
    mFuseRead.clear();
    mFuseWrite.clear();

    return OK;
}

}  // namespace vold
}  // namespace android
