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

#include "Ext4.h"
#include "PrivateVolume.h"
#include "EmulatedVolume.h"
#include "Utils.h"
#include "VolumeManager.h"
#include "ResponseCode.h"
#include "cryptfs.h"

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
#include <sys/param.h>

using android::base::StringPrintf;

namespace android {
namespace vold {

PrivateVolume::PrivateVolume(dev_t device, const std::string& keyRaw) :
        VolumeBase(Type::kPrivate), mRawDevice(device), mKeyRaw(keyRaw) {
    setId(StringPrintf("private:%u,%u", major(device), minor(device)));
    mRawDevPath = StringPrintf("/dev/block/vold/%s", getId().c_str());
}

PrivateVolume::~PrivateVolume() {
}

status_t PrivateVolume::readMetadata() {
    status_t res = ReadMetadata(mDmDevPath, mFsType, mFsUuid, mFsLabel);
    notifyEvent(ResponseCode::VolumeFsTypeChanged, mFsType);
    notifyEvent(ResponseCode::VolumeFsUuidChanged, mFsUuid);
    notifyEvent(ResponseCode::VolumeFsLabelChanged, mFsLabel);
    return res;
}

status_t PrivateVolume::doCreate() {
    if (CreateDeviceNode(mRawDevPath, mRawDevice)) {
        return -EIO;
    }

    // Recover from stale vold by tearing down any old mappings
    cryptfs_revert_ext_volume(getId().c_str());

    // TODO: figure out better SELinux labels for private volumes

    unsigned char* key = (unsigned char*) mKeyRaw.data();
    char crypto_blkdev[MAXPATHLEN];
    int res = cryptfs_setup_ext_volume(getId().c_str(), mRawDevPath.c_str(),
            key, mKeyRaw.size(), crypto_blkdev);
    mDmDevPath = crypto_blkdev;
    if (res != 0) {
        PLOG(ERROR) << getId() << " failed to setup cryptfs";
        return -EIO;
    }

    return OK;
}

status_t PrivateVolume::doDestroy() {
    if (cryptfs_revert_ext_volume(getId().c_str())) {
        LOG(ERROR) << getId() << " failed to revert cryptfs";
    }
    return DestroyDeviceNode(mRawDevPath);
}

status_t PrivateVolume::doMount() {
    if (readMetadata()) {
        LOG(ERROR) << getId() << " failed to read metadata";
        return -EIO;
    }

    mPath = StringPrintf("/mnt/expand/%s", mFsUuid.c_str());
    setPath(mPath);

    if (PrepareDir(mPath, 0700, AID_ROOT, AID_ROOT)) {
        PLOG(ERROR) << getId() << " failed to create mount point " << mPath;
        return -EIO;
    }

    if (Ext4::check(mDmDevPath.c_str(), mPath.c_str())) {
        PLOG(ERROR) << getId() << " failed filesystem check";
        return -EIO;
    }

    if (Ext4::doMount(mDmDevPath.c_str(), mPath.c_str(), false, false, true)) {
        PLOG(ERROR) << getId() << " failed to mount";
        return -EIO;
    }

    // Verify that common directories are ready to roll
    if (PrepareDir(mPath + "/app", 0771, AID_SYSTEM, AID_SYSTEM) ||
            PrepareDir(mPath + "/user", 0711, AID_SYSTEM, AID_SYSTEM) ||
            PrepareDir(mPath + "/media", 0770, AID_MEDIA_RW, AID_MEDIA_RW) ||
            PrepareDir(mPath + "/local", 0751, AID_ROOT, AID_ROOT) ||
            PrepareDir(mPath + "/local/tmp", 0771, AID_SHELL, AID_SHELL)) {
        PLOG(ERROR) << getId() << " failed to prepare";
        return -EIO;
    }

    // Create a new emulated volume stacked above us, it will automatically
    // be destroyed during unmount
    std::string mediaPath(mPath + "/media");
    auto vol = std::shared_ptr<VolumeBase>(
            new EmulatedVolume(mediaPath, mRawDevice, mFsUuid));
    addVolume(vol);
    vol->create();

    return OK;
}

status_t PrivateVolume::doUnmount() {
    ForceUnmount(mPath);

    if (TEMP_FAILURE_RETRY(rmdir(mPath.c_str()))) {
        PLOG(ERROR) << getId() << " failed to rmdir mount point " << mPath;
    }

    return OK;
}

status_t PrivateVolume::doFormat() {
    // TODO: change mountpoint once we have selinux labels
    if (Ext4::format(mDmDevPath.c_str(), 0, "/data")) {
        PLOG(ERROR) << getId() << " failed to format";
        return -EIO;
    }

    return OK;
}

}  // namespace vold
}  // namespace android
