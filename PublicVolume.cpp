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

#include "fs/Exfat.h"
#include "fs/Ext4.h"
#include "fs/F2fs.h"
#include "fs/Ntfs.h"
#include "fs/Vfat.h"
#include "PublicVolume.h"
#include "Utils.h"
#include "VolumeManager.h"
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

static const char* kAsecPath = "/mnt/secure/asec";

PublicVolume::PublicVolume(dev_t device, const std::string& nickname,
                const std::string& fstype /* = "" */,
                const std::string& mntopts /* = "" */) :
        VolumeBase(Type::kPublic), mDevice(device), mFusePid(0),
        mFsType(fstype), mFsLabel(nickname), mMntOpts(mntopts) {
    setId(StringPrintf("public:%u_%u", major(device), minor(device)));
    mDevPath = StringPrintf("/dev/block/vold/%s", getId().c_str());
}

PublicVolume::~PublicVolume() {
}

status_t PublicVolume::readMetadata() {
    status_t res = ReadMetadataUntrusted(mDevPath, mFsType, mFsUuid, mFsLabel);
    notifyEvent(ResponseCode::VolumeFsTypeChanged, mFsType);
    notifyEvent(ResponseCode::VolumeFsUuidChanged, mFsUuid);
    notifyEvent(ResponseCode::VolumeFsLabelChanged, mFsLabel);
    return res;
}

status_t PublicVolume::initAsecStage() {
    std::string legacyPath(mRawPath + "/android_secure");
    std::string securePath(mRawPath + "/.android_secure");

    // Recover legacy secure path
    if (!access(legacyPath.c_str(), R_OK | X_OK)
            && access(securePath.c_str(), R_OK | X_OK)) {
        if (rename(legacyPath.c_str(), securePath.c_str())) {
            PLOG(WARNING) << getId() << " failed to rename legacy ASEC dir";
        }
    }

    if (TEMP_FAILURE_RETRY(mkdir(securePath.c_str(), 0700))) {
        if (errno != EEXIST) {
            PLOG(WARNING) << getId() << " creating ASEC stage failed";
            return -errno;
        }
    }

    BindMount(securePath, kAsecPath);

    return OK;
}

status_t PublicVolume::doCreate() {
    if (mFsLabel.size() > 0) {
        notifyEvent(ResponseCode::VolumeFsLabelChanged, mFsLabel);
    }
    return CreateDeviceNode(mDevPath, mDevice);
}

status_t PublicVolume::doDestroy() {
    return DestroyDeviceNode(mDevPath);
}

status_t PublicVolume::doMount() {
    // TODO: expand to support mounting other filesystems
    readMetadata();

    if (!IsFilesystemSupported(mFsType)) {
        LOG(ERROR) << getId() << " unsupported filesystem " << mFsType;
        return -EIO;
    }

    // Use UUID as stable name, if available
    std::string stableName = getId();
    if (!mFsUuid.empty()) {
        stableName = mFsUuid;
    }

#ifdef MINIVOLD
    // In recovery, directly mount to /storage/* since we have no fuse daemon
    mRawPath = StringPrintf("/storage/%s", stableName.c_str());
    mFuseDefault = StringPrintf("/storage/%s", stableName.c_str());
    mFuseRead = StringPrintf("/storage/%s", stableName.c_str());
    mFuseWrite = StringPrintf("/storage/%s", stableName.c_str());
#else
    mRawPath = StringPrintf("/mnt/media_rw/%s", stableName.c_str());
    mFuseDefault = StringPrintf("/mnt/runtime/default/%s", stableName.c_str());
    mFuseRead = StringPrintf("/mnt/runtime/read/%s", stableName.c_str());
    mFuseWrite = StringPrintf("/mnt/runtime/write/%s", stableName.c_str());
#endif

    setInternalPath(mRawPath);
    if (getMountFlags() & MountFlags::kVisible) {
        setPath(StringPrintf("/storage/%s", stableName.c_str()));
    } else {
        setPath(mRawPath);
    }

    if (fs_prepare_dir(mRawPath.c_str(), 0700, AID_ROOT, AID_ROOT)) {
        PLOG(ERROR) << getId() << " failed to create mount points";
        return -errno;
    }

    int ret = 0;
    if (mFsType == "exfat") {
        ret = exfat::Check(mDevPath);
    } else if (mFsType == "ext4") {
        ret = ext4::Check(mDevPath, mRawPath, false);
    } else if (mFsType == "f2fs") {
        ret = f2fs::Check(mDevPath, false);
    } else if (mFsType == "ntfs") {
        ret = ntfs::Check(mDevPath);
    } else if (mFsType == "vfat") {
        ret = vfat::Check(mDevPath);
    } else {
        LOG(WARNING) << getId() << " unsupported filesystem check, skipping";
    }
    if (ret) {
        LOG(ERROR) << getId() << " failed filesystem check";
        return -EIO;
    }

    if (mFsType == "exfat") {
        ret = exfat::Mount(mDevPath, mRawPath, false, false, false,
                AID_MEDIA_RW, AID_MEDIA_RW, 0007);
    } else if (mFsType == "ext4") {
        ret = ext4::Mount(mDevPath, mRawPath, false, false, true, mMntOpts,
                false);
    } else if (mFsType == "f2fs") {
        ret = f2fs::Mount(mDevPath, mRawPath, false);
    } else if (mFsType == "ntfs") {
        ret = ntfs::Mount(mDevPath, mRawPath, false, false, false,
                AID_MEDIA_RW, AID_MEDIA_RW, 0007, true);
    } else if (mFsType == "vfat") {
        ret = vfat::Mount(mDevPath, mRawPath, false, false, false,
                AID_MEDIA_RW, AID_MEDIA_RW, 0007, true);
    } else {
        ret = ::mount(mDevPath.c_str(), mRawPath.c_str(), mFsType.c_str(), 0, NULL);
    }
    if (ret) {
        PLOG(ERROR) << getId() << " failed to mount " << mDevPath;
        return -EIO;
    }

#ifdef MINIVOLD
    // In recovery, don't setup ASEC or FUSE
    return OK;
#endif

    if (getMountFlags() & MountFlags::kPrimary) {
        initAsecStage();
    }

    if (!(getMountFlags() & MountFlags::kVisible)) {
        // Not visible to apps, so no need to spin up FUSE
        return OK;
    }

    if (fs_prepare_dir(mFuseDefault.c_str(), 0700, AID_ROOT, AID_ROOT) ||
            fs_prepare_dir(mFuseRead.c_str(), 0700, AID_ROOT, AID_ROOT) ||
            fs_prepare_dir(mFuseWrite.c_str(), 0700, AID_ROOT, AID_ROOT)) {
        PLOG(ERROR) << getId() << " failed to create FUSE mount points";
        return -errno;
    }

    dev_t before = GetDevice(mFuseWrite);

    if (!(mFusePid = fork())) {
        if (getMountFlags() & MountFlags::kPrimary) {
            if (execl(kFusePath, kFusePath,
                    "-u", "1023", // AID_MEDIA_RW
                    "-g", "1023", // AID_MEDIA_RW
                    "-U", std::to_string(getMountUserId()).c_str(),
                    "-w",
                    mRawPath.c_str(),
                    stableName.c_str(),
                    NULL)) {
                PLOG(ERROR) << "Failed to exec";
            }
        } else {
            if (execl(kFusePath, kFusePath,
                    "-u", "1023", // AID_MEDIA_RW
                    "-g", "1023", // AID_MEDIA_RW
                    "-U", std::to_string(getMountUserId()).c_str(),
                    mRawPath.c_str(),
                    stableName.c_str(),
                    NULL)) {
                PLOG(ERROR) << "Failed to exec";
            }
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

status_t PublicVolume::doUnmount(bool detach /* = false */) {
    // Unmount the storage before we kill the FUSE process. If we kill
    // the FUSE process first, most file system operations will return
    // ENOTCONN until the unmount completes. This is an exotic and unusual
    // error code and might cause broken behaviour in applications.
    KillProcessesUsingPath(getPath());

#ifndef MINIVOLD
    ForceUnmount(kAsecPath);

    ForceUnmount(mFuseDefault);
    ForceUnmount(mFuseRead);
    ForceUnmount(mFuseWrite);
#endif

    ForceUnmount(mRawPath, detach);

    if (mFusePid > 0) {
        kill(mFusePid, SIGTERM);
        TEMP_FAILURE_RETRY(waitpid(mFusePid, nullptr, 0));
        mFusePid = 0;
    }

    rmdir(mFuseDefault.c_str());
    rmdir(mFuseRead.c_str());
    rmdir(mFuseWrite.c_str());
    rmdir(mRawPath.c_str());

    mFuseDefault.clear();
    mFuseRead.clear();
    mFuseWrite.clear();
    mRawPath.clear();

    return OK;
}

status_t PublicVolume::doFormat(const std::string& fsType) {
    // "auto" is used for newly partitioned disks (see Disk::partition*)
    // and thus is restricted to external/removable storage.
    if (!(IsFilesystemSupported(fsType) || fsType == "auto")) {
        LOG(ERROR) << "Unsupported filesystem " << fsType;
        return -EINVAL;
    }

    if (WipeBlockDevice(mDevPath) != OK) {
        LOG(WARNING) << getId() << " failed to wipe";
    }

    int ret = 0;
    if (fsType == "auto") {
        ret = vfat::Format(mDevPath, 0);
    } else if (fsType == "exfat") {
        ret = exfat::Format(mDevPath);
    } else if (fsType == "ext4") {
        ret = ext4::Format(mDevPath, 0, mRawPath);
    } else if (fsType == "f2fs") {
        ret = f2fs::Format(mDevPath);
    } else if (fsType == "ntfs") {
        ret = ntfs::Format(mDevPath, 0);
    } else if (fsType == "vfat") {
        ret = vfat::Format(mDevPath, 0);
    } else {
        LOG(ERROR) << getId() << " unrecognized filesystem " << fsType;
        ret = -1;
        errno = EIO;
    }

    if (ret) {
        LOG(ERROR) << getId() << " failed to format";
        return -errno;
    }

    return OK;
}

}  // namespace vold
}  // namespace android
