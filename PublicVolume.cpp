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

#include "Fat.h"
#include "PublicVolume.h"
#include "Utils.h"
#include "VolumeManager.h"
#include "ResponseCode.h"

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

static const char* kBlkidPath = "/system/bin/blkid";
static const char* kFusePath = "/system/bin/sdcard";

static const char* kAsecPath = "/mnt/secure/asec";

PublicVolume::PublicVolume(dev_t device) :
        VolumeBase(Type::kPublic), mDevice(device), mFusePid(0) {
    setId(StringPrintf("public:%u,%u", major(device), minor(device)));
    mDevPath = StringPrintf("/dev/block/vold/%s", getId().c_str());
    CreateDeviceNode(mDevPath, mDevice);
}

PublicVolume::~PublicVolume() {
    DestroyDeviceNode(mDevPath);
}

status_t PublicVolume::readMetadata() {
    mFsType.clear();
    mFsUuid.clear();
    mFsLabel.clear();

    std::string path(StringPrintf("%s -c /dev/null %s", kBlkidPath, mDevPath.c_str()));
    FILE* fp = popen(path.c_str(), "r");
    if (!fp) {
        PLOG(ERROR) << "Failed to run " << path;
        return -errno;
    }

    status_t res = OK;
    char line[1024];
    char value[128];
    if (fgets(line, sizeof(line), fp) != nullptr) {
        LOG(DEBUG) << "blkid identified as " << line;

        char* start = strstr(line, "TYPE=");
        if (start != nullptr && sscanf(start + 5, "\"%127[^\"]\"", value) == 1) {
            mFsType = value;
        }

        start = strstr(line, "UUID=");
        if (start != nullptr && sscanf(start + 5, "\"%127[^\"]\"", value) == 1) {
            mFsUuid = value;
        }

        start = strstr(line, "LABEL=");
        if (start != nullptr && sscanf(start + 6, "\"%127[^\"]\"", value) == 1) {
            mFsLabel = value;
        }
    } else {
        LOG(WARNING) << "blkid failed to identify " << mDevPath;
        res = -ENODATA;
    }

    pclose(fp);

    VolumeManager::Instance()->getBroadcaster()->sendBroadcast(
            ResponseCode::VolumeFsTypeChanged,
            StringPrintf("%s %s", getId().c_str(), mFsType.c_str()).c_str(), false);
    VolumeManager::Instance()->getBroadcaster()->sendBroadcast(
            ResponseCode::VolumeFsUuidChanged,
            StringPrintf("%s %s", getId().c_str(), mFsUuid.c_str()).c_str(), false);
    VolumeManager::Instance()->getBroadcaster()->sendBroadcast(
            ResponseCode::VolumeFsLabelChanged,
            StringPrintf("%s %s", getId().c_str(), mFsLabel.c_str()).c_str(), false);

    return res;
}

status_t PublicVolume::initAsecStage() {
    std::string legacyPath(mRawPath + "/android_secure");
    std::string securePath(mRawPath + "/.android_secure");

    // Recover legacy secure path
    if (!access(legacyPath.c_str(), R_OK | X_OK)
            && access(securePath.c_str(), R_OK | X_OK)) {
        if (rename(legacyPath.c_str(), securePath.c_str())) {
            PLOG(WARNING) << "Failed to rename legacy ASEC dir";
        }
    }

    if (TEMP_FAILURE_RETRY(mkdir(securePath.c_str(), 0700))) {
        if (errno != EEXIST) {
            PLOG(WARNING) << "Creating ASEC stage failed";
            return -errno;
        }
    }

    BindMount(securePath, kAsecPath);

    return OK;
}

status_t PublicVolume::doMount() {
    // TODO: expand to support mounting other filesystems
    if (Fat::check(mDevPath.c_str())) {
        LOG(ERROR) << "Failed filesystem check; not mounting";
        return -EIO;
    }

    readMetadata();

    // Use UUID as stable name, if available
    std::string stableName = getId();
    if (!mFsUuid.empty()) {
        stableName = "public:" + mFsUuid;
    }

    mRawPath = StringPrintf("/mnt/media_rw/%s", stableName.c_str());
    mFusePath = StringPrintf("/storage/%s", stableName.c_str());
    setPath(mFusePath);

    if (fs_prepare_dir(mRawPath.c_str(), 0700, AID_ROOT, AID_ROOT)) {
        PLOG(ERROR) << "Failed to create mount point " << mRawPath;
        return -errno;
    }
    if (fs_prepare_dir(mFusePath.c_str(), 0700, AID_ROOT, AID_ROOT)) {
        PLOG(ERROR) << "Failed to create mount point " << mFusePath;
        return -errno;
    }

    if (Fat::doMount(mDevPath.c_str(), mRawPath.c_str(), false, false, false,
            AID_MEDIA_RW, AID_MEDIA_RW, 0007, true)) {
        PLOG(ERROR) << "Failed to mount " << mDevPath;
        return -EIO;
    }

    if (getFlags() & Flags::kPrimary) {
        initAsecStage();
    }

    // Only need to spin up FUSE when visible
    if (!(getFlags() & Flags::kVisible)) {
        return OK;
    }

    // TODO: teach FUSE daemon to protect itself with user-specific GID
    if (!(mFusePid = fork())) {
        if (getFlags() & Flags::kPrimary) {
            if (execl(kFusePath, kFusePath,
                    "-u", "1023", // AID_MEDIA_RW
                    "-g", "1023", // AID_MEDIA_RW
                    "-d",
                    mRawPath.c_str(),
                    mFusePath.c_str(),
                    NULL)) {
                PLOG(ERROR) << "Failed to exec";
            }
        } else {
            if (execl(kFusePath, kFusePath,
                    "-u", "1023", // AID_MEDIA_RW
                    "-g", "1023", // AID_MEDIA_RW
                    "-w", "1023", // AID_MEDIA_RW
                    "-d",
                    mRawPath.c_str(),
                    mFusePath.c_str(),
                    NULL)) {
                PLOG(ERROR) << "Failed to exec";
            }
        }

        PLOG(DEBUG) << "FUSE exiting";
        _exit(1);
    }

    if (mFusePid == -1) {
        PLOG(ERROR) << "Failed to fork";
        return -errno;
    }

    return OK;
}

status_t PublicVolume::doUnmount() {
    if (mFusePid > 0) {
        kill(mFusePid, SIGTERM);
        TEMP_FAILURE_RETRY(waitpid(mFusePid, nullptr, 0));
        mFusePid = 0;
    }

    ForceUnmount(mFusePath);
    ForceUnmount(mRawPath);

    if (TEMP_FAILURE_RETRY(rmdir(mRawPath.c_str()))) {
        PLOG(ERROR) << "Failed to rmdir mount point " << mRawPath;
    }
    if (TEMP_FAILURE_RETRY(rmdir(mFusePath.c_str()))) {
        PLOG(ERROR) << "Failed to rmdir mount point " << mFusePath;
    }

    mFusePath.clear();
    mRawPath.clear();

    return OK;
}

status_t PublicVolume::doFormat() {
    if (Fat::format(mDevPath.c_str(), 0, true)) {
        LOG(ERROR) << "Failed to format";
        return -errno;
    }
    return OK;
}

}  // namespace vold
}  // namespace android
