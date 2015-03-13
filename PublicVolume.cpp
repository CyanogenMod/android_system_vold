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

#include "Fat.h"
#include "PublicVolume.h"
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

static const char* kBlkidPath = "/system/bin/blkid";
static const char* kFusePath = "/system/bin/sdcard";

static const char* kUserMountPath = "/mnt/user";

PublicVolume::PublicVolume(dev_t device) :
        VolumeBase(VolumeType::kPublic), mDevice(device), mFusePid(0), mPrimary(false) {
    mId = StringPrintf("public:%ud:%ud", major(device), minor(device));
    mDevPath = StringPrintf("/dev/block/vold/%ud:%ud", major(device), minor(device));
    mRawPath = StringPrintf("/mnt/media_rw/public_raw_%ud:%ud", major(device), minor(device));
    mFusePath = StringPrintf("/mnt/media_rw/public_fuse_%ud:%ud", major(device), minor(device));

    CreateDeviceNode(mDevPath, device);
}

PublicVolume::~PublicVolume() {
    DestroyDeviceNode(mDevPath);
}

status_t PublicVolume::readMetadata() {
    mFsUuid = "";
    mFsLabel = "";

    std::string path(StringPrintf("%s -c /dev/null %s", kBlkidPath, mDevPath.c_str()));
    FILE* fp = popen(path.c_str(), "r");
    if (!fp) {
        ALOGE("Failed to run %s: %s", path.c_str(), strerror(errno));
        return -errno;
    }

    char line[1024];
    char value[128];
    if (fgets(line, sizeof(line), fp) != nullptr) {
        ALOGD("blkid identified as %s", line);

        char* start = strstr(line, "UUID=");
        if (start != nullptr && sscanf(start + 5, "\"%127[^\"]\"", value) == 1) {
            mFsUuid = value;
        }

        start = strstr(line, "LABEL=");
        if (start != nullptr && sscanf(start + 6, "\"%127[^\"]\"", value) == 1) {
            mFsLabel = value;
        }
    } else {
        ALOGW("blkid failed to identify %s", mDevPath.c_str());
        return -ENODATA;
    }

    pclose(fp);

    // TODO: broadcast ident to framework
    return OK;
}

status_t PublicVolume::initAsecStage() {
    std::string legacyPath(mRawPath + "/android_secure");
    std::string securePath(mRawPath + "/.android_secure");

    // Recover legacy secure path
    if (!access(legacyPath.c_str(), R_OK | X_OK)
            && access(securePath.c_str(), R_OK | X_OK)) {
        if (rename(legacyPath.c_str(), securePath.c_str())) {
            SLOGE("Failed to rename legacy ASEC dir: %s", strerror(errno));
        }
    }

    if (fs_prepare_dir(securePath.c_str(), 0770, AID_MEDIA_RW, AID_MEDIA_RW) != 0) {
        SLOGW("fs_prepare_dir failed: %s", strerror(errno));
        return -errno;
    }

    return OK;
}

status_t PublicVolume::doMount() {
    if (Fat::check(mDevPath.c_str())) {
        SLOGE("Failed filesystem check; not mounting");
        return -EIO;
    }

    if (fs_prepare_dir(mRawPath.c_str(), 0770, AID_MEDIA_RW, AID_MEDIA_RW)) {
        SLOGE("Failed to create mount point %s: %s", mRawPath.c_str(), strerror(errno));
        return -errno;
    }
    if (fs_prepare_dir(mFusePath.c_str(), 0770, AID_MEDIA_RW, AID_MEDIA_RW)) {
        SLOGE("Failed to create mount point %s: %s", mFusePath.c_str(), strerror(errno));
        return -errno;
    }

    if (Fat::doMount(mDevPath.c_str(), mRawPath.c_str(), false, false, false,
            AID_MEDIA_RW, AID_MEDIA_RW, 0007, true)) {
        SLOGE("Failed to mount %s: %s", mDevPath.c_str(), strerror(errno));
        return -EIO;
    }

    if (!(mFusePid = fork())) {
        if (mPrimary) {
            if (execl(kFusePath,
                    "-u", "1023", // AID_MEDIA_RW
                    "-g", "1023", // AID_MEDIA_RW
                    "-d",
                    mRawPath.c_str(),
                    mFusePath.c_str())) {
                SLOGE("Failed to exec: %s", strerror(errno));
            }
        } else {
            if (execl(kFusePath,
                    "-u", "1023", // AID_MEDIA_RW
                    "-g", "1023", // AID_MEDIA_RW
                    "-w", "1023", // AID_MEDIA_RW
                    "-d",
                    mRawPath.c_str(),
                    mFusePath.c_str())) {
                SLOGE("Failed to exec: %s", strerror(errno));
            }
        }

        _exit(1);
    }

    if (mFusePid == -1) {
        SLOGE("Failed to fork: %s", strerror(errno));
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

    TEMP_FAILURE_RETRY(unlink(mRawPath.c_str()));
    TEMP_FAILURE_RETRY(unlink(mFusePath.c_str()));

    return OK;
}

status_t PublicVolume::doFormat() {
    if (Fat::format(mDevPath.c_str(), 0, true)) {
        SLOGE("Failed to format: %s", strerror(errno));
        return -errno;
    }
    return OK;
}

status_t PublicVolume::bindUser(userid_t user) {
    return bindUserInternal(user, true);
}

status_t PublicVolume::unbindUser(userid_t user) {
    return bindUserInternal(user, false);
}

status_t PublicVolume::bindUserInternal(userid_t user, bool bind) {
    if (mPrimary) {
        if (user == 0) {
            std::string path(StringPrintf("%s/%ud/primary", kUserMountPath, user));
            if (bind) {
                mountBind(mFusePath, path);
            } else {
                unmountBind(path);
            }
        } else {
            // Public volumes are only visible to owner when primary
            // storage, so we don't mount for secondary users.
        }
    } else {
        std::string path(StringPrintf("%s/%ud/public_%ud:%ud", kUserMountPath, user,
                        major(mDevice), minor(mDevice)));
        if (bind) {
            mountBind(mFusePath, path);
        } else {
            unmountBind(path);
        }

        if (user != 0) {
            // To prevent information leakage between users, only owner
            // has access to the Android directory
            path += "/Android";
            if (bind) {
                if (::mount("tmpfs", path.c_str(), "tmpfs", MS_NOSUID, "mode=0000")) {
                    SLOGE("Failed to protect secondary path %s: %s",
                            path.c_str(), strerror(errno));
                    return -errno;
                }
            } else {
                ForceUnmount(path);
            }
        }
    }

    return OK;
}

void PublicVolume::setPrimary(bool primary) {
    if (getState() != VolumeState::kUnmounted) {
        SLOGE("Primary state change requires %s to be unmounted", getId().c_str());
        return;
    }

    mPrimary = primary;
}

}  // namespace vold
}  // namespace android
