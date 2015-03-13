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

#ifndef ANDROID_VOLD_PUBLIC_VOLUME_H
#define ANDROID_VOLD_PUBLIC_VOLUME_H

#include "VolumeBase.h"

#include <cutils/multiuser.h>

namespace android {
namespace vold {

/*
 * Shared storage provided by public (vfat) partition.
 *
 * Knows how to mount itself and then spawn a FUSE daemon to synthesize
 * permissions.  AsecVolume and ObbVolume can be stacked above it.
 *
 * This volume is not inherently multi-user aware, so it has two possible
 * modes of operation:
 * 1. If primary storage for the device, it only binds itself to the
 * owner user.
 * 2. If secondary storage, it binds itself for all users, but masks
 * away the Android directory for secondary users.
 */
class PublicVolume : public VolumeBase {
public:
    explicit PublicVolume(dev_t device);
    virtual ~PublicVolume();

    status_t readMetadata();
    status_t initAsecStage();

    void setPrimary(bool primary);
    bool getPrimary() { return mPrimary; }

    const std::string& getFsUuid() { return mFsUuid; }
    const std::string& getFsLabel() { return mFsLabel; }

    status_t bindUser(userid_t user);
    status_t unbindUser(userid_t user);

protected:
    status_t doMount();
    status_t doUnmount();
    status_t doFormat();

    status_t bindUserInternal(userid_t user, bool bind);

private:
    /* Kernel device representing partition */
    dev_t mDevice;
    /* Block device path */
    std::string mDevPath;
    /* Mount point of raw partition */
    std::string mRawPath;
    /* Mount point of FUSE wrapper */
    std::string mFusePath;
    /* PID of FUSE wrapper */
    pid_t mFusePid;
    /* Flag indicating this is primary storage */
    bool mPrimary;

    /* Parsed UUID from filesystem */
    std::string mFsUuid;
    /* User-visible label from filesystem */
    std::string mFsLabel;

    DISALLOW_COPY_AND_ASSIGN(PublicVolume);
};

}  // namespace vold
}  // namespace android

#endif
