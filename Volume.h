/*
 * Copyright (C) 2008 The Android Open Source Project
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

#ifndef _VOLUME_H
#define _VOLUME_H

#include <utils/List.h>

class NetlinkEvent;
class VolumeManager;

class Volume {
private:
    int mState;

public:
    static const int State_Init       = -1;
    static const int State_NoMedia    = 0;
    static const int State_Idle       = 1;
    static const int State_Pending    = 2;
    static const int State_Checking   = 3;
    static const int State_Mounted    = 4;
    static const int State_Unmounting = 5;
    static const int State_Formatting = 6;
    static const int State_Shared     = 7;
    static const int State_SharedMnt  = 8;

protected:
    char *mLabel;
    char *mMountpoint;
    VolumeManager *mVm;

    /*
     * The major/minor tuple of the currently mounted filesystem.
     */
    dev_t mCurrentlyMountedKdev;

public:
    Volume(VolumeManager *vm, const char *label, const char *mount_point);
    virtual ~Volume();

    int mountVol();
    int unmountVol();
    int formatVol();

    const char *getLabel() { return mLabel; }
    const char *getMountpoint() { return mMountpoint; }
    int getState() { return mState; }

    virtual int handleBlockEvent(NetlinkEvent *evt);
    virtual dev_t getDiskDevice();
    virtual void handleVolumeShared();
    virtual void handleVolumeUnshared();

protected:
    void setState(int state);

    virtual int getDeviceNodes(dev_t *devs, int max) = 0;

    int createDeviceNode(const char *path, int major, int minor);

private:
    int checkFilesystem(const char *nodepath);
    int doMountVfat(const char *deviceNode, const char *mountPoint);
    int doFormatVfat(const char *deviceNode);
    int initializeMbr(const char *deviceNode);
    bool isMountpointMounted(const char *path);
};

typedef android::List<Volume *> VolumeCollection;

#endif
