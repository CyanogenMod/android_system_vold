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

#ifndef _DEVICEVOLUME_H
#define _DEVICEVOLUME_H

#include <utils/List.h>

#include "Volume.h"

#ifndef VOLD_MAX_PARTITIONS
#define VOLD_MAX_PARTITIONS 4
#endif

typedef android::List<char *> PathCollection;

class DirectVolume : public Volume {
public:
    static const int MAX_PARTITIONS = VOLD_MAX_PARTITIONS;

protected:
    PathCollection *mPaths;
    int            mDiskMajor;
    int            mDiskMinor;
    int            mPartMinors[MAX_PARTITIONS];
    int            mOrigDiskMajor;
    int            mOrigDiskMinor;
    int            mOrigPartMinors[MAX_PARTITIONS];
    int            mDiskNumParts;
    unsigned char  mPendingPartMap;
    int            mIsDecrypted;
    int            mFlags;

#ifdef VOLD_DISC_HAS_MULTIPLE_MAJORS
private:
    struct ValuePair {
        int major;
        int part_num;
    };

    android::List<ValuePair> badPartitions;
#endif

public:
    DirectVolume(VolumeManager *vm, const char *label, const char *mount_point, int partIdx);
    virtual ~DirectVolume();

    int addPath(const char *path);

    int handleBlockEvent(NetlinkEvent *evt);
    dev_t getDiskDevice();
    dev_t getShareDevice();
    void handleVolumeShared();
    void handleVolumeUnshared();
    int getVolInfo(struct volume_info *v);
    void setFlags(int flags);

protected:
    int getDeviceNodes(dev_t *devs, int max);
    int updateDeviceInfo(char *new_path, int new_major, int new_minor);
    virtual void revertDeviceInfo(void);
    int isDecrypted() { return mIsDecrypted; }
    int getFlags() { return mFlags; }

private:
    void handleDiskAdded(const char *devpath, NetlinkEvent *evt);
    void handleDiskRemoved(const char *devpath, NetlinkEvent *evt);
    void handleDiskChanged(const char *devpath, NetlinkEvent *evt);
    void handlePartitionAdded(const char *devpath, NetlinkEvent *evt);
    void handlePartitionRemoved(const char *devpath, NetlinkEvent *evt);
    void handlePartitionChanged(const char *devpath, NetlinkEvent *evt);

    int doMountVfat(const char *deviceNode, const char *mountPoint);
#ifdef VOLD_DISC_HAS_MULTIPLE_MAJORS
    int getMajorNumberForBadPartition(int part_num);
#endif

};

typedef android::List<DirectVolume *> DirectVolumeCollection;

#endif
