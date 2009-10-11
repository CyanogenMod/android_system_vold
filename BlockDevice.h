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

#ifndef _BLKDEVICE_H
#define _BLKDEVICE_H

#include <utils/List.h>

class BlockDevice {

    char *mDevpath;
    int mMajor;
    int mMinor;

public:
    BlockDevice(const char *devpath, int major, int minor);
    virtual ~BlockDevice();

    const char *getDevpath() { return mDevpath; }
    int getMajor() { return mMajor; }
    int getMinor() { return mMinor; }
};

typedef android::List<BlockDevice *> BlockDeviceCollection;

#endif
