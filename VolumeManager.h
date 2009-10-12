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

#ifndef _VOLUMEMANAGER_H
#define _VOLUMEMANAGER_H

#include <pthread.h>

#include <utils/List.h>
#include <sysutils/SocketListener.h>

#include "BlockDevice.h"
#include "Volume.h"

class VolumeManager {
private:
    static VolumeManager *sInstance;

private:
    SocketListener        *mBroadcaster;
    BlockDeviceCollection *mBlockDevices;

    VolumeCollection      *mVolumes;

public:
    virtual ~VolumeManager();

    int start();
    int stop();

    void handleBlockEvent(NetlinkEvent *evt);

    int addVolume(Volume *v);

    int listVolumes(SocketClient *cli);
    int mountVolume(const char *label);
    int unmountVolume(const char *label);

    void setBroadcaster(SocketListener *sl) { mBroadcaster = sl; }
    SocketListener *getBroadcaster() { return mBroadcaster; }

    static VolumeManager *Instance();

private:
    VolumeManager();
    Volume *lookupVolume(const char *label);
};
#endif
