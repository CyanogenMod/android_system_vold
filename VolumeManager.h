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

#include "Volume.h"

typedef android::List<char *> AsecIdCollection;

class VolumeManager {
private:
    static VolumeManager *sInstance;

private:
    SocketListener        *mBroadcaster;

    VolumeCollection      *mVolumes;
    AsecIdCollection      *mActiveContainers;
    bool                   mUsbMassStorageConnected;
    bool                   mDebug;

public:
    virtual ~VolumeManager();

    int start();
    int stop();

    void handleBlockEvent(NetlinkEvent *evt);
    void handleSwitchEvent(NetlinkEvent *evt);

    int addVolume(Volume *v);

    int listVolumes(SocketClient *cli);
    int mountVolume(const char *label);
    int unmountVolume(const char *label, bool force);
    int shareVolume(const char *label, const char *method);
    int unshareVolume(const char *label, const char *method);
    int shareAvailable(const char *method, bool *avail);
    int shareEnabled(const char *path, const char *method, bool *enabled);
    int simulate(const char *cmd, const char *arg);
    int formatVolume(const char *label);
    int createAsec(const char *id, unsigned numSectors, const char *fstype,
                   const char *key, int ownerUid);
    int finalizeAsec(const char *id);
    int destroyAsec(const char *id, bool force);
    int mountAsec(const char *id, const char *key, int ownerUid);
    int unmountAsec(const char *id, bool force);
    int renameAsec(const char *id1, const char *id2);
    int getAsecMountPath(const char *id, char *buffer, int maxlen);

    void setDebug(bool enable);

    // XXX: This should be moved private once switch uevents are working
    void notifyUmsConnected(bool connected);
    // XXX: Post froyo this should be moved and cleaned up
    int cleanupAsec(Volume *v, bool force);

    void setBroadcaster(SocketListener *sl) { mBroadcaster = sl; }
    SocketListener *getBroadcaster() { return mBroadcaster; }

    static VolumeManager *Instance();

    static char *asecHash(const char *id, char *buffer, size_t len);

private:
    VolumeManager();
    Volume *lookupVolume(const char *label);
    bool isMountpointMounted(const char *mp);
};
#endif
