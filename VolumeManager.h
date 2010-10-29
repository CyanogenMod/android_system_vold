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

/* The length of an MD5 hash when encoded into ASCII hex characters */
#define MD5_ASCII_LENGTH_PLUS_NULL ((MD5_DIGEST_LENGTH*2)+1)

typedef enum { ASEC, OBB } container_type_t;

class ContainerData {
public:
    ContainerData(char* _id, container_type_t _type)
            : id(_id)
            , type(_type)
    {}

    ~ContainerData() {
        if (id != NULL) {
            free(id);
            id = NULL;
        }
    }

    char *id;
    container_type_t type;
};

typedef android::List<ContainerData*> AsecIdCollection;

class VolumeManager {
private:
    static VolumeManager *sInstance;

private:
    SocketListener        *mBroadcaster;

    VolumeCollection      *mVolumes;
    AsecIdCollection      *mActiveContainers;
    bool                   mUsbMassStorageEnabled;
    bool                   mUsbConnected;
    bool                   mDebug;

    // for adjusting /proc/sys/vm/dirty_ratio when UMS is active
    int                    mUmsSharingCount;
    int                    mSavedDirtyRatio;
    int                    mUmsDirtyRatio;

public:
    virtual ~VolumeManager();

    int start();
    int stop();

    void handleBlockEvent(NetlinkEvent *evt);
    void handleSwitchEvent(NetlinkEvent *evt);
    void handleUsbCompositeEvent(NetlinkEvent *evt);

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

    /* ASEC */
    int createAsec(const char *id, unsigned numSectors, const char *fstype,
                   const char *key, int ownerUid);
    int finalizeAsec(const char *id);
    int destroyAsec(const char *id, bool force);
    int mountAsec(const char *id, const char *key, int ownerUid);
    int unmountAsec(const char *id, bool force);
    int renameAsec(const char *id1, const char *id2);
    int getAsecMountPath(const char *id, char *buffer, int maxlen);

    /* Loopback images */
    int listMountedObbs(SocketClient* cli);
    int mountObb(const char *fileName, const char *key, int ownerUid);
    int unmountObb(const char *fileName, bool force);
    int getObbMountPath(const char *id, char *buffer, int maxlen);

    /* Shared between ASEC and Loopback images */
    int unmountLoopImage(const char *containerId, const char *loopId,
            const char *fileName, const char *mountPoint, bool force);

    void setDebug(bool enable);

    // XXX: Post froyo this should be moved and cleaned up
    int cleanupAsec(Volume *v, bool force);

    void setBroadcaster(SocketListener *sl) { mBroadcaster = sl; }
    SocketListener *getBroadcaster() { return mBroadcaster; }

    static VolumeManager *Instance();

    static char *asecHash(const char *id, char *buffer, size_t len);

private:
    VolumeManager();
    void readInitialState();
    Volume *lookupVolume(const char *label);
    bool isMountpointMounted(const char *mp);

    inline bool massStorageAvailable() const { return mUsbMassStorageEnabled && mUsbConnected; }
    void notifyUmsAvailable(bool available);
};
#endif
