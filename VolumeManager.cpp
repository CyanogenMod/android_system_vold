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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define LOG_TAG "Vold"

#include <cutils/log.h>

#include <sysutils/NetlinkEvent.h>

#include "VolumeManager.h"
#include "DirectVolume.h"
#include "ErrorCode.h"

VolumeManager *VolumeManager::sInstance = NULL;

VolumeManager *VolumeManager::Instance() {
    if (!sInstance)
        sInstance = new VolumeManager();
    return sInstance;
}

VolumeManager::VolumeManager() {
    mBlockDevices = new BlockDeviceCollection();
    mVolumes = new VolumeCollection();
    mBroadcaster = NULL;
}

VolumeManager::~VolumeManager() {
    delete mBlockDevices;
}

int VolumeManager::start() {
    return 0;
}

int VolumeManager::stop() {
    return 0;
}

int VolumeManager::addVolume(Volume *v) {
    mVolumes->push_back(v);
    return 0;
}

void VolumeManager::handleBlockEvent(NetlinkEvent *evt) {
    const char *devpath = evt->findParam("DEVPATH");

    /* Lookup a volume to handle this device */
    VolumeCollection::iterator it;
    bool hit = false;
    for (it = mVolumes->begin(); it != mVolumes->end(); ++it) {
        if (!(*it)->handleBlockEvent(evt)) {
            hit = true;
            break;
        }
    }

    if (!hit) {
        LOGW("No volumes handled block event for '%s'", devpath);
    }
}

int VolumeManager::listVolumes(SocketClient *cli) {
    VolumeCollection::iterator i;

    for (i = mVolumes->begin(); i != mVolumes->end(); ++i) {
        char *buffer;
        asprintf(&buffer, "%s %s %d",
                 (*i)->getLabel(), (*i)->getMountpoint(),
                 (*i)->getState());
        cli->sendMsg(ErrorCode::VolumeListResult, buffer, false);
        free(buffer);
    }
    cli->sendMsg(ErrorCode::CommandOkay, "Volumes listed.", false);
    return 0;
}

int VolumeManager::mountVolume(const char *label) {
    Volume *v = lookupVolume(label);

    if (!v) {
        errno = ENOENT;
        return -1;
    }

    if (v->getState() != Volume::State_Idle) {
        errno = EBUSY;
        return -1;
    }

    return v->mount();
}

int VolumeManager::unmountVolume(const char *label) {
    Volume *v = lookupVolume(label);

    if (!v) {
        errno = ENOENT;
        return -1;
    }

    if (v->getState() != Volume::State_Mounted) {
        errno = EBUSY;
        return -1;
    }

    return v->unmount();
}

Volume *VolumeManager::lookupVolume(const char *label) {
    VolumeCollection::iterator i;

    for (i = mVolumes->begin(); i != mVolumes->end(); ++i) {
        if (!strcmp(label, (*i)->getLabel()))
            return (*i);
    }
    return NULL;
}
