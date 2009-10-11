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
#include <errno.h>

#define LOG_TAG "Vold"

#include <cutils/log.h>

#include "VolumeManager.h"
#include "DeviceVolume.h"
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

void VolumeManager::handleDiskInserted(const char *devpath, int maj, int min,
                                       int nr_parts) {

    /* Lookup possible candidate DeviceVolumes */
    VolumeCollection::iterator it;
    bool hit = false;
    for (it = mVolumes->begin(); it != mVolumes->end(); ++it) {
        if (!(*it)->handleDiskInsertion(devpath, maj, min, nr_parts)) {
            hit = true;
            LOGD("Volume '%s' has handled disk insertion for '%s'",
                 (*it)->getLabel(), devpath);
            break;
        }
    }

    if (!hit) {
        LOGW("No volumes handled insertion of disk '%s'", devpath);
    }
}

void VolumeManager::handleDiskRemoved(int maj, int min) {
}

void VolumeManager::handlePartCreated(const char *devpath, int maj, int min,
                                      int part_no) {
}

void VolumeManager::handlePartRemoved(int maj, int min) {
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
    cli->sendMsg(ErrorCode::CommandOkay, "Volumes Listed", false);
    return 0;
}
