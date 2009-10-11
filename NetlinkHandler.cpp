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
#include <errno.h>

#define LOG_TAG "Vold"

#include <cutils/log.h>

#include <sysutils/NetlinkEvent.h>
#include "NetlinkHandler.h"
#include "VolumeManager.h"

NetlinkHandler::NetlinkHandler(int listenerSocket) :
                NetlinkListener(listenerSocket) {
}

NetlinkHandler::~NetlinkHandler() {
}

int NetlinkHandler::start() {
    return this->startListener();
}

int NetlinkHandler::stop() {
    return this->stopListener();
}

void NetlinkHandler::onEvent(NetlinkEvent *evt) {
    VolumeManager *vm = VolumeManager::Instance();
    const char *subsys = evt->getSubsystem();
    int action = evt->getAction();

    if (!subsys) {
        LOGW("No subsystem found in netlink event");
        return;
    }

    if (!strcmp(subsys, "block")) {
        const char *devpath = evt->findParam("DEVPATH");
        const char *devtype = evt->findParam("DEVTYPE");
        int major = atoi(evt->findParam("MAJOR"));
        int minor = atoi(evt->findParam("MINOR"));

        LOGI("Block event %d, type %s, %d:%d, path '%s'", action, devtype, major, minor, devpath);

        if (!strcmp(devtype, "disk")) {
            const char *tmp = evt->findParam("NPARTS");

            if (!tmp) {
                LOGE("Disk uevent missing 'NPARTS' parameter");
                return;
            }
            if (action == NetlinkEvent::NlActionAdd)
                vm->handleDiskInserted(devpath, major, minor, atoi(tmp));
            else if (action == NetlinkEvent::NlActionRemove)
                vm->handleDiskRemoved(major, minor);
        } else {
            const char *tmp = evt->findParam("PARTN");

            if (!tmp) {
                LOGE("Partition uevent missing 'PARTN' parameter");
                return;
            }
            if (action == NetlinkEvent::NlActionAdd)
                vm->handlePartCreated(devpath, major, minor, atoi(tmp));
            else if (action == NetlinkEvent::NlActionRemove)
                vm->handlePartRemoved(major, minor);
        }
        LOGD("Block event handled");
    } else if (!strcmp(subsys, "battery")) {
    } else if (!strcmp(subsys, "power_supply")) {
    } else {
        LOGE("Dropping %s netlink event", subsys);
    }
}
