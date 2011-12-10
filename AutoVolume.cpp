/*
 * Copyright (C) 2010 The Android-x86 Open Source Project
 *
 * Author: Chih-Wei Huang <cwhuang@linux.org.tw>
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

#define LOG_TAG "AutoVolume"

#include <dirent.h>
#include <stdlib.h>

#include <cutils/log.h>
#include <sysutils/NetlinkEvent.h>

#include "Fat.h"
#include "Loop.h"
#include "AutoVolume.h"

AutoVolume::AutoVolume(VolumeManager *vm, const char *label, const char *mount_point, const char *sdcard)
          : DirectVolume(vm, label, mount_point, -1), mSdcard(0)
{
    if (sdcard && *sdcard) {
        if (strncmp(sdcard, "/dev/", 5) && !access(sdcard, F_OK)) {
            char loopdev[256];
            if (!Loop::create(label, sdcard, loopdev, sizeof(loopdev)))
                sdcard = loopdev;
        } else if (!strcmp(sdcard, "ramdisk")) {
            // FIXME: do not hardcode ramdisk device
            const char *ramdisk = "/dev/block/ram1";
            Fat::format(ramdisk, 0);
            sdcard = ramdisk;
        }
        if (const char *d = strrchr(sdcard, '/'))
            sdcard = ++d;
        else if (!strcmp(sdcard, "premount"))
            setState(State_Idle);
        mSdcard = strdup(sdcard);
    }
}

AutoVolume::~AutoVolume()
{
    free(mSdcard);
}

static bool isExternalStorage(const char *dir, const char *syspath)
{
    bool ret = false;
    if (DIR *d = opendir(dir)) {
        while (struct dirent *e = readdir(d)) {
            char buf[256];
            if (e->d_name[0] != '.' &&
                    strcmp(e->d_name, "module") && strcmp(e->d_name, "uevent") &&
                    strcmp(e->d_name, "unbind") && strcmp(e->d_name, "bind") &&
                    strcmp(e->d_name, "new_id") && strcmp(e->d_name, "remove_id")) {
                char p[256];
                snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
                ssize_t sz = readlink(p, buf, sizeof(buf));
                // skip the beginning "../../../.."
                if (sz > 11 && !strncmp(buf + 11, syspath, sz - 11)) {
                    ret = true;
                    break;
                }
            }
        }
        closedir(d);
    }
    return ret;
}

int AutoVolume::handleBlockEvent(NetlinkEvent *evt)
{
    if (evt->getAction() == NetlinkEvent::NlActionAdd) {
        const char *dt = evt->findParam("DEVTYPE");
        const char *dp = evt->findParam("DEVPATH");
        bool isdisk = !strcmp(dt, "disk");
        if (mSdcard) {
            if (const char *d = strrchr(dp, '/')) {
                int ret = strcmp(++d, mSdcard);
                if (isdisk) {
                    if (ret) {
                        char p[256];
                        snprintf(p, sizeof(p), "/sys%s/%s", dp, mSdcard);
                        ret = access(p, F_OK);
                    }
                    if (!ret)
                        addPath(dp);
                } else {
                    if (!ret) {
                        const char *t = evt->findParam("PARTN");
                        mPartIdx = t ? atoi(t) : 1;
                    }
                }
            }
        } else {
            if (isdisk) {
                const char *storages[] = {
                    "/sys/bus/mmc/drivers/mmcblk",      // MMC block device
                    "/sys/bus/usb/drivers/usb-storage", // USB Mass Storage
                };

                size_t i = 0;
                while (i < sizeof(storages) / sizeof(const char *)) {
                    if (isExternalStorage(storages[i++], dp)) {
                        addPath(dp);
                        break;
                    }
                }
            }
        }
    }

    return DirectVolume::handleBlockEvent(evt);
}
