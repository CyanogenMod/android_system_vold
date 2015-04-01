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
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <getopt.h>

#include <fcntl.h>
#include <dirent.h>
#include <fs_mgr.h>

#define LOG_TAG "Vold"

#include <base/logging.h>
#include <base/stringprintf.h>
#include "cutils/klog.h"
#include "cutils/log.h"
#include "cutils/properties.h"

#include "Disk.h"
#include "VolumeManager.h"
#include "CommandListener.h"
#include "NetlinkManager.h"
#include "DirectVolume.h"
#include "cryptfs.h"
#include "sehandle.h"

static int process_config(VolumeManager *vm);
static void coldboot(const char *path);
static void parse_args(int argc, char** argv);

//#define DEBUG_FSTAB "/data/local/tmp/fstab.debug"

struct fstab *fstab;

struct selabel_handle *sehandle;

using android::base::StringPrintf;

int main(int argc, char** argv) {
    SLOGI("Vold 2.1 (the revenge) firing up");

    setenv("ANDROID_LOG_TAGS", "*:v", 1);
    android::base::InitLogging(argv);

    VolumeManager *vm;
    CommandListener *cl;
    NetlinkManager *nm;

    parse_args(argc, argv);

    sehandle = selinux_android_file_context_handle();
    if (sehandle) {
        selinux_android_set_sehandle(sehandle);
    }

    mkdir("/dev/block/vold", 0755);

    /* For when cryptfs checks and mounts an encrypted filesystem */
    klog_set_level(6);

    /* Create our singleton managers */
    if (!(vm = VolumeManager::Instance())) {
        SLOGE("Unable to create VolumeManager");
        exit(1);
    }

    if (!(nm = NetlinkManager::Instance())) {
        SLOGE("Unable to create NetlinkManager");
        exit(1);
    }

    cl = new CommandListener();
    vm->setBroadcaster((SocketListener *) cl);
    nm->setBroadcaster((SocketListener *) cl);

    if (vm->start()) {
        SLOGE("Unable to start VolumeManager (%s)", strerror(errno));
        exit(1);
    }

    if (process_config(vm)) {
        SLOGE("Error reading configuration (%s)... continuing anyways", strerror(errno));
    }

    if (nm->start()) {
        SLOGE("Unable to start NetlinkManager (%s)", strerror(errno));
        exit(1);
    }

    coldboot("/sys/block");
//    coldboot("/sys/class/switch");

    /*
     * Now that we're up, we can respond to commands
     */
    if (cl->startListener()) {
        SLOGE("Unable to start CommandListener (%s)", strerror(errno));
        exit(1);
    }

    // Eventually we'll become the monitoring thread
    while(1) {
        sleep(1000);
    }

    SLOGI("Vold exiting");
    exit(0);
}

static void parse_args(int argc, char** argv) {
    static struct option opts[] = {
        {"blkid_context", required_argument, 0, 'b' },
        {"blkid_untrusted_context", required_argument, 0, 'B' },
        {"fsck_context", required_argument, 0, 'f' },
        {"fsck_untrusted_context", required_argument, 0, 'F' },
    };

    int c;
    while ((c = getopt_long(argc, argv, "", opts, nullptr)) != -1) {
        switch (c) {
        case 'b': android::vold::sBlkidContext = optarg; break;
        case 'B': android::vold::sBlkidUntrustedContext = optarg; break;
        case 'f': android::vold::sFsckContext = optarg; break;
        case 'F': android::vold::sFsckUntrustedContext = optarg; break;
        }
    }

    CHECK(android::vold::sBlkidContext != nullptr);
    CHECK(android::vold::sBlkidUntrustedContext != nullptr);
    CHECK(android::vold::sFsckContext != nullptr);
    CHECK(android::vold::sFsckUntrustedContext != nullptr);
}

static void do_coldboot(DIR *d, int lvl) {
    struct dirent *de;
    int dfd, fd;

    dfd = dirfd(d);

    fd = openat(dfd, "uevent", O_WRONLY);
    if(fd >= 0) {
        write(fd, "add\n", 4);
        close(fd);
    }

    while((de = readdir(d))) {
        DIR *d2;

        if (de->d_name[0] == '.')
            continue;

        if (de->d_type != DT_DIR && lvl > 0)
            continue;

        fd = openat(dfd, de->d_name, O_RDONLY | O_DIRECTORY);
        if(fd < 0)
            continue;

        d2 = fdopendir(fd);
        if(d2 == 0)
            close(fd);
        else {
            do_coldboot(d2, lvl + 1);
            closedir(d2);
        }
    }
}

static void coldboot(const char *path) {
    DIR *d = opendir(path);
    if(d) {
        do_coldboot(d, 0);
        closedir(d);
    }
}

static int process_config(VolumeManager *vm) {
    char hardware[PROPERTY_VALUE_MAX];
    property_get("ro.hardware", hardware, "");
    std::string fstab_filename(StringPrintf("/fstab.%s", hardware));

#ifdef DEBUG_FSTAB
    if (access(DEBUG_FSTAB, R_OK) == 0) {
        LOG(DEBUG) << "Found debug fstab; switching!";
        fstab_filename = DEBUG_FSTAB;
    }
#endif

    fstab = fs_mgr_read_fstab(fstab_filename.c_str());
    if (!fstab) {
        PLOG(ERROR) << "Failed to open " << fstab_filename;
        return -1;
    }

    /* Loop through entries looking for ones that vold manages */
    for (int i = 0; i < fstab->num_entries; i++) {
        if (fs_mgr_is_voldmanaged(&fstab->recs[i])) {
            if (fs_mgr_is_nonremovable(&fstab->recs[i])) {
                LOG(WARNING) << "nonremovable no longer supported; ignoring volume";
                continue;
            }

            std::string sysPattern(fstab->recs[i].blk_device);
            std::string nickname(fstab->recs[i].label);
            int flags = 0;

            if (fs_mgr_is_encryptable(&fstab->recs[i])) {
                flags |= android::vold::Disk::Flags::kAdoptable;
            }
            if (fs_mgr_is_noemulatedsd(&fstab->recs[i])) {
                flags |= android::vold::Disk::Flags::kDefaultPrimary;
            }

            vm->addDiskSource(std::shared_ptr<VolumeManager::DiskSource>(
                    new VolumeManager::DiskSource(sysPattern, nickname, flags)));
        }
    }

    return 0;
}
