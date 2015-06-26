/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include "TrimTask.h"
#include "Benchmark.h"
#include "Utils.h"
#include "VolumeManager.h"
#include "ResponseCode.h"

#include <base/stringprintf.h>
#include <base/logging.h>
#include <cutils/properties.h>
#include <fs_mgr.h>
#include <private/android_filesystem_config.h>
#include <hardware_legacy/power.h>

#include <dirent.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>

/* From a would-be kernel header */
#define FIDTRIM         _IOWR('f', 128, struct fstrim_range)    /* Deep discard trim */

#define BENCHMARK_ENABLED 0

using android::base::StringPrintf;

namespace android {
namespace vold {

static const char* kWakeLock = "TrimTask";

TrimTask::TrimTask(int flags) : mFlags(flags) {
    // Collect both fstab and vold volumes
    addFromFstab();

    VolumeManager* vm = VolumeManager::Instance();
    std::list<std::string> privateIds;
    vm->listVolumes(VolumeBase::Type::kPrivate, privateIds);
    for (auto id : privateIds) {
        auto vol = vm->findVolume(id);
        if (vol != nullptr && vol->getState() == VolumeBase::State::kMounted) {
            mPaths.push_back(vol->getPath());
        }
    }
}

TrimTask::~TrimTask() {
}

void TrimTask::addFromFstab() {
    struct fstab *fstab;
    struct fstab_rec *prev_rec = NULL;

    fstab = fs_mgr_read_fstab(android::vold::DefaultFstabPath().c_str());
    for (int i = 0; i < fstab->num_entries; i++) {
        /* Skip raw partitions */
        if (!strcmp(fstab->recs[i].fs_type, "emmc") ||
            !strcmp(fstab->recs[i].fs_type, "mtd")) {
            continue;
        }
        /* Skip read-only filesystems */
        if (fstab->recs[i].flags & MS_RDONLY) {
            continue;
        }
        if (fs_mgr_is_voldmanaged(&fstab->recs[i])) {
            continue; /* Should we trim fat32 filesystems? */
        }
        if (fs_mgr_is_notrim(&fstab->recs[i])) {
            continue;
        }

        /* Skip the multi-type partitions, which are required to be following each other.
         * See fs_mgr.c's mount_with_alternatives().
         */
        if (prev_rec && !strcmp(prev_rec->mount_point, fstab->recs[i].mount_point)) {
            continue;
        }

        mPaths.push_back(fstab->recs[i].mount_point);
        prev_rec = &fstab->recs[i];
    }
    fs_mgr_free_fstab(fstab);
}

void TrimTask::start() {
    mThread = std::thread(&TrimTask::run, this);
}

static void notifyResult(const std::string& path, int64_t bytes, int64_t delta) {
    std::string res(path
            + " " + std::to_string(bytes)
            + " " + std::to_string(delta));
    VolumeManager::Instance()->getBroadcaster()->sendBroadcast(
            ResponseCode::TrimResult, res.c_str(), false);
}

void TrimTask::run() {
    acquire_wake_lock(PARTIAL_WAKE_LOCK, kWakeLock);

    for (auto path : mPaths) {
        LOG(DEBUG) << "Starting trim of " << path;

        int fd = open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) {
            PLOG(WARNING) << "Failed to open " << path;
            continue;
        }

        struct fstrim_range range;
        memset(&range, 0, sizeof(range));
        range.len = ULLONG_MAX;

        nsecs_t start = systemTime(SYSTEM_TIME_BOOTTIME);
        if (ioctl(fd, (mFlags & Flags::kDeepTrim) ? FIDTRIM : FITRIM, &range)) {
            PLOG(WARNING) << "Trim failed on " << path;
            notifyResult(path, -1, -1);
        } else {
            nsecs_t delta = systemTime(SYSTEM_TIME_BOOTTIME) - start;
            LOG(INFO) << "Trimmed " << range.len << " bytes on " << path
                    << " in " << nanoseconds_to_milliseconds(delta) << "ms";
            notifyResult(path, range.len, delta);
        }
        close(fd);

        if (mFlags & Flags::kBenchmarkAfter) {
#if BENCHMARK_ENABLED
            BenchmarkPrivate(path);
#else
            LOG(DEBUG) << "Benchmark disabled";
#endif
        }
    }

    release_wake_lock(kWakeLock);
}

}  // namespace vold
}  // namespace android
