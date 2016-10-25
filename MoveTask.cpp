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

#include "MoveTask.h"
#include "Utils.h"
#include "VolumeManager.h"
#include "ResponseCode.h"

#include <android-base/stringprintf.h>
#include <android-base/logging.h>
#include <private/android_filesystem_config.h>
#include <hardware_legacy/power.h>

#include <dirent.h>
#include <sys/wait.h>

#define CONSTRAIN(amount, low, high) (amount < low ? low : (amount > high ? high : amount))

using android::base::StringPrintf;

namespace android {
namespace vold {

// TODO: keep in sync with PackageManager
static const int kMoveSucceeded = -100;
static const int kMoveFailedInternalError = -6;

static const char* kCpPath = "/system/bin/cp";
static const char* kRmPath = "/system/bin/rm";

static const char* kWakeLock = "MoveTask";

MoveTask::MoveTask(const std::shared_ptr<VolumeBase>& from,
        const std::shared_ptr<VolumeBase>& to) :
        mFrom(from), mTo(to) {
}

MoveTask::~MoveTask() {
}

void MoveTask::start() {
    mThread = std::thread(&MoveTask::run, this);
}

static void notifyProgress(int progress) {
    VolumeManager::Instance()->getBroadcaster()->sendBroadcast(ResponseCode::MoveStatus,
            StringPrintf("%d", progress).c_str(), false);
}

static status_t pushBackContents(const std::string& path, std::vector<std::string>& cmd) {
    DIR* dir = opendir(path.c_str());
    if (dir == NULL) {
        return -1;
    }
    bool found = false;
    struct dirent* ent;
    while ((ent = readdir(dir)) != NULL) {
        if ((!strcmp(ent->d_name, ".")) || (!strcmp(ent->d_name, ".."))) {
            continue;
        }
        cmd.push_back(StringPrintf("%s/%s", path.c_str(), ent->d_name));
        found = true;
    }
    closedir(dir);
    return found ? OK : -1;
}

static status_t execRm(const std::string& path, int startProgress, int stepProgress) {
    notifyProgress(startProgress);

    uint64_t expectedBytes = GetTreeBytes(path);
    uint64_t startFreeBytes = GetFreeBytes(path);

    std::vector<std::string> cmd;
    cmd.push_back(kRmPath);
    cmd.push_back("-f"); /* force: remove without confirmation, no error if it doesn't exist */
    cmd.push_back("-R"); /* recursive: remove directory contents */
    if (pushBackContents(path, cmd) != OK) {
        LOG(WARNING) << "No contents in " << path;
        return OK;
    }

    pid_t pid = ForkExecvpAsync(cmd);
    if (pid == -1) return -1;

    int status;
    while (true) {
        if (waitpid(pid, &status, WNOHANG) == pid) {
            if (WIFEXITED(status)) {
                LOG(DEBUG) << "Finished rm with status " << WEXITSTATUS(status);
                return (WEXITSTATUS(status) == 0) ? OK : -1;
            } else {
                break;
            }
        }

        sleep(1);
        uint64_t deltaFreeBytes = GetFreeBytes(path) - startFreeBytes;
        notifyProgress(startProgress + CONSTRAIN((int)
                ((deltaFreeBytes * stepProgress) / expectedBytes), 0, stepProgress));
    }
    return -1;
}

static status_t execCp(const std::string& fromPath, const std::string& toPath,
        int startProgress, int stepProgress) {
    notifyProgress(startProgress);

    uint64_t expectedBytes = GetTreeBytes(fromPath);
    uint64_t startFreeBytes = GetFreeBytes(toPath);

    std::vector<std::string> cmd;
    cmd.push_back(kCpPath);
    cmd.push_back("-p"); /* preserve timestamps, ownership, and permissions */
    cmd.push_back("-R"); /* recurse into subdirectories (DEST must be a directory) */
    cmd.push_back("-P"); /* Do not follow symlinks [default] */
    cmd.push_back("-d"); /* don't dereference symlinks */
    if (pushBackContents(fromPath, cmd) != OK) {
        LOG(WARNING) << "No contents in " << fromPath;
        return OK;
    }
    cmd.push_back(toPath.c_str());

    pid_t pid = ForkExecvpAsync(cmd);
    if (pid == -1) return -1;

    int status;
    while (true) {
        if (waitpid(pid, &status, WNOHANG) == pid) {
            if (WIFEXITED(status)) {
                LOG(DEBUG) << "Finished cp with status " << WEXITSTATUS(status);
                return (WEXITSTATUS(status) == 0) ? OK : -1;
            } else {
                break;
            }
        }

        sleep(1);
        uint64_t deltaFreeBytes = startFreeBytes - GetFreeBytes(toPath);
        notifyProgress(startProgress + CONSTRAIN((int)
                ((deltaFreeBytes * stepProgress) / expectedBytes), 0, stepProgress));
    }
    return -1;
}

static void bringOffline(const std::shared_ptr<VolumeBase>& vol) {
    vol->destroy();
    vol->setSilent(true);
    vol->create();
    vol->setMountFlags(0);
    vol->mount();
}

static void bringOnline(const std::shared_ptr<VolumeBase>& vol) {
    vol->destroy();
    vol->setSilent(false);
    vol->create();
}

void MoveTask::run() {
    acquire_wake_lock(PARTIAL_WAKE_LOCK, kWakeLock);

    std::string fromPath;
    std::string toPath;

    // TODO: add support for public volumes
    if (mFrom->getType() != VolumeBase::Type::kEmulated) goto fail;
    if (mTo->getType() != VolumeBase::Type::kEmulated) goto fail;

    // Step 1: tear down volumes and mount silently without making
    // visible to userspace apps
    {
        std::lock_guard<std::mutex> lock(VolumeManager::Instance()->getLock());
        bringOffline(mFrom);
        bringOffline(mTo);
    }

    fromPath = mFrom->getInternalPath();
    toPath = mTo->getInternalPath();

    // Step 2: clean up any stale data
    if (execRm(toPath, 10, 10) != OK) {
        goto fail;
    }

    // Step 3: perform actual copy
    if (execCp(fromPath, toPath, 20, 60) != OK) {
        goto copy_fail;
    }

    // NOTE: MountService watches for this magic value to know
    // that move was successful
    notifyProgress(82);
    {
        std::lock_guard<std::mutex> lock(VolumeManager::Instance()->getLock());
        bringOnline(mFrom);
        bringOnline(mTo);
    }

    // Step 4: clean up old data
    if (execRm(fromPath, 85, 15) != OK) {
        goto fail;
    }

    notifyProgress(kMoveSucceeded);
    release_wake_lock(kWakeLock);
    return;

copy_fail:
    // if we failed to copy the data we should not leave it laying around
    // in target location. Do not check return value, we can not do any
    // useful anyway.
    execRm(toPath, 80, 1);
fail:
    {
        std::lock_guard<std::mutex> lock(VolumeManager::Instance()->getLock());
        bringOnline(mFrom);
        bringOnline(mTo);
    }
    notifyProgress(kMoveFailedInternalError);
    release_wake_lock(kWakeLock);
    return;
}

}  // namespace vold
}  // namespace android
