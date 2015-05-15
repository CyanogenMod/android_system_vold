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

#include "Benchmark.h"
#include "BenchmarkGen.h"
#include "VolumeManager.h"
#include "ResponseCode.h"

#include <base/file.h>
#include <base/logging.h>
#include <cutils/iosched_policy.h>

#include <sys/time.h>
#include <sys/resource.h>

using android::base::ReadFileToString;
using android::base::WriteStringToFile;

namespace android {
namespace vold {

static std::string simpleRead(const std::string& path) {
    std::string tmp;
    ReadFileToString(path, &tmp);
    tmp.erase(tmp.find_last_not_of(" \n\r") + 1);
    return tmp;
}

nsecs_t Benchmark(const std::string& path, const std::string& sysPath) {
    errno = 0;
    int orig_prio = getpriority(PRIO_PROCESS, 0);
    if (errno != 0) {
        PLOG(ERROR) << "Failed to getpriority";
        return -1;
    }
    if (setpriority(PRIO_PROCESS, 0, -10) != 0) {
        PLOG(ERROR) << "Failed to setpriority";
        return -1;
    }

    IoSchedClass orig_clazz = IoSchedClass_NONE;
    int orig_ioprio = 0;
    if (android_get_ioprio(0, &orig_clazz, &orig_ioprio)) {
        PLOG(ERROR) << "Failed to android_get_ioprio";
        return -1;
    }
    if (android_set_ioprio(0, IoSchedClass_RT, 0)) {
        PLOG(ERROR) << "Failed to android_set_ioprio";
        return -1;
    }

    char orig_cwd[PATH_MAX];
    if (getcwd(orig_cwd, PATH_MAX) == NULL) {
        PLOG(ERROR) << "Failed getcwd";
        return -1;
    }
    if (chdir(path.c_str()) != 0) {
        PLOG(ERROR) << "Failed chdir";
        return -1;
    }

    LOG(INFO) << "Benchmarking " << path;
    nsecs_t start = systemTime(SYSTEM_TIME_BOOTTIME);

    BenchmarkCreate();
    nsecs_t create = systemTime(SYSTEM_TIME_BOOTTIME);

    if (!WriteStringToFile("3", "/proc/sys/vm/drop_caches")) {
        PLOG(ERROR) << "Failed to drop_caches";
    }
    nsecs_t drop = systemTime(SYSTEM_TIME_BOOTTIME);

    BenchmarkRun();
    nsecs_t run = systemTime(SYSTEM_TIME_BOOTTIME);

    BenchmarkDestroy();
    nsecs_t destroy = systemTime(SYSTEM_TIME_BOOTTIME);

    nsecs_t create_d = create - start;
    nsecs_t drop_d = drop - create;
    nsecs_t run_d = run - drop;
    nsecs_t destroy_d = destroy - run;

    LOG(INFO) << "create took " << nanoseconds_to_milliseconds(create_d) << "ms";
    LOG(INFO) << "drop took " << nanoseconds_to_milliseconds(drop_d) << "ms";
    LOG(INFO) << "run took " << nanoseconds_to_milliseconds(run_d) << "ms";
    LOG(INFO) << "destroy took " << nanoseconds_to_milliseconds(destroy_d) << "ms";

    std::string detail;
    detail += "id=" + BenchmarkIdent()
            + ",cr=" + std::to_string(create_d)
            + ",dr=" + std::to_string(drop_d)
            + ",ru=" + std::to_string(run_d)
            + ",de=" + std::to_string(destroy_d)
            + ",si=" + simpleRead(sysPath + "/size")
            + ",ve=" + simpleRead(sysPath + "/device/vendor")
            + ",mo=" + simpleRead(sysPath + "/device/model")
            + ",csd=" + simpleRead(sysPath + "/device/csd")
            + ",scr=" + simpleRead(sysPath + "/device/scr");

    // Scrub CRC and serial number out of CID
    std::string cid = simpleRead(sysPath + "/device/cid");
    if (cid.length() == 32) {
        cid.erase(32, 1);
        cid.erase(18, 8);
        detail += ",cid=" + cid;
    }

    VolumeManager::Instance()->getBroadcaster()->sendBroadcast(
            ResponseCode::BenchmarkResult, detail.c_str(), false);

    if (chdir(orig_cwd) != 0) {
        PLOG(ERROR) << "Failed to chdir";
    }
    if (android_set_ioprio(0, orig_clazz, orig_ioprio)) {
        PLOG(ERROR) << "Failed to android_set_ioprio";
    }
    if (setpriority(PRIO_PROCESS, 0, orig_prio) != 0) {
        PLOG(ERROR) << "Failed to setpriority";
    }
    return run_d;
}

}  // namespace vold
}  // namespace android
