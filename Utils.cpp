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

#include "sehandle.h"
#include "Utils.h"
#include "Process.h"

#include <base/logging.h>
#include <base/stringprintf.h>
#include <cutils/fs.h>
#include <private/android_filesystem_config.h>
#include <logwrap/logwrap.h>

#include <fcntl.h>
#include <linux/fs.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#ifndef UMOUNT_NOFOLLOW
#define UMOUNT_NOFOLLOW    0x00000008  /* Don't follow symlink on umount */
#endif

using android::base::StringPrintf;

namespace android {
namespace vold {

security_context_t sBlkidContext = nullptr;
security_context_t sBlkidUntrustedContext = nullptr;
security_context_t sFsckContext = nullptr;
security_context_t sFsckUntrustedContext = nullptr;

static const char* kBlkidPath = "/system/bin/blkid";

status_t CreateDeviceNode(const std::string& path, dev_t dev) {
    const char* cpath = path.c_str();
    status_t res = 0;

    char* secontext = nullptr;
    if (sehandle) {
        if (!selabel_lookup(sehandle, &secontext, cpath, S_IFBLK)) {
            setfscreatecon(secontext);
        }
    }

    mode_t mode = 0660 | S_IFBLK;
    if (mknod(cpath, mode, dev) < 0) {
        if (errno != EEXIST) {
            PLOG(ERROR) << "Failed to create device node for " << major(dev)
                    << ":" << minor(dev) << " at " << path;
            res = -errno;
        }
    }

    if (secontext) {
        setfscreatecon(nullptr);
        freecon(secontext);
    }

    return res;
}

status_t DestroyDeviceNode(const std::string& path) {
    const char* cpath = path.c_str();
    if (TEMP_FAILURE_RETRY(unlink(cpath))) {
        return -errno;
    } else {
        return OK;
    }
}

status_t ForceUnmount(const std::string& path) {
    const char* cpath = path.c_str();
    if (!umount2(cpath, UMOUNT_NOFOLLOW) || errno == EINVAL || errno == ENOENT) {
        return OK;
    }
    PLOG(WARNING) << "Failed to unmount " << path << "; sending SIGTERM";
    Process::killProcessesWithOpenFiles(cpath, SIGTERM);
    sleep(5);

    if (!umount2(cpath, UMOUNT_NOFOLLOW) || errno == EINVAL || errno == ENOENT) {
        return OK;
    }
    PLOG(WARNING) << "Failed to unmount " << path << "; sending SIGKILL";
    Process::killProcessesWithOpenFiles(cpath, SIGKILL);
    sleep(5);

    if (!umount2(cpath, UMOUNT_NOFOLLOW) || errno == EINVAL || errno == ENOENT) {
        return OK;
    }
    PLOG(ERROR) << "Failed to unmount " << path << "; giving up";
    return -errno;
}

status_t BindMount(const std::string& source, const std::string& target) {
    if (::mount(source.c_str(), target.c_str(), "", MS_BIND, NULL)) {
        PLOG(ERROR) << "Failed to bind mount " << source << " to " << target;
        return -errno;
    }
    return OK;
}

static status_t readMetadata(const std::string& path, std::string& fsType,
        std::string& fsUuid, std::string& fsLabel, bool untrusted) {
    fsType.clear();
    fsUuid.clear();
    fsLabel.clear();

    std::string cmd(StringPrintf("%s -c /dev/null %s", kBlkidPath, path.c_str()));
    if (setexeccon(untrusted ? sBlkidUntrustedContext : sBlkidContext)) {
        LOG(ERROR) << "Failed to setexeccon()";
        return -EPERM;
    }
    FILE* fp = popen(cmd.c_str(), "r");
    if (setexeccon(NULL)) {
        abort();
    }
    if (!fp) {
        PLOG(ERROR) << "Failed to run " << cmd;
        return -errno;
    }

    status_t res = OK;
    char line[1024];
    char value[128];
    if (fgets(line, sizeof(line), fp) != nullptr) {
        LOG(DEBUG) << "blkid identified " << path << " as " << line;

        // Extract values from blkid output, if defined
        char* start = strstr(line, "TYPE=");
        if (start != nullptr && sscanf(start + 5, "\"%127[^\"]\"", value) == 1) {
            fsType = value;
        }

        start = strstr(line, "UUID=");
        if (start != nullptr && sscanf(start + 5, "\"%127[^\"]\"", value) == 1) {
            fsUuid = value;
        }

        start = strstr(line, "LABEL=");
        if (start != nullptr && sscanf(start + 6, "\"%127[^\"]\"", value) == 1) {
            fsLabel = value;
        }
    } else {
        LOG(WARNING) << "blkid failed to identify " << path;
        res = -ENODATA;
    }

    pclose(fp);
    return res;
}

status_t ReadMetadata(const std::string& path, std::string& fsType,
        std::string& fsUuid, std::string& fsLabel) {
    return readMetadata(path, fsType, fsUuid, fsLabel, false);
}

status_t ReadMetadataUntrusted(const std::string& path, std::string& fsType,
        std::string& fsUuid, std::string& fsLabel) {
    return readMetadata(path, fsType, fsUuid, fsLabel, true);
}

status_t ForkExecvp(const std::vector<std::string>& args, int* status,
        bool ignore_int_quit, bool logwrap) {
    int argc = args.size();
    char** argv = (char**) calloc(argc, sizeof(char*));
    for (int i = 0; i < argc; i++) {
        argv[i] = (char*) args[i].c_str();
        if (i == 0) {
            LOG(VERBOSE) << args[i];
        } else {
            LOG(VERBOSE) << "    " << args[i];
        }
    }
    int res = android_fork_execvp(argc, argv, status, ignore_int_quit, logwrap);
    free(argv);
    return res;
}

status_t ReadRandomBytes(size_t bytes, std::string& out) {
    out.clear();

    int fd = TEMP_FAILURE_RETRY(open("/dev/urandom", O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    if (fd == -1) {
        return -errno;
    }

    char buf[BUFSIZ];
    size_t n;
    while ((n = TEMP_FAILURE_RETRY(read(fd, &buf[0], std::min(sizeof(buf), bytes)))) > 0) {
        out.append(buf, n);
        bytes -= n;
    }
    TEMP_FAILURE_RETRY(close(fd));

    if (bytes == 0) {
        return OK;
    } else {
        return -EIO;
    }
}

status_t HexToStr(const std::string& hex, std::string& str) {
    str.clear();
    bool even = true;
    char cur = 0;
    for (size_t i = 0; i < hex.size(); i++) {
        int val = 0;
        switch (hex[i]) {
        case ' ': case '-': case ':': continue;
        case 'f': case 'F': val = 15; break;
        case 'e': case 'E': val = 14; break;
        case 'd': case 'D': val = 13; break;
        case 'c': case 'C': val = 12; break;
        case 'b': case 'B': val = 11; break;
        case 'a': case 'A': val = 10; break;
        case '9': val = 9; break;
        case '8': val = 8; break;
        case '7': val = 7; break;
        case '6': val = 6; break;
        case '5': val = 5; break;
        case '4': val = 4; break;
        case '3': val = 3; break;
        case '2': val = 2; break;
        case '1': val = 1; break;
        case '0': val = 0; break;
        default: return -EINVAL;
        }

        if (even) {
            cur = val << 4;
        } else {
            cur += val;
            str.push_back(cur);
            cur = 0;
        }
        even = !even;
    }
    return even ? OK : -EINVAL;
}

static const char* kLookup = "0123456789abcdef";

status_t StrToHex(const std::string& str, std::string& hex) {
    hex.clear();
    for (size_t i = 0; i < str.size(); i++) {
        hex.push_back(kLookup[str[i] >> 4]);
        hex.push_back(kLookup[str[i] & 0x0F]);
    }
    return OK;
}

}  // namespace vold
}  // namespace android
