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

#include <string>
#include <vector>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/fiemap.h>
#include <mntent.h>

#define LOG_TAG "secdiscard"
#include "cutils/log.h"

#include <AutoCloseFD.h>

namespace {

struct Options {
    std::vector<std::string> targets;
    bool unlink{true};
};

// Deliberately limit ourselves to wiping small files.
constexpr uint64_t max_wipe_length = 4096;

bool read_command_line(int argc, const char * const argv[], Options &options);
void usage(const char *progname);
int secdiscard_path(const std::string &path);
int path_device_range(const std::string &path, uint64_t range[2]);
std::string block_device_for_path(const std::string &path);

}

int main(int argc, const char * const argv[]) {
    Options options;
    if (!read_command_line(argc, argv, options)) {
        usage(argv[0]);
        return -1;
    }
    for (auto target: options.targets) {
        SLOGD("Securely discarding '%s' unlink=%d", target.c_str(), options.unlink);
        secdiscard_path(target);
        if (options.unlink) {
            if (unlink(target.c_str()) != 0 && errno != ENOENT) {
                SLOGE("Unable to unlink %s: %s",
                    target.c_str(), strerror(errno));
            }
        }
        SLOGD("Discarded %s", target.c_str());
    }
    return 0;
}

namespace {

bool read_command_line(int argc, const char * const argv[], Options &options) {
    for (int i = 1; i < argc; i++) {
        if (!strcmp("--no-unlink", argv[i])) {
            options.unlink = false;
        } else if (!strcmp("--", argv[i])) {
            for (int j = i+1; j < argc; j++) {
                if (argv[j][0] != '/') return false; // Must be absolute path
                options.targets.emplace_back(argv[j]);
            }
            return options.targets.size() > 0;
        } else {
            return false; // Unknown option
        }
    }
    return false; // "--" not found
}

void usage(const char *progname) {
    fprintf(stderr, "Usage: %s [--no-unlink] -- <absolute path> ...\n", progname);
}

// BLKSECDISCARD all content in "path", if it's small enough.
int secdiscard_path(const std::string &path) {
    uint64_t range[2];
    if (path_device_range(path, range) == -1) {
        return -1;
    }
    auto block_device = block_device_for_path(path);
    if (block_device.empty()) {
        return -1;
    }
    AutoCloseFD fs_fd(block_device, O_RDWR | O_LARGEFILE);
    if (!fs_fd) {
        SLOGE("Failed to open device %s: %s", block_device.c_str(), strerror(errno));
        return -1;
    }
    if (ioctl(fs_fd.get(), BLKSECDISCARD, range) == -1) {
        SLOGE("Unable to BLKSECDISCARD %s: %s", path.c_str(), strerror(errno));
        return -1;
    }
    return 0;
}

// Find a short range that completely covers the file.
// If there isn't one, return -1, otherwise 0.
int path_device_range(const std::string &path, uint64_t range[2])
{
    AutoCloseFD fd(path);
    if (!fd) {
        if (errno == ENOENT) {
            SLOGD("Unable to open %s: %s", path.c_str(), strerror(errno));
        } else {
            SLOGE("Unable to open %s: %s", path.c_str(), strerror(errno));
        }
        return -1;
    }
    alignas(struct fiemap) char fiemap_buffer[offsetof(struct fiemap, fm_extents[1])];
    memset(fiemap_buffer, 0, sizeof(fiemap_buffer));
    struct fiemap *fiemap = (struct fiemap *)fiemap_buffer;
    fiemap->fm_start = 0;
    fiemap->fm_length = UINT64_MAX;
    fiemap->fm_flags = 0;
    fiemap->fm_extent_count = 1;
    fiemap->fm_mapped_extents = 0;
    if (ioctl(fd.get(), FS_IOC_FIEMAP, fiemap) != 0) {
        SLOGE("Unable to FIEMAP %s: %s", path.c_str(), strerror(errno));
        return -1;
    }
    if (fiemap->fm_mapped_extents != 1) {
        SLOGE("Expecting one extent, got %d in %s", fiemap->fm_mapped_extents, path.c_str());
        return -1;
    }
    struct fiemap_extent *extent = &fiemap->fm_extents[0];
    if (!(extent->fe_flags & FIEMAP_EXTENT_LAST)) {
        SLOGE("First extent was not the last in %s", path.c_str());
        return -1;
    }
    if (extent->fe_flags &
            (FIEMAP_EXTENT_UNKNOWN | FIEMAP_EXTENT_DELALLOC | FIEMAP_EXTENT_NOT_ALIGNED)) {
        SLOGE("Extent has unexpected flags %ulx: %s", extent->fe_flags, path.c_str());
        return -1;
    }
    if (extent->fe_length > max_wipe_length) {
        SLOGE("Extent too big, %llu bytes in %s", extent->fe_length, path.c_str());
        return -1;
    }
    range[0] = extent->fe_physical;
    range[1] = extent->fe_length;
    return 0;
}

// Given a file path, look for the corresponding block device in /proc/mount
std::string block_device_for_path(const std::string &path)
{
    std::unique_ptr<FILE, int(*)(FILE*)> mnts(setmntent("/proc/mounts", "re"), endmntent);
    if (!mnts) {
        SLOGE("Unable to open /proc/mounts: %s", strerror(errno));
        return "";
    }
    std::string result;
    size_t best_length = 0;
    struct mntent *mnt; // getmntent returns a thread local, so it's safe.
    while ((mnt = getmntent(mnts.get())) != nullptr) {
        auto l = strlen(mnt->mnt_dir);
        if (l > best_length &&
            path.size() > l &&
            path[l] == '/' &&
            path.compare(0, l, mnt->mnt_dir) == 0) {
                result = mnt->mnt_fsname;
                best_length = l;
        }
    }
    if (result.empty()) {
        SLOGE("Didn't find a mountpoint to match path %s", path.c_str());
        return "";
    }
    SLOGD("For path %s block device is %s", path.c_str(), result.c_str());
    return result;
}

}
