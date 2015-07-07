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

#include <memory>
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

constexpr uint32_t max_extents = 32;

bool read_command_line(int argc, const char * const argv[], Options &options);
void usage(const char *progname);
int secdiscard_path(const std::string &path);
std::unique_ptr<struct fiemap> path_fiemap(const std::string &path, uint32_t extent_count);
bool check_fiemap(const struct fiemap &fiemap, const std::string &path);
std::unique_ptr<struct fiemap> alloc_fiemap(uint32_t extent_count);
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
    auto fiemap = path_fiemap(path, max_extents);
    if (!fiemap || !check_fiemap(*fiemap, path)) {
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
    for (uint32_t i = 0; i < fiemap->fm_mapped_extents; i++) {
        uint64_t range[2];
        range[0] = fiemap->fm_extents[i].fe_physical;
        range[1] = fiemap->fm_extents[i].fe_length;
        if (ioctl(fs_fd.get(), BLKSECDISCARD, range) == -1) {
            SLOGE("Unable to BLKSECDISCARD %s: %s", path.c_str(), strerror(errno));
            return -1;
        }
    }
    return 0;
}

// Read the file's FIEMAP
std::unique_ptr<struct fiemap> path_fiemap(const std::string &path, uint32_t extent_count)
{
    AutoCloseFD fd(path);
    if (!fd) {
        if (errno == ENOENT) {
            SLOGD("Unable to open %s: %s", path.c_str(), strerror(errno));
        } else {
            SLOGE("Unable to open %s: %s", path.c_str(), strerror(errno));
        }
        return nullptr;
    }
    auto fiemap = alloc_fiemap(extent_count);
    if (ioctl(fd.get(), FS_IOC_FIEMAP, fiemap.get()) != 0) {
        SLOGE("Unable to FIEMAP %s: %s", path.c_str(), strerror(errno));
        return nullptr;
    }
    auto mapped = fiemap->fm_mapped_extents;
    if (mapped < 1 || mapped > extent_count) {
        SLOGE("Extent count not in bounds 1 <= %u <= %u in %s", mapped, extent_count, path.c_str());
        return nullptr;
    }
    return fiemap;
}

// Ensure that the FIEMAP covers the file and is OK to discard
bool check_fiemap(const struct fiemap &fiemap, const std::string &path) {
    auto mapped = fiemap.fm_mapped_extents;
    if (!(fiemap.fm_extents[mapped - 1].fe_flags & FIEMAP_EXTENT_LAST)) {
        SLOGE("Extent %u was not the last in %s", mapped - 1, path.c_str());
        return false;
    }
    for (uint32_t i = 0; i < mapped; i++) {
        auto flags = fiemap.fm_extents[i].fe_flags;
        if (flags & (FIEMAP_EXTENT_UNKNOWN | FIEMAP_EXTENT_DELALLOC | FIEMAP_EXTENT_NOT_ALIGNED)) {
            SLOGE("Extent %u has unexpected flags %ulx: %s", i, flags, path.c_str());
            return false;
        }
    }
    return true;
}

std::unique_ptr<struct fiemap> alloc_fiemap(uint32_t extent_count)
{
    size_t allocsize = offsetof(struct fiemap, fm_extents[extent_count]);
    std::unique_ptr<struct fiemap> res(new (::operator new (allocsize)) struct fiemap);
    memset(res.get(), 0, allocsize);
    res->fm_start = 0;
    res->fm_length = UINT64_MAX;
    res->fm_flags = 0;
    res->fm_extent_count = extent_count;
    res->fm_mapped_extents = 0;
    return res;
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
