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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/fiemap.h>

#define LOG_TAG "secdiscard"
#include "cutils/log.h"

// Deliberately limit ourselves to wiping small files.
#define MAX_WIPE_LENGTH 4096
#define INIT_BUFFER_SIZE 2048

static void usage(char *progname);
static void destroy_key(const std::string &path);
static int file_device_range(const std::string &path, uint64_t range[2]);
static int open_block_device_for_path(const std::string &path);
static int read_file_as_string_atomically(const std::string &path, std::string &contents);
static int find_block_device_for_path(
    const std::string &mounts,
    const std::string &path,
    std::string &block_device);

int main(int argc, char **argv) {
    if (argc != 2 || argv[1][0] != '/') {
        usage(argv[0]);
        return -1;
    }
    SLOGD("Running: %s %s", argv[0], argv[1]);
    std::string target(argv[1]);
    destroy_key(target);
    if (unlink(argv[1]) != 0 && errno != ENOENT) {
        SLOGE("Unable to delete %s: %s",
            argv[1], strerror(errno));
        return -1;
    }
    return 0;
}

static void usage(char *progname) {
    fprintf(stderr, "Usage: %s <absolute path>\n", progname);
}

// BLKSECDISCARD all content in "path", if it's small enough.
static void destroy_key(const std::string &path) {
    uint64_t range[2];
    if (file_device_range(path, range) < 0) {
        return;
    }
    int fs_fd = open_block_device_for_path(path);
    if (fs_fd < 0) {
        return;
    }
    if (ioctl(fs_fd, BLKSECDISCARD, range) != 0) {
        SLOGE("Unable to BLKSECDISCARD %s: %s", path.c_str(), strerror(errno));
        close(fs_fd);
        return;
    }
    close(fs_fd);
    SLOGD("Discarded %s", path.c_str());
}

// Find a short range that completely covers the file.
// If there isn't one, return -1, otherwise 0.
static int file_device_range(const std::string &path, uint64_t range[2])
{
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
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
    if (ioctl(fd, FS_IOC_FIEMAP, fiemap) != 0) {
        SLOGE("Unable to FIEMAP %s: %s", path.c_str(), strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
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
    if (extent->fe_length > MAX_WIPE_LENGTH) {
        SLOGE("Extent too big, %llu bytes in %s", extent->fe_length, path.c_str());
        return -1;
    }
    range[0] = extent->fe_physical;
    range[1] = extent->fe_length;
    return 0;
}

// Given a file path, look for the corresponding
// block device in /proc/mounts and open it.
static int open_block_device_for_path(const std::string &path)
{
    std::string mountsfile("/proc/mounts");
    std::string mounts;
    if (read_file_as_string_atomically(mountsfile, mounts) < 0) {
        return -1;
    }
    std::string block_device;
    if (find_block_device_for_path(mounts, path, block_device) < 0) {
        return -1;
    }
    SLOGD("For path %s block device is %s", path.c_str(), block_device.c_str());
    int res = open(block_device.c_str(), O_RDWR | O_LARGEFILE | O_CLOEXEC);
    if (res < 0) {
        SLOGE("Failed to open device %s: %s", block_device.c_str(), strerror(errno));
        return -1;
    }
    return res;
}

// Read a file into a buffer in a single gulp, for atomicity.
// Null-terminate the buffer.
// Retry until the buffer is big enough.
static int read_file_as_string_atomically(const std::string &path, std::string &contents)
{
    ssize_t buffer_size = INIT_BUFFER_SIZE;
    while (true) {
        int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            SLOGE("Failed to open %s: %s", path.c_str(), strerror(errno));
            return -1;
        }
        contents.resize(buffer_size);
        ssize_t read_size = read(fd, &contents[0], buffer_size);
        if (read_size < 0) {
            SLOGE("Failed to read from %s: %s", path.c_str(), strerror(errno));
            close(fd);
            return -1;
        }
        close(fd);
        if (read_size < buffer_size) {
            contents.resize(read_size);
            return 0;
        }
        SLOGD("%s too big for buffer of size %zu", path.c_str(), buffer_size);
        buffer_size <<= 1;
    }
}

// Search a string representing the contents of /proc/mounts
// for the mount point of a particular file by prefix matching
// and return the corresponding block device.
static int find_block_device_for_path(
    const std::string &mounts,
    const std::string &path,
    std::string &block_device)
{
    auto line_begin = mounts.begin();
    size_t best_prefix = 0;
    std::string::const_iterator line_end;
    while (line_begin != mounts.end()) {
        line_end = std::find(line_begin, mounts.end(), '\n');
        if (line_end == mounts.end()) {
            break;
        }
        auto device_end = std::find(line_begin, line_end, ' ');
        if (device_end == line_end) {
            break;
        }
        auto mountpoint_begin = device_end + 1;
        auto mountpoint_end = std::find(mountpoint_begin, line_end, ' ');
        if (mountpoint_end == line_end) {
            break;
        }
        if (std::find(line_begin, mountpoint_end, '\\') != mountpoint_end) {
            // We don't correctly handle escape sequences, and we don't expect
            // to encounter any, so fail if we do.
            break;
        }
        size_t mountpoint_len = mountpoint_end - mountpoint_begin;
        if (mountpoint_len > best_prefix &&
                mountpoint_len < path.length() &&
                path[mountpoint_len] == '/' &&
                std::equal(mountpoint_begin, mountpoint_end, path.begin())) {
            block_device = std::string(line_begin, device_end);
            best_prefix = mountpoint_len;
        }
        line_begin = line_end + 1;
    }
    // All of the "break"s above are fatal parse errors.
    if (line_begin != mounts.end()) {
        auto bad_line = std::string(line_begin, line_end);
        SLOGE("Unable to parse line in %s: %s", path.c_str(), bad_line.c_str());
        return -1;
    }
    if (best_prefix == 0) {
        SLOGE("No prefix found for path: %s", path.c_str());
        return -1;
    }
    return 0;
}
