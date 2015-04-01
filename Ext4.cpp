/*
 * Copyright (C) 2012 The Android Open Source Project
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
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <vector>
#include <string>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/wait.h>

#include <linux/kdev_t.h>

#define LOG_TAG "Vold"

#include <base/logging.h>
#include <base/stringprintf.h>
#include <cutils/log.h>
#include <cutils/properties.h>
#include <logwrap/logwrap.h>
#include <selinux/selinux.h>

#include "Ext4.h"
#include "Utils.h"
#include "VoldUtil.h"

#define RESIZE2FS_PATH "/system/bin/resize2fs"

using android::base::StringPrintf;

static const char* kMkfsPath = "/system/bin/make_ext4fs";

static const char* kFsckPath = "/system/bin/e2fsck";
static const char* kFsckLogFile = "/dev/fscklogs/log";

int Ext4::check(const char *fsPath, const char *mountPoint) {
    // The following is shamelessly borrowed from fs_mgr.c, so it should be
    // kept in sync with any changes over there.

    char* blk_device = (char*) fsPath;
    char* target = (char*) mountPoint;

    int status;
    int ret;
    long tmpmnt_flags = MS_NOATIME | MS_NOEXEC | MS_NOSUID;
    char *tmpmnt_opts = (char*) "nomblk_io_submit,errors=remount-ro";
    char *e2fsck_argv[] = {
        (char*) kFsckPath,
        (char*) "-y",
        blk_device
    };

    /*
     * First try to mount and unmount the filesystem.  We do this because
     * the kernel is more efficient than e2fsck in running the journal and
     * processing orphaned inodes, and on at least one device with a
     * performance issue in the emmc firmware, it can take e2fsck 2.5 minutes
     * to do what the kernel does in about a second.
     *
     * After mounting and unmounting the filesystem, run e2fsck, and if an
     * error is recorded in the filesystem superblock, e2fsck will do a full
     * check.  Otherwise, it does nothing.  If the kernel cannot mount the
     * filesytsem due to an error, e2fsck is still run to do a full check
     * fix the filesystem.
     */
    ret = mount(blk_device, target, "ext4", tmpmnt_flags, tmpmnt_opts);
    if (!ret) {
        int i;
        for (i = 0; i < 5; i++) {
            // Try to umount 5 times before continuing on.
            // Should we try rebooting if all attempts fail?
            int result = umount(target);
            if (result == 0) {
                break;
            }
            ALOGW("%s(): umount(%s)=%d: %s\n", __func__, target, result, strerror(errno));
            sleep(1);
        }
    }

    /*
     * Some system images do not have e2fsck for licensing reasons
     * (e.g. recent SDK system images). Detect these and skip the check.
     */
    if (access(kFsckPath, X_OK)) {
        ALOGD("Not running %s on %s (executable not in system image)\n",
                kFsckPath, blk_device);
    } else {
        ALOGD("Running %s on %s\n", kFsckPath, blk_device);

        // Ext4 devices are currently always trusted
        if (setexeccon(android::vold::sFsckContext)) {
            LOG(ERROR) << "Failed to setexeccon()";
            errno = EPERM;
            return -1;
        }
        ret = android_fork_execvp(ARRAY_SIZE(e2fsck_argv), e2fsck_argv,
                                    &status, false, true);
        if (setexeccon(NULL)) {
            abort();
        }

        if (ret < 0) {
            /* No need to check for error in fork, we can't really handle it now */
            ALOGW("Failed trying to run %s\n", kFsckPath);
            return -1;
        }
    }

    return 0;
}

int Ext4::doMount(const char *fsPath, const char *mountPoint, bool ro, bool remount,
        bool executable) {
    int rc;
    unsigned long flags;

    flags = MS_NOATIME | MS_NODEV | MS_NOSUID | MS_DIRSYNC;

    flags |= (executable ? 0 : MS_NOEXEC);
    flags |= (ro ? MS_RDONLY : 0);
    flags |= (remount ? MS_REMOUNT : 0);

    rc = mount(fsPath, mountPoint, "ext4", flags, NULL);

    if (rc && errno == EROFS) {
        SLOGE("%s appears to be a read only filesystem - retrying mount RO", fsPath);
        flags |= MS_RDONLY;
        rc = mount(fsPath, mountPoint, "ext4", flags, NULL);
    }

    return rc;
}

int Ext4::resize(const char *fspath, unsigned int numSectors) {
    const char *args[4];
    char* size_str;
    int rc;
    int status;

    args[0] = RESIZE2FS_PATH;
    args[1] = "-f";
    args[2] = fspath;
    if (asprintf(&size_str, "%ds", numSectors) < 0)
    {
      SLOGE("Filesystem (ext4) resize failed to set size");
      return -1;
    }
    args[3] = size_str;
    rc = android_fork_execvp(ARRAY_SIZE(args), (char **)args, &status, false,
            true);
    free(size_str);
    if (rc != 0) {
        SLOGE("Filesystem (ext4) resize failed due to logwrap error");
        errno = EIO;
        return -1;
    }

    if (!WIFEXITED(status)) {
        SLOGE("Filesystem (ext4) resize did not exit properly");
        errno = EIO;
        return -1;
    }

    status = WEXITSTATUS(status);

    if (status == 0) {
        SLOGI("Filesystem (ext4) resized OK");
        return 0;
    } else {
        SLOGE("Resize (ext4) failed (unknown exit code %d)", status);
        errno = EIO;
        return -1;
    }
    return 0;
}

int Ext4::format(const char *fsPath, unsigned int numSectors, const char *mountpoint) {
    int status;

    std::vector<std::string> cmd;
    cmd.push_back(kMkfsPath);
    cmd.push_back("-J");

    cmd.push_back("-a");
    cmd.push_back(mountpoint);

    if (numSectors) {
        cmd.push_back("-l");
        cmd.push_back(StringPrintf("%u", numSectors * 512));
    }

    cmd.push_back(fsPath);

    int rc = android::vold::ForkExecvp(cmd, &status, false, true);
    if (rc != 0) {
        SLOGE("Filesystem (ext4) format failed due to logwrap error");
        errno = EIO;
        return -1;
    }

    if (!WIFEXITED(status)) {
        SLOGE("Filesystem (ext4) format did not exit properly");
        errno = EIO;
        return -1;
    }

    status = WEXITSTATUS(status);

    if (status == 0) {
        SLOGI("Filesystem (ext4) formatted OK");
        return 0;
    } else {
        SLOGE("Format (ext4) failed (unknown exit code %d)", status);
        errno = EIO;
        return -1;
    }
    return 0;
}
