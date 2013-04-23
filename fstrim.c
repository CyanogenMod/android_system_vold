/*
 * Copyright (C) 2013 The Android Open Source Project
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <limits.h>
#include <linux/fs.h>
#include <fs_mgr.h>
#include <pthread.h>
#define LOG_TAG "fstrim"
#include "cutils/log.h"

static void *do_fstrim_filesystems(void *ignored)
{
    int i;
    int fd;
    int ret = 0;
    struct fstrim_range range = { 0 };
    struct stat sb;
    extern struct fstab *fstab;

    SLOGI("Starting fstrim work...\n");

    for (i = 0; i < fstab->num_entries; i++) {
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

        if (stat(fstab->recs[i].mount_point, &sb) == -1) {
            SLOGE("Cannot stat mount point %s\n", fstab->recs[i].mount_point);
            ret = -1;
            continue;
        }
        if (!S_ISDIR(sb.st_mode)) {
            SLOGE("%s is not a directory\n", fstab->recs[i].mount_point);
            ret = -1;
            continue;
        }

        fd = open(fstab->recs[i].mount_point, O_RDONLY);
        if (fd < 0) {
            SLOGE("Cannot open %s for FITRIM\n", fstab->recs[i].mount_point);
            ret = -1;
            continue;
        }

        memset(&range, 0, sizeof(range));
        range.len = ULLONG_MAX;
        SLOGI("Invoking FITRIM ioctl on %s", fstab->recs[i].mount_point);
        if (ioctl(fd, FITRIM, &range)) {
            SLOGE("FITRIM ioctl failed on %s", fstab->recs[i].mount_point);
            ret = -1;
        }
        SLOGI("Trimmed %llu bytes on %s\n", range.len, fstab->recs[i].mount_point);
        close(fd);
    }
    SLOGI("Finished fstrim work.\n");

    return (void *)ret;
}

int fstrim_filesystems(void)
{
    pthread_t t;
    int ret;

    /* Depending on the emmc chip and size, this can take upwards
     * of a few minutes.  If done in the same thread as the caller
     * of this function, that would block vold from accepting any
     * commands until the trim is finished.  So start another thread
     * to do the work, and return immediately.
     *
     * This function should not be called more than once per day, but
     * even if it is called a second time before the first one finishes,
     * the kernel will "do the right thing" and split the work between
     * the two ioctls invoked in separate threads.
     */
    ret = pthread_create(&t, NULL, do_fstrim_filesystems, NULL);
    if (ret) {
        SLOGE("Cannot create thread to do fstrim");
        return ret;
    }

    ret = pthread_detach(t);
    if (ret) {
        SLOGE("Cannot detach thread doing fstrim");
        return ret;
    }

    return 0;
}
