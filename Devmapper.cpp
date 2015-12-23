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
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <linux/kdev_t.h>

#define LOG_TAG "Vold"

#include <cutils/log.h>

#include <sysutils/SocketClient.h>

#include "Devmapper.h"

#define DEVMAPPER_BUFFER_SIZE 4096

int Devmapper::dumpState(SocketClient *c) {

    char *buffer = (char *) malloc(1024 * 64);
    if (!buffer) {
        SLOGE("Error allocating memory (%s)", strerror(errno));
        return -1;
    }
    memset(buffer, 0, (1024 * 64));

    char *buffer2 = (char *) malloc(DEVMAPPER_BUFFER_SIZE);
    if (!buffer2) {
        SLOGE("Error allocating memory (%s)", strerror(errno));
        free(buffer);
        return -1;
    }

    int fd;
    if ((fd = open("/dev/device-mapper", O_RDWR | O_CLOEXEC)) < 0) {
        SLOGE("Error opening devmapper (%s)", strerror(errno));
        free(buffer);
        free(buffer2);
        return -1;
    }

    struct dm_ioctl *io = (struct dm_ioctl *) buffer;
    ioctlInit(io, (1024 * 64), NULL, 0);

    if (ioctl(fd, DM_LIST_DEVICES, io)) {
        SLOGE("DM_LIST_DEVICES ioctl failed (%s)", strerror(errno));
        free(buffer);
        free(buffer2);
        close(fd);
        return -1;
    }

    struct dm_name_list *n = (struct dm_name_list *) (((char *) buffer) + io->data_start);
    if (!n->dev) {
        free(buffer);
        free(buffer2);
        close(fd);
        return 0;
    }

    unsigned nxt = 0;
    do {
        n = (struct dm_name_list *) (((char *) n) + nxt);

        memset(buffer2, 0, DEVMAPPER_BUFFER_SIZE);
        struct dm_ioctl *io2 = (struct dm_ioctl *) buffer2;
        ioctlInit(io2, DEVMAPPER_BUFFER_SIZE, n->name, 0);
        if (ioctl(fd, DM_DEV_STATUS, io2)) {
            if (errno != ENXIO) {
                SLOGE("DM_DEV_STATUS ioctl failed (%s)", strerror(errno));
            }
            io2 = NULL;
        }

        char *tmp;
        if (!io2) {
            asprintf(&tmp, "%s %llu:%llu (no status available)", n->name, MAJOR(n->dev), MINOR(n->dev));
        } else {
            asprintf(&tmp, "%s %llu:%llu %d %d 0x%.8x %llu:%llu", n->name, MAJOR(n->dev),
                    MINOR(n->dev), io2->target_count, io2->open_count, io2->flags, MAJOR(io2->dev),
                            MINOR(io2->dev));
        }
        c->sendMsg(0, tmp, false);
        free(tmp);
        nxt = n->next;
    } while (nxt);

    free(buffer);
    free(buffer2);
    close(fd);
    return 0;
}

void Devmapper::ioctlInit(struct dm_ioctl *io, size_t dataSize,
                          const char *name, unsigned flags) {
    memset(io, 0, dataSize);
    io->data_size = dataSize;
    io->data_start = sizeof(struct dm_ioctl);
    io->version[0] = 4;
    io->version[1] = 0;
    io->version[2] = 0;
    io->flags = flags;
    if (name) {
        size_t ret = strlcpy(io->name, name, sizeof(io->name));
        if (ret >= sizeof(io->name))
            abort();
    }
}

int Devmapper::lookupActive(const char *name, char *ubuffer, size_t len) {
    char *buffer = (char *) malloc(DEVMAPPER_BUFFER_SIZE);
    if (!buffer) {
        SLOGE("Error allocating memory (%s)", strerror(errno));
        return -1;
    }

    int fd;
    if ((fd = open("/dev/device-mapper", O_RDWR | O_CLOEXEC)) < 0) {
        SLOGE("Error opening devmapper (%s)", strerror(errno));
        free(buffer);
        return -1;
    }

    struct dm_ioctl *io = (struct dm_ioctl *) buffer;
 
    ioctlInit(io, DEVMAPPER_BUFFER_SIZE, name, 0);
    if (ioctl(fd, DM_DEV_STATUS, io)) {
        if (errno != ENXIO) {
            SLOGE("DM_DEV_STATUS ioctl failed for lookup (%s)", strerror(errno));
        }
        free(buffer);
        close(fd);
        return -1;
    }
    close(fd);

    unsigned minor = (io->dev & 0xff) | ((io->dev >> 12) & 0xfff00);
    free(buffer);
    snprintf(ubuffer, len, "/dev/block/dm-%u", minor);
    return 0;
}

int Devmapper::create(const char *name, const char *loopFile, const char *key,
                      unsigned long numSectors, char *ubuffer, size_t len) {
    char *buffer = (char *) malloc(DEVMAPPER_BUFFER_SIZE);
    if (!buffer) {
        SLOGE("Error allocating memory (%s)", strerror(errno));
        return -1;
    }

    int fd;
    if ((fd = open("/dev/device-mapper", O_RDWR | O_CLOEXEC)) < 0) {
        SLOGE("Error opening devmapper (%s)", strerror(errno));
        free(buffer);
        return -1;
    }

    struct dm_ioctl *io = (struct dm_ioctl *) buffer;
 
    // Create the DM device
    ioctlInit(io, DEVMAPPER_BUFFER_SIZE, name, 0);

    if (ioctl(fd, DM_DEV_CREATE, io)) {
        SLOGE("Error creating device mapping (%s)", strerror(errno));
        free(buffer);
        close(fd);
        return -1;
    }

    // Set the legacy geometry
    ioctlInit(io, DEVMAPPER_BUFFER_SIZE, name, 0);

    char *geoParams = buffer + sizeof(struct dm_ioctl);
    // bps=512 spc=8 res=32 nft=2 sec=8190 mid=0xf0 spt=63 hds=64 hid=0 bspf=8 rdcl=2 infs=1 bkbs=2
    strcpy(geoParams, "0 64 63 0");
    geoParams += strlen(geoParams) + 1;
    geoParams = (char *) _align(geoParams, 8);
    if (ioctl(fd, DM_DEV_SET_GEOMETRY, io)) {
        SLOGE("Error setting device geometry (%s)", strerror(errno));
        free(buffer);
        close(fd);
        return -1;
    }

    // Retrieve the device number we were allocated
    ioctlInit(io, DEVMAPPER_BUFFER_SIZE, name, 0);
    if (ioctl(fd, DM_DEV_STATUS, io)) {
        SLOGE("Error retrieving devmapper status (%s)", strerror(errno));
        free(buffer);
        close(fd);
        return -1;
    }

    unsigned minor = (io->dev & 0xff) | ((io->dev >> 12) & 0xfff00);
    snprintf(ubuffer, len, "/dev/block/dm-%u", minor);

    // Load the table
    struct dm_target_spec *tgt;
    tgt = (struct dm_target_spec *) &buffer[sizeof(struct dm_ioctl)];

    ioctlInit(io, DEVMAPPER_BUFFER_SIZE, name, DM_STATUS_TABLE_FLAG);
    io->target_count = 1;
    tgt->status = 0;

    tgt->sector_start = 0;
    tgt->length = numSectors;

    strlcpy(tgt->target_type, "crypt", sizeof(tgt->target_type));

    char *cryptParams = buffer + sizeof(struct dm_ioctl) + sizeof(struct dm_target_spec);
    snprintf(cryptParams,
            DEVMAPPER_BUFFER_SIZE - (sizeof(struct dm_ioctl) + sizeof(struct dm_target_spec)),
            "twofish %s 0 %s 0", key, loopFile);
    cryptParams += strlen(cryptParams) + 1;
    cryptParams = (char *) _align(cryptParams, 8);
    tgt->next = cryptParams - buffer;

    if (ioctl(fd, DM_TABLE_LOAD, io)) {
        SLOGE("Error loading mapping table (%s)", strerror(errno));
        free(buffer);
        close(fd);
        return -1;
    }

    // Resume the new table
    ioctlInit(io, DEVMAPPER_BUFFER_SIZE, name, 0);

    if (ioctl(fd, DM_DEV_SUSPEND, io)) {
        SLOGE("Error Resuming (%s)", strerror(errno));
        free(buffer);
        close(fd);
        return -1;
    }

    free(buffer);

    close(fd);
    return 0;
}

int Devmapper::destroy(const char *name) {
    char *buffer = (char *) malloc(DEVMAPPER_BUFFER_SIZE);
    if (!buffer) {
        SLOGE("Error allocating memory (%s)", strerror(errno));
        return -1;
    }

    int fd;
    if ((fd = open("/dev/device-mapper", O_RDWR | O_CLOEXEC)) < 0) {
        SLOGE("Error opening devmapper (%s)", strerror(errno));
        free(buffer);
        return -1;
    }

    struct dm_ioctl *io = (struct dm_ioctl *) buffer;
 
    // Create the DM device
    ioctlInit(io, DEVMAPPER_BUFFER_SIZE, name, 0);

    if (ioctl(fd, DM_DEV_REMOVE, io)) {
        if (errno != ENXIO) {
            SLOGE("Error destroying device mapping (%s)", strerror(errno));
        }
        free(buffer);
        close(fd);
        return -1;
    }

    free(buffer);
    close(fd);
    return 0;
}

void *Devmapper::_align(void *ptr, unsigned int a)
{
        unsigned long agn = --a;

        return (void *) (((unsigned long) ptr + agn) & ~agn);
}
