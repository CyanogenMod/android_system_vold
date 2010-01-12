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
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#define LOG_TAG "Vold"

#include <cutils/log.h>

#include "Devmapper.h"

void Devmapper::ioctlInit(struct dm_ioctl *io, size_t dataSize,
                          const char *name, unsigned flags) {
    memset(io, 0, dataSize);
    io->data_size = dataSize;
    io->data_start = sizeof(struct dm_ioctl);
    io->version[0] = 4;
    io->version[1] = 0;
    io->version[2] = 0;
    io->flags = flags;
    strncpy(io->name, name, sizeof(io->name));
}

int Devmapper::lookupActive(const char *name, char *ubuffer, size_t len) {
    char *buffer = (char *) malloc(4096);
    if (!buffer) {
        LOGE("Error allocating memory (%s)", strerror(errno));
        return -1;
    }

    int fd;
    if ((fd = open("/dev/device-mapper", O_RDWR)) < 0) {
        LOGE("Error opening devmapper (%s)", strerror(errno));
        free(buffer);
        return -1;
    }

    struct dm_ioctl *io = (struct dm_ioctl *) buffer;
 
    ioctlInit(io, 4096, name, 0);
    if (ioctl(fd, DM_DEV_STATUS, io)) {
        if (errno != ENXIO) {
            LOGE("DM_DEV_STATUS ioctl failed for lookup (%s)", strerror(errno));
        }
        free(buffer);
        close(fd);
        return -1;
    }
    close(fd);

    unsigned minor = (io->dev & 0xff) | ((io->dev >> 12) & 0xfff00);
    free(buffer);
    LOGD("Newly created devmapper instance minor = %d\n", minor);
    snprintf(ubuffer, len, "/dev/block/dm-%u", minor);
    return 0;
}

int Devmapper::create(const char *name, const char *loopFile, const char *key,
                      unsigned int numSectors, char *ubuffer, size_t len) {
    char *buffer = (char *) malloc(4096);
    if (!buffer) {
        LOGE("Error allocating memory (%s)", strerror(errno));
        return -1;
    }

    int fd;
    if ((fd = open("/dev/device-mapper", O_RDWR)) < 0) {
        LOGE("Error opening devmapper (%s)", strerror(errno));
        free(buffer);
        return -1;
    }

    struct dm_ioctl *io = (struct dm_ioctl *) buffer;
 
    // Create the DM device
    ioctlInit(io, 4096, name, 0);

    if (ioctl(fd, DM_DEV_CREATE, io)) {
        LOGE("Error creating device mapping (%s)", strerror(errno));
        free(buffer);
        close(fd);
        return -1;
    }

    // Set the legacy geometry
    ioctlInit(io, 4096, name, 0);

    char *geoParams = buffer + sizeof(struct dm_ioctl);
    // bps=512 spc=8 res=32 nft=2 sec=8190 mid=0xf0 spt=63 hds=64 hid=0 bspf=8 rdcl=2 infs=1 bkbs=2
    strcpy(geoParams, "0 64 63 0");
    geoParams += strlen(geoParams) + 1;
    geoParams = (char *) _align(geoParams, 8);
    if (ioctl(fd, DM_DEV_SET_GEOMETRY, io)) {
        LOGE("Error setting device geometry (%s)", strerror(errno));
        free(buffer);
        close(fd);
        return -1;
    }

    // Retrieve the device number we were allocated
    ioctlInit(io, 4096, name, 0);
    if (ioctl(fd, DM_DEV_STATUS, io)) {
        LOGE("Error retrieving devmapper status (%s)", strerror(errno));
        free(buffer);
        close(fd);
        return -1;
    }

    unsigned minor = (io->dev & 0xff) | ((io->dev >> 12) & 0xfff00);
    LOGD("Newly created devmapper instance minor = %d\n", minor);
    snprintf(ubuffer, len, "/dev/block/dm-%u", minor);

    // Load the table
    struct dm_target_spec *tgt;
    tgt = (struct dm_target_spec *) &buffer[sizeof(struct dm_ioctl)];

    ioctlInit(io, 4096, name, DM_STATUS_TABLE_FLAG);
    io->target_count = 1;
    tgt->status = 0;
    tgt->sector_start = 0;
    tgt->length = numSectors;
    strcpy(tgt->target_type, "crypt");

    char *cryptParams = buffer + sizeof(struct dm_ioctl) + sizeof(struct dm_target_spec);
    sprintf(cryptParams, "twofish %s 0 %s 0", key, loopFile);
    cryptParams += strlen(cryptParams) + 1;
    cryptParams = (char *) _align(cryptParams, 8);
    tgt->next = cryptParams - buffer;

    if (ioctl(fd, DM_TABLE_LOAD, io)) {
        LOGE("Error loading mapping table (%s)", strerror(errno));
        free(buffer);
        close(fd);
        return -1;
    }

    // Resume the new table
    ioctlInit(io, 4096, name, 0);

    if (ioctl(fd, DM_DEV_SUSPEND, io)) {
        LOGE("Error Resuming (%s)", strerror(errno));
        free(buffer);
        close(fd);
        return -1;
    }

    free(buffer);

    return 0;
}

int Devmapper::destroy(const char *name) {
    char *buffer = (char *) malloc(4096);
    if (!buffer) {
        LOGE("Error allocating memory (%s)", strerror(errno));
        return -1;
    }

    int fd;
    if ((fd = open("/dev/device-mapper", O_RDWR)) < 0) {
        LOGE("Error opening devmapper (%s)", strerror(errno));
        free(buffer);
        return -1;
    }

    struct dm_ioctl *io = (struct dm_ioctl *) buffer;
 
    // Create the DM device
    ioctlInit(io, 4096, name, 0);

    if (ioctl(fd, DM_DEV_REMOVE, io)) {
        if (errno != ENXIO) {
            LOGE("Error destroying device mapping (%s)", strerror(errno));
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
        register unsigned long agn = --a;

        return (void *) (((unsigned long) ptr + agn) & ~agn);
}

