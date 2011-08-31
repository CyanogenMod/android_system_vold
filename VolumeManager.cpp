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
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>

#include <linux/kdev_t.h>

#define LOG_TAG "Vold"

#include <openssl/md5.h>

#include <cutils/log.h>

#include <sysutils/NetlinkEvent.h>

#include "VolumeManager.h"
#include "DirectVolume.h"
#include "ResponseCode.h"
#include "Loop.h"
#include "Fat.h"
#include "Devmapper.h"
#include "Process.h"
#include "Asec.h"
#include "cryptfs.h"

#define MASS_STORAGE_FILE_PATH  "/sys/class/android_usb/android0/f_mass_storage/lun/file"

VolumeManager *VolumeManager::sInstance = NULL;

VolumeManager *VolumeManager::Instance() {
    if (!sInstance)
        sInstance = new VolumeManager();
    return sInstance;
}

VolumeManager::VolumeManager() {
    mDebug = false;
    mVolumes = new VolumeCollection();
    mActiveContainers = new AsecIdCollection();
    mBroadcaster = NULL;
    mUmsSharingCount = 0;
    mSavedDirtyRatio = -1;
    // set dirty ratio to 0 when UMS is active
    mUmsDirtyRatio = 0;
    mVolManagerDisabled = 0;
}

VolumeManager::~VolumeManager() {
    delete mVolumes;
    delete mActiveContainers;
}

char *VolumeManager::asecHash(const char *id, char *buffer, size_t len) {
    static const char* digits = "0123456789abcdef";

    unsigned char sig[MD5_DIGEST_LENGTH];

    if (buffer == NULL) {
        SLOGE("Destination buffer is NULL");
        errno = ESPIPE;
        return NULL;
    } else if (id == NULL) {
        SLOGE("Source buffer is NULL");
        errno = ESPIPE;
        return NULL;
    } else if (len < MD5_ASCII_LENGTH_PLUS_NULL) {
        SLOGE("Target hash buffer size < %d bytes (%d)",
                MD5_ASCII_LENGTH_PLUS_NULL, len);
        errno = ESPIPE;
        return NULL;
    }

    MD5(reinterpret_cast<const unsigned char*>(id), strlen(id), sig);

    char *p = buffer;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        *p++ = digits[sig[i] >> 4];
        *p++ = digits[sig[i] & 0x0F];
    }
    *p = '\0';

    return buffer;
}

void VolumeManager::setDebug(bool enable) {
    mDebug = enable;
    VolumeCollection::iterator it;
    for (it = mVolumes->begin(); it != mVolumes->end(); ++it) {
        (*it)->setDebug(enable);
    }
}

int VolumeManager::start() {
    return 0;
}

int VolumeManager::stop() {
    return 0;
}

int VolumeManager::addVolume(Volume *v) {
    mVolumes->push_back(v);
    return 0;
}

void VolumeManager::handleBlockEvent(NetlinkEvent *evt) {
    const char *devpath = evt->findParam("DEVPATH");

    /* Lookup a volume to handle this device */
    VolumeCollection::iterator it;
    bool hit = false;
    for (it = mVolumes->begin(); it != mVolumes->end(); ++it) {
        if (!(*it)->handleBlockEvent(evt)) {
#ifdef NETLINK_DEBUG
            SLOGD("Device '%s' event handled by volume %s\n", devpath, (*it)->getLabel());
#endif
            hit = true;
            break;
        }
    }

    if (!hit) {
#ifdef NETLINK_DEBUG
        SLOGW("No volumes handled block event for '%s'", devpath);
#endif
    }
}

int VolumeManager::listVolumes(SocketClient *cli) {
    VolumeCollection::iterator i;

    for (i = mVolumes->begin(); i != mVolumes->end(); ++i) {
        char *buffer;
        asprintf(&buffer, "%s %s %d",
                 (*i)->getLabel(), (*i)->getMountpoint(),
                 (*i)->getState());
        cli->sendMsg(ResponseCode::VolumeListResult, buffer, false);
        free(buffer);
    }
    cli->sendMsg(ResponseCode::CommandOkay, "Volumes listed.", false);
    return 0;
}

int VolumeManager::formatVolume(const char *label) {
    Volume *v = lookupVolume(label);

    if (!v) {
        errno = ENOENT;
        return -1;
    }

    if (mVolManagerDisabled) {
        errno = EBUSY;
        return -1;
    }

    return v->formatVol();
}

int VolumeManager::getObbMountPath(const char *sourceFile, char *mountPath, int mountPathLen) {
    char idHash[33];
    if (!asecHash(sourceFile, idHash, sizeof(idHash))) {
        SLOGE("Hash of '%s' failed (%s)", sourceFile, strerror(errno));
        return -1;
    }

    memset(mountPath, 0, mountPathLen);
    snprintf(mountPath, mountPathLen, "%s/%s", Volume::LOOPDIR, idHash);

    if (access(mountPath, F_OK)) {
        errno = ENOENT;
        return -1;
    }

    return 0;
}

int VolumeManager::getAsecMountPath(const char *id, char *buffer, int maxlen) {
    char asecFileName[255];
    snprintf(asecFileName, sizeof(asecFileName), "%s/%s.asec", Volume::SEC_ASECDIR, id);

    memset(buffer, 0, maxlen);
    if (access(asecFileName, F_OK)) {
        errno = ENOENT;
        return -1;
    }

    snprintf(buffer, maxlen, "%s/%s", Volume::ASECDIR, id);
    return 0;
}

int VolumeManager::getAsecFilesystemPath(const char *id, char *buffer, int maxlen) {
    char asecFileName[255];
    snprintf(asecFileName, sizeof(asecFileName), "%s/%s.asec", Volume::SEC_ASECDIR, id);

    memset(buffer, 0, maxlen);
    if (access(asecFileName, F_OK)) {
        errno = ENOENT;
        return -1;
    }

    snprintf(buffer, maxlen, "%s", asecFileName);
    return 0;
}

int VolumeManager::createAsec(const char *id, unsigned int numSectors,
                              const char *fstype, const char *key, int ownerUid) {
    struct asec_superblock sb;
    memset(&sb, 0, sizeof(sb));

    sb.magic = ASEC_SB_MAGIC;
    sb.ver = ASEC_SB_VER;

    if (numSectors < ((1024*1024)/512)) {
        SLOGE("Invalid container size specified (%d sectors)", numSectors);
        errno = EINVAL;
        return -1;
    }

    if (lookupVolume(id)) {
        SLOGE("ASEC id '%s' currently exists", id);
        errno = EADDRINUSE;
        return -1;
    }

    char asecFileName[255];
    snprintf(asecFileName, sizeof(asecFileName), "%s/%s.asec", Volume::SEC_ASECDIR, id);

    if (!access(asecFileName, F_OK)) {
        SLOGE("ASEC file '%s' currently exists - destroy it first! (%s)",
             asecFileName, strerror(errno));
        errno = EADDRINUSE;
        return -1;
    }

    /*
     * Add some headroom
     */
    unsigned fatSize = (((numSectors * 4) / 512) + 1) * 2;
    unsigned numImgSectors = numSectors + fatSize + 2;

    if (numImgSectors % 63) {
        numImgSectors += (63 - (numImgSectors % 63));
    }

    // Add +1 for our superblock which is at the end
    if (Loop::createImageFile(asecFileName, numImgSectors + 1)) {
        SLOGE("ASEC image file creation failed (%s)", strerror(errno));
        return -1;
    }

    char idHash[33];
    if (!asecHash(id, idHash, sizeof(idHash))) {
        SLOGE("Hash of '%s' failed (%s)", id, strerror(errno));
        unlink(asecFileName);
        return -1;
    }

    char loopDevice[255];
    if (Loop::create(idHash, asecFileName, loopDevice, sizeof(loopDevice))) {
        SLOGE("ASEC loop device creation failed (%s)", strerror(errno));
        unlink(asecFileName);
        return -1;
    }

    char dmDevice[255];
    bool cleanupDm = false;

    if (strcmp(key, "none")) {
        // XXX: This is all we support for now
        sb.c_cipher = ASEC_SB_C_CIPHER_TWOFISH;
        if (Devmapper::create(idHash, loopDevice, key, numImgSectors, dmDevice,
                             sizeof(dmDevice))) {
            SLOGE("ASEC device mapping failed (%s)", strerror(errno));
            Loop::destroyByDevice(loopDevice);
            unlink(asecFileName);
            return -1;
        }
        cleanupDm = true;
    } else {
        sb.c_cipher = ASEC_SB_C_CIPHER_NONE;
        strcpy(dmDevice, loopDevice);
    }

    /*
     * Drop down the superblock at the end of the file
     */

    int sbfd = open(loopDevice, O_RDWR);
    if (sbfd < 0) {
        SLOGE("Failed to open new DM device for superblock write (%s)", strerror(errno));
        if (cleanupDm) {
            Devmapper::destroy(idHash);
        }
        Loop::destroyByDevice(loopDevice);
        unlink(asecFileName);
        return -1;
    }

    if (lseek(sbfd, (numImgSectors * 512), SEEK_SET) < 0) {
        close(sbfd);
        SLOGE("Failed to lseek for superblock (%s)", strerror(errno));
        if (cleanupDm) {
            Devmapper::destroy(idHash);
        }
        Loop::destroyByDevice(loopDevice);
        unlink(asecFileName);
        return -1;
    }

    if (write(sbfd, &sb, sizeof(sb)) != sizeof(sb)) {
        close(sbfd);
        SLOGE("Failed to write superblock (%s)", strerror(errno));
        if (cleanupDm) {
            Devmapper::destroy(idHash);
        }
        Loop::destroyByDevice(loopDevice);
        unlink(asecFileName);
        return -1;
    }
    close(sbfd);

    if (strcmp(fstype, "none")) {
        if (strcmp(fstype, "fat")) {
            SLOGW("Unknown fstype '%s' specified for container", fstype);
        }

        if (Fat::format(dmDevice, numImgSectors)) {
            SLOGE("ASEC FAT format failed (%s)", strerror(errno));
            if (cleanupDm) {
                Devmapper::destroy(idHash);
            }
            Loop::destroyByDevice(loopDevice);
            unlink(asecFileName);
            return -1;
        }
        char mountPoint[255];

        snprintf(mountPoint, sizeof(mountPoint), "%s/%s", Volume::ASECDIR, id);
        if (mkdir(mountPoint, 0777)) {
            if (errno != EEXIST) {
                SLOGE("Mountpoint creation failed (%s)", strerror(errno));
                if (cleanupDm) {
                    Devmapper::destroy(idHash);
                }
                Loop::destroyByDevice(loopDevice);
                unlink(asecFileName);
                return -1;
            }
        }

        if (Fat::doMount(dmDevice, mountPoint, false, false, false, ownerUid,
                         0, 0000, false)) {
            SLOGE("ASEC FAT mount failed (%s)", strerror(errno));
            if (cleanupDm) {
                Devmapper::destroy(idHash);
            }
            Loop::destroyByDevice(loopDevice);
            unlink(asecFileName);
            return -1;
        }
    } else {
        SLOGI("Created raw secure container %s (no filesystem)", id);
    }

    mActiveContainers->push_back(new ContainerData(strdup(id), ASEC));
    return 0;
}

int VolumeManager::finalizeAsec(const char *id) {
    char asecFileName[255];
    char loopDevice[255];
    char mountPoint[255];

    snprintf(asecFileName, sizeof(asecFileName), "%s/%s.asec", Volume::SEC_ASECDIR, id);

    char idHash[33];
    if (!asecHash(id, idHash, sizeof(idHash))) {
        SLOGE("Hash of '%s' failed (%s)", id, strerror(errno));
        return -1;
    }

    if (Loop::lookupActive(idHash, loopDevice, sizeof(loopDevice))) {
        SLOGE("Unable to finalize %s (%s)", id, strerror(errno));
        return -1;
    }

    snprintf(mountPoint, sizeof(mountPoint), "%s/%s", Volume::ASECDIR, id);
    // XXX:
    if (Fat::doMount(loopDevice, mountPoint, true, true, true, 0, 0, 0227, false)) {
        SLOGE("ASEC finalize mount failed (%s)", strerror(errno));
        return -1;
    }

    if (mDebug) {
        SLOGD("ASEC %s finalized", id);
    }
    return 0;
}

int VolumeManager::renameAsec(const char *id1, const char *id2) {
    char *asecFilename1;
    char *asecFilename2;
    char mountPoint[255];

    asprintf(&asecFilename1, "%s/%s.asec", Volume::SEC_ASECDIR, id1);
    asprintf(&asecFilename2, "%s/%s.asec", Volume::SEC_ASECDIR, id2);

    snprintf(mountPoint, sizeof(mountPoint), "%s/%s", Volume::ASECDIR, id1);
    if (isMountpointMounted(mountPoint)) {
        SLOGW("Rename attempt when src mounted");
        errno = EBUSY;
        goto out_err;
    }

    snprintf(mountPoint, sizeof(mountPoint), "%s/%s", Volume::ASECDIR, id2);
    if (isMountpointMounted(mountPoint)) {
        SLOGW("Rename attempt when dst mounted");
        errno = EBUSY;
        goto out_err;
    }

    if (!access(asecFilename2, F_OK)) {
        SLOGE("Rename attempt when dst exists");
        errno = EADDRINUSE;
        goto out_err;
    }

    if (rename(asecFilename1, asecFilename2)) {
        SLOGE("Rename of '%s' to '%s' failed (%s)", asecFilename1, asecFilename2, strerror(errno));
        goto out_err;
    }

    free(asecFilename1);
    free(asecFilename2);
    return 0;

out_err:
    free(asecFilename1);
    free(asecFilename2);
    return -1;
}

#define UNMOUNT_RETRIES 5
#define UNMOUNT_SLEEP_BETWEEN_RETRY_MS (1000 * 1000)
int VolumeManager::unmountAsec(const char *id, bool force) {
    char asecFileName[255];
    char mountPoint[255];

    snprintf(asecFileName, sizeof(asecFileName), "%s/%s.asec", Volume::SEC_ASECDIR, id);
    snprintf(mountPoint, sizeof(mountPoint), "%s/%s", Volume::ASECDIR, id);

    char idHash[33];
    if (!asecHash(id, idHash, sizeof(idHash))) {
        SLOGE("Hash of '%s' failed (%s)", id, strerror(errno));
        return -1;
    }

    return unmountLoopImage(id, idHash, asecFileName, mountPoint, force);
}

int VolumeManager::unmountObb(const char *fileName, bool force) {
    char mountPoint[255];

    char idHash[33];
    if (!asecHash(fileName, idHash, sizeof(idHash))) {
        SLOGE("Hash of '%s' failed (%s)", fileName, strerror(errno));
        return -1;
    }

    snprintf(mountPoint, sizeof(mountPoint), "%s/%s", Volume::LOOPDIR, idHash);

    return unmountLoopImage(fileName, idHash, fileName, mountPoint, force);
}

int VolumeManager::unmountLoopImage(const char *id, const char *idHash,
        const char *fileName, const char *mountPoint, bool force) {
    if (!isMountpointMounted(mountPoint)) {
        SLOGE("Unmount request for %s when not mounted", id);
        errno = ENOENT;
        return -1;
    }

    int i, rc;
    for (i = 1; i <= UNMOUNT_RETRIES; i++) {
        rc = umount(mountPoint);
        if (!rc) {
            break;
        }
        if (rc && (errno == EINVAL || errno == ENOENT)) {
            SLOGI("Container %s unmounted OK", id);
            rc = 0;
            break;
        }
        SLOGW("%s unmount attempt %d failed (%s)",
              id, i, strerror(errno));

        int action = 0; // default is to just complain

        if (force) {
            if (i > (UNMOUNT_RETRIES - 2))
                action = 2; // SIGKILL
            else if (i > (UNMOUNT_RETRIES - 3))
                action = 1; // SIGHUP
        }

        Process::killProcessesWithOpenFiles(mountPoint, action);
        usleep(UNMOUNT_SLEEP_BETWEEN_RETRY_MS);
    }

    if (rc) {
        errno = EBUSY;
        SLOGE("Failed to unmount container %s (%s)", id, strerror(errno));
        return -1;
    }

    int retries = 10;

    while(retries--) {
        if (!rmdir(mountPoint)) {
            break;
        }

        SLOGW("Failed to rmdir %s (%s)", mountPoint, strerror(errno));
        usleep(UNMOUNT_SLEEP_BETWEEN_RETRY_MS);
    }

    if (!retries) {
        SLOGE("Timed out trying to rmdir %s (%s)", mountPoint, strerror(errno));
    }

    if (Devmapper::destroy(idHash) && errno != ENXIO) {
        SLOGE("Failed to destroy devmapper instance (%s)", strerror(errno));
    }

    char loopDevice[255];
    if (!Loop::lookupActive(idHash, loopDevice, sizeof(loopDevice))) {
        Loop::destroyByDevice(loopDevice);
    } else {
        SLOGW("Failed to find loop device for {%s} (%s)", fileName, strerror(errno));
    }

    AsecIdCollection::iterator it;
    for (it = mActiveContainers->begin(); it != mActiveContainers->end(); ++it) {
        ContainerData* cd = *it;
        if (!strcmp(cd->id, id)) {
            free(*it);
            mActiveContainers->erase(it);
            break;
        }
    }
    if (it == mActiveContainers->end()) {
        SLOGW("mActiveContainers is inconsistent!");
    }
    return 0;
}

int VolumeManager::destroyAsec(const char *id, bool force) {
    char asecFileName[255];
    char mountPoint[255];

    snprintf(asecFileName, sizeof(asecFileName), "%s/%s.asec", Volume::SEC_ASECDIR, id);
    snprintf(mountPoint, sizeof(mountPoint), "%s/%s", Volume::ASECDIR, id);

    if (isMountpointMounted(mountPoint)) {
        if (mDebug) {
            SLOGD("Unmounting container before destroy");
        }
        if (unmountAsec(id, force)) {
            SLOGE("Failed to unmount asec %s for destroy (%s)", id, strerror(errno));
            return -1;
        }
    }

    if (unlink(asecFileName)) {
        SLOGE("Failed to unlink asec '%s' (%s)", asecFileName, strerror(errno));
        return -1;
    }

    if (mDebug) {
        SLOGD("ASEC %s destroyed", id);
    }
    return 0;
}

int VolumeManager::mountAsec(const char *id, const char *key, int ownerUid) {
    char asecFileName[255];
    char mountPoint[255];

    snprintf(asecFileName, sizeof(asecFileName), "%s/%s.asec", Volume::SEC_ASECDIR, id);
    snprintf(mountPoint, sizeof(mountPoint), "%s/%s", Volume::ASECDIR, id);

    if (isMountpointMounted(mountPoint)) {
        SLOGE("ASEC %s already mounted", id);
        errno = EBUSY;
        return -1;
    }

    char idHash[33];
    if (!asecHash(id, idHash, sizeof(idHash))) {
        SLOGE("Hash of '%s' failed (%s)", id, strerror(errno));
        return -1;
    }

    char loopDevice[255];
    if (Loop::lookupActive(idHash, loopDevice, sizeof(loopDevice))) {
        if (Loop::create(idHash, asecFileName, loopDevice, sizeof(loopDevice))) {
            SLOGE("ASEC loop device creation failed (%s)", strerror(errno));
            return -1;
        }
        if (mDebug) {
            SLOGD("New loop device created at %s", loopDevice);
        }
    } else {
        if (mDebug) {
            SLOGD("Found active loopback for %s at %s", asecFileName, loopDevice);
        }
    }

    char dmDevice[255];
    bool cleanupDm = false;
    int fd;
    unsigned int nr_sec = 0;

    if ((fd = open(loopDevice, O_RDWR)) < 0) {
        SLOGE("Failed to open loopdevice (%s)", strerror(errno));
        Loop::destroyByDevice(loopDevice);
        return -1;
    }

    if (ioctl(fd, BLKGETSIZE, &nr_sec)) {
        SLOGE("Failed to get loop size (%s)", strerror(errno));
        Loop::destroyByDevice(loopDevice);
        close(fd);
        return -1;
    }

    /*
     * Validate superblock
     */
    struct asec_superblock sb;
    memset(&sb, 0, sizeof(sb));
    if (lseek(fd, ((nr_sec-1) * 512), SEEK_SET) < 0) {
        SLOGE("lseek failed (%s)", strerror(errno));
        close(fd);
        Loop::destroyByDevice(loopDevice);
        return -1;
    }
    if (read(fd, &sb, sizeof(sb)) != sizeof(sb)) {
        SLOGE("superblock read failed (%s)", strerror(errno));
        close(fd);
        Loop::destroyByDevice(loopDevice);
        return -1;
    }

    close(fd);

    if (mDebug) {
        SLOGD("Container sb magic/ver (%.8x/%.2x)", sb.magic, sb.ver);
    }
    if (sb.magic != ASEC_SB_MAGIC || sb.ver != ASEC_SB_VER) {
        SLOGE("Bad container magic/version (%.8x/%.2x)", sb.magic, sb.ver);
        Loop::destroyByDevice(loopDevice);
        errno = EMEDIUMTYPE;
        return -1;
    }
    nr_sec--; // We don't want the devmapping to extend onto our superblock

    if (strcmp(key, "none")) {
        if (Devmapper::lookupActive(idHash, dmDevice, sizeof(dmDevice))) {
            if (Devmapper::create(idHash, loopDevice, key, nr_sec,
                                  dmDevice, sizeof(dmDevice))) {
                SLOGE("ASEC device mapping failed (%s)", strerror(errno));
                Loop::destroyByDevice(loopDevice);
                return -1;
            }
            if (mDebug) {
                SLOGD("New devmapper instance created at %s", dmDevice);
            }
        } else {
            if (mDebug) {
                SLOGD("Found active devmapper for %s at %s", asecFileName, dmDevice);
            }
        }
        cleanupDm = true;
    } else {
        strcpy(dmDevice, loopDevice);
    }

    if (mkdir(mountPoint, 0777)) {
        if (errno != EEXIST) {
            SLOGE("Mountpoint creation failed (%s)", strerror(errno));
            if (cleanupDm) {
                Devmapper::destroy(idHash);
            }
            Loop::destroyByDevice(loopDevice);
            return -1;
        }
    }

    if (Fat::doMount(dmDevice, mountPoint, true, false, true, ownerUid, 0,
                     0222, false)) {
//                     0227, false)) {
        SLOGE("ASEC mount failed (%s)", strerror(errno));
        if (cleanupDm) {
            Devmapper::destroy(idHash);
        }
        Loop::destroyByDevice(loopDevice);
        return -1;
    }

    mActiveContainers->push_back(new ContainerData(strdup(id), ASEC));
    if (mDebug) {
        SLOGD("ASEC %s mounted", id);
    }
    return 0;
}

/**
 * Mounts an image file <code>img</code>.
 */
int VolumeManager::mountObb(const char *img, const char *key, int ownerUid) {
    char mountPoint[255];

    char idHash[33];
    if (!asecHash(img, idHash, sizeof(idHash))) {
        SLOGE("Hash of '%s' failed (%s)", img, strerror(errno));
        return -1;
    }

    snprintf(mountPoint, sizeof(mountPoint), "%s/%s", Volume::LOOPDIR, idHash);

    if (isMountpointMounted(mountPoint)) {
        SLOGE("Image %s already mounted", img);
        errno = EBUSY;
        return -1;
    }

    char loopDevice[255];
    if (Loop::lookupActive(idHash, loopDevice, sizeof(loopDevice))) {
        if (Loop::create(idHash, img, loopDevice, sizeof(loopDevice))) {
            SLOGE("Image loop device creation failed (%s)", strerror(errno));
            return -1;
        }
        if (mDebug) {
            SLOGD("New loop device created at %s", loopDevice);
        }
    } else {
        if (mDebug) {
            SLOGD("Found active loopback for %s at %s", img, loopDevice);
        }
    }

    char dmDevice[255];
    bool cleanupDm = false;
    int fd;
    unsigned int nr_sec = 0;

    if ((fd = open(loopDevice, O_RDWR)) < 0) {
        SLOGE("Failed to open loopdevice (%s)", strerror(errno));
        Loop::destroyByDevice(loopDevice);
        return -1;
    }

    if (ioctl(fd, BLKGETSIZE, &nr_sec)) {
        SLOGE("Failed to get loop size (%s)", strerror(errno));
        Loop::destroyByDevice(loopDevice);
        close(fd);
        return -1;
    }

    close(fd);

    if (strcmp(key, "none")) {
        if (Devmapper::lookupActive(idHash, dmDevice, sizeof(dmDevice))) {
            if (Devmapper::create(idHash, loopDevice, key, nr_sec,
                                  dmDevice, sizeof(dmDevice))) {
                SLOGE("ASEC device mapping failed (%s)", strerror(errno));
                Loop::destroyByDevice(loopDevice);
                return -1;
            }
            if (mDebug) {
                SLOGD("New devmapper instance created at %s", dmDevice);
            }
        } else {
            if (mDebug) {
                SLOGD("Found active devmapper for %s at %s", img, dmDevice);
            }
        }
        cleanupDm = true;
    } else {
        strcpy(dmDevice, loopDevice);
    }

    if (mkdir(mountPoint, 0755)) {
        if (errno != EEXIST) {
            SLOGE("Mountpoint creation failed (%s)", strerror(errno));
            if (cleanupDm) {
                Devmapper::destroy(idHash);
            }
            Loop::destroyByDevice(loopDevice);
            return -1;
        }
    }

    if (Fat::doMount(dmDevice, mountPoint, true, false, true, ownerUid, 0,
                     0227, false)) {
        SLOGE("Image mount failed (%s)", strerror(errno));
        if (cleanupDm) {
            Devmapper::destroy(idHash);
        }
        Loop::destroyByDevice(loopDevice);
        return -1;
    }

    mActiveContainers->push_back(new ContainerData(strdup(img), OBB));
    if (mDebug) {
        SLOGD("Image %s mounted", img);
    }
    return 0;
}

int VolumeManager::mountVolume(const char *label) {
    Volume *v = lookupVolume(label);

    if (!v) {
        errno = ENOENT;
        return -1;
    }

    return v->mountVol();
}

int VolumeManager::listMountedObbs(SocketClient* cli) {
    char device[256];
    char mount_path[256];
    char rest[256];
    FILE *fp;
    char line[1024];

    if (!(fp = fopen("/proc/mounts", "r"))) {
        SLOGE("Error opening /proc/mounts (%s)", strerror(errno));
        return -1;
    }

    // Create a string to compare against that has a trailing slash
    int loopDirLen = sizeof(Volume::LOOPDIR);
    char loopDir[loopDirLen + 2];
    strcpy(loopDir, Volume::LOOPDIR);
    loopDir[loopDirLen++] = '/';
    loopDir[loopDirLen] = '\0';

    while(fgets(line, sizeof(line), fp)) {
        line[strlen(line)-1] = '\0';

        /*
         * Should look like:
         * /dev/block/loop0 /mnt/obb/fc99df1323fd36424f864dcb76b76d65 ...
         */
        sscanf(line, "%255s %255s %255s\n", device, mount_path, rest);

        if (!strncmp(mount_path, loopDir, loopDirLen)) {
            int fd = open(device, O_RDONLY);
            if (fd >= 0) {
                struct loop_info64 li;
                if (ioctl(fd, LOOP_GET_STATUS64, &li) >= 0) {
                    cli->sendMsg(ResponseCode::AsecListResult,
                            (const char*) li.lo_file_name, false);
                }
                close(fd);
            }
        }
    }

    fclose(fp);
    return 0;
}

int VolumeManager::shareEnabled(const char *label, const char *method, bool *enabled) {
    Volume *v = lookupVolume(label);

    if (!v) {
        errno = ENOENT;
        return -1;
    }

    if (strcmp(method, "ums")) {
        errno = ENOSYS;
        return -1;
    }

    if (v->getState() != Volume::State_Shared) {
        *enabled = false;
    } else {
        *enabled = true;
    }
    return 0;
}

int VolumeManager::shareVolume(const char *label, const char *method) {
    Volume *v = lookupVolume(label);

    if (!v) {
        errno = ENOENT;
        return -1;
    }

    /*
     * Eventually, we'll want to support additional share back-ends,
     * some of which may work while the media is mounted. For now,
     * we just support UMS
     */
    if (strcmp(method, "ums")) {
        errno = ENOSYS;
        return -1;
    }

    if (v->getState() == Volume::State_NoMedia) {
        errno = ENODEV;
        return -1;
    }

    if (v->getState() != Volume::State_Idle) {
        // You need to unmount manually befoe sharing
        errno = EBUSY;
        return -1;
    }

    if (mVolManagerDisabled) {
        errno = EBUSY;
        return -1;
    }

    dev_t d = v->getShareDevice();
    if ((MAJOR(d) == 0) && (MINOR(d) == 0)) {
        // This volume does not support raw disk access
        errno = EINVAL;
        return -1;
    }

    int fd;
    char nodepath[255];
    snprintf(nodepath,
             sizeof(nodepath), "/dev/block/vold/%d:%d",
             MAJOR(d), MINOR(d));

    if ((fd = open(MASS_STORAGE_FILE_PATH, O_WRONLY)) < 0) {
        SLOGE("Unable to open ums lunfile (%s)", strerror(errno));
        return -1;
    }

    if (write(fd, nodepath, strlen(nodepath)) < 0) {
        SLOGE("Unable to write to ums lunfile (%s)", strerror(errno));
        close(fd);
        return -1;
    }

    close(fd);
    v->handleVolumeShared();
    if (mUmsSharingCount++ == 0) {
        FILE* fp;
        mSavedDirtyRatio = -1; // in case we fail
        if ((fp = fopen("/proc/sys/vm/dirty_ratio", "r+"))) {
            char line[16];
            if (fgets(line, sizeof(line), fp) && sscanf(line, "%d", &mSavedDirtyRatio)) {
                fprintf(fp, "%d\n", mUmsDirtyRatio);
            } else {
                SLOGE("Failed to read dirty_ratio (%s)", strerror(errno));
            }
            fclose(fp);
        } else {
            SLOGE("Failed to open /proc/sys/vm/dirty_ratio (%s)", strerror(errno));
        }
    }
    return 0;
}

int VolumeManager::unshareVolume(const char *label, const char *method) {
    Volume *v = lookupVolume(label);

    if (!v) {
        errno = ENOENT;
        return -1;
    }

    if (strcmp(method, "ums")) {
        errno = ENOSYS;
        return -1;
    }

    if (v->getState() != Volume::State_Shared) {
        errno = EINVAL;
        return -1;
    }

    int fd;
    if ((fd = open(MASS_STORAGE_FILE_PATH, O_WRONLY)) < 0) {
        SLOGE("Unable to open ums lunfile (%s)", strerror(errno));
        return -1;
    }

    char ch = 0;
    if (write(fd, &ch, 1) < 0) {
        SLOGE("Unable to write to ums lunfile (%s)", strerror(errno));
        close(fd);
        return -1;
    }

    close(fd);
    v->handleVolumeUnshared();
    if (--mUmsSharingCount == 0 && mSavedDirtyRatio != -1) {
        FILE* fp;
        if ((fp = fopen("/proc/sys/vm/dirty_ratio", "r+"))) {
            fprintf(fp, "%d\n", mSavedDirtyRatio);
            fclose(fp);
        } else {
            SLOGE("Failed to open /proc/sys/vm/dirty_ratio (%s)", strerror(errno));
        }
        mSavedDirtyRatio = -1;
    }
    return 0;
}

extern "C" int vold_disableVol(const char *label) {
    VolumeManager *vm = VolumeManager::Instance();
    vm->disableVolumeManager();
    vm->unshareVolume(label, "ums");
    return vm->unmountVolume(label, true, false);
}

extern "C" int vold_getNumDirectVolumes(void) {
    VolumeManager *vm = VolumeManager::Instance();
    return vm->getNumDirectVolumes();
}

int VolumeManager::getNumDirectVolumes(void) {
    VolumeCollection::iterator i;
    int n=0;

    for (i = mVolumes->begin(); i != mVolumes->end(); ++i) {
        if ((*i)->getShareDevice() != (dev_t)0) {
            n++;
        }
    }
    return n;
}

extern "C" int vold_getDirectVolumeList(struct volume_info *vol_list) {
    VolumeManager *vm = VolumeManager::Instance();
    return vm->getDirectVolumeList(vol_list);
}

int VolumeManager::getDirectVolumeList(struct volume_info *vol_list) {
    VolumeCollection::iterator i;
    int n=0;
    dev_t d;

    for (i = mVolumes->begin(); i != mVolumes->end(); ++i) {
        if ((d=(*i)->getShareDevice()) != (dev_t)0) {
            (*i)->getVolInfo(&vol_list[n]);
            snprintf(vol_list[n].blk_dev, sizeof(vol_list[n].blk_dev),
                     "/dev/block/vold/%d:%d",MAJOR(d), MINOR(d));
            n++;
        }
    }

    return 0;
}

int VolumeManager::unmountVolume(const char *label, bool force, bool revert) {
    Volume *v = lookupVolume(label);

    if (!v) {
        errno = ENOENT;
        return -1;
    }

    if (v->getState() == Volume::State_NoMedia) {
        errno = ENODEV;
        return -1;
    }

    if (v->getState() != Volume::State_Mounted) {
        SLOGW("Attempt to unmount volume which isn't mounted (%d)\n",
             v->getState());
        errno = EBUSY;
        return UNMOUNT_NOT_MOUNTED_ERR;
    }

    cleanupAsec(v, force);

    return v->unmountVol(force, revert);
}

/*
 * Looks up a volume by it's label or mount-point
 */
Volume *VolumeManager::lookupVolume(const char *label) {
    VolumeCollection::iterator i;

    for (i = mVolumes->begin(); i != mVolumes->end(); ++i) {
        if (label[0] == '/') {
            if (!strcmp(label, (*i)->getMountpoint()))
                return (*i);
        } else {
            if (!strcmp(label, (*i)->getLabel()))
                return (*i);
        }
    }
    return NULL;
}

bool VolumeManager::isMountpointMounted(const char *mp)
{
    char device[256];
    char mount_path[256];
    char rest[256];
    FILE *fp;
    char line[1024];

    if (!(fp = fopen("/proc/mounts", "r"))) {
        SLOGE("Error opening /proc/mounts (%s)", strerror(errno));
        return false;
    }

    while(fgets(line, sizeof(line), fp)) {
        line[strlen(line)-1] = '\0';
        sscanf(line, "%255s %255s %255s\n", device, mount_path, rest);
        if (!strcmp(mount_path, mp)) {
            fclose(fp);
            return true;
        }
    }

    fclose(fp);
    return false;
}

int VolumeManager::cleanupAsec(Volume *v, bool force) {
    while(mActiveContainers->size()) {
        AsecIdCollection::iterator it = mActiveContainers->begin();
        ContainerData* cd = *it;
        SLOGI("Unmounting ASEC %s (dependant on %s)", cd->id, v->getMountpoint());
        if (cd->type == ASEC) {
            if (unmountAsec(cd->id, force)) {
                SLOGE("Failed to unmount ASEC %s (%s)", cd->id, strerror(errno));
                return -1;
            }
        } else if (cd->type == OBB) {
            if (unmountObb(cd->id, force)) {
                SLOGE("Failed to unmount OBB %s (%s)", cd->id, strerror(errno));
                return -1;
            }
        } else {
            SLOGE("Unknown container type %d!", cd->type);
            return -1;
        }
    }
    return 0;
}

