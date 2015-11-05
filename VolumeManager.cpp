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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <mntent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <linux/kdev_t.h>

#define LOG_TAG "Vold"

#include <openssl/md5.h>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <cutils/fs.h>
#include <cutils/log.h>

#include <selinux/android.h>

#include <sysutils/NetlinkEvent.h>

#include <private/android_filesystem_config.h>

#include "Benchmark.h"
#include "EmulatedVolume.h"
#include "VolumeManager.h"
#include "NetlinkManager.h"
#include "ResponseCode.h"
#include "Loop.h"
#include "fs/Ext4.h"
#include "fs/Vfat.h"
#include "Utils.h"
#include "Devmapper.h"
#include "Process.h"
#include "Asec.h"
#include "VoldUtil.h"
#include "cryptfs.h"

#define MASS_STORAGE_FILE_PATH  "/sys/class/android_usb/android0/f_mass_storage/lun/file"

#define ROUND_UP_POWER_OF_2(number, po2) (((!!(number & ((1U << po2) - 1))) << po2)\
                                         + (number & (~((1U << po2) - 1))))

using android::base::StringPrintf;

/*
 * Path to external storage where *only* root can access ASEC image files
 */
const char *VolumeManager::SEC_ASECDIR_EXT   = "/mnt/secure/asec";

/*
 * Path to internal storage where *only* root can access ASEC image files
 */
const char *VolumeManager::SEC_ASECDIR_INT   = "/data/app-asec";

/*
 * Path to where secure containers are mounted
 */
const char *VolumeManager::ASECDIR           = "/mnt/asec";

/*
 * Path to where OBBs are mounted
 */
const char *VolumeManager::LOOPDIR           = "/mnt/obb";

static const char* kUserMountPath = "/mnt/user";

static const unsigned int kMajorBlockMmc = 179;
static const unsigned int kMajorBlockExperimentalMin = 240;
static const unsigned int kMajorBlockExperimentalMax = 254;

/* writes superblock at end of file or device given by name */
static int writeSuperBlock(const char* name, struct asec_superblock *sb, unsigned int numImgSectors) {
    int sbfd = open(name, O_RDWR | O_CLOEXEC);
    if (sbfd < 0) {
        SLOGE("Failed to open %s for superblock write (%s)", name, strerror(errno));
        return -1;
    }

    if (lseek(sbfd, (numImgSectors * 512), SEEK_SET) < 0) {
        SLOGE("Failed to lseek for superblock (%s)", strerror(errno));
        close(sbfd);
        return -1;
    }

    if (write(sbfd, sb, sizeof(struct asec_superblock)) != sizeof(struct asec_superblock)) {
        SLOGE("Failed to write superblock (%s)", strerror(errno));
        close(sbfd);
        return -1;
    }
    close(sbfd);
    return 0;
}

static unsigned long adjustSectorNumExt4(unsigned long numSectors) {
    // Ext4 started to reserve 2% or 4096 clusters, whichever is smaller for
    // preventing costly operations or unexpected ENOSPC error.
    // Ext4::format() uses default block size without clustering.
    unsigned long clusterSectors = 4096 / 512;
    unsigned long reservedSectors = (numSectors * 2)/100 + (numSectors % 50 > 0);
    numSectors += reservedSectors > (4096 * clusterSectors) ? (4096 * clusterSectors) : reservedSectors;
    return ROUND_UP_POWER_OF_2(numSectors, 3);
}

static unsigned long adjustSectorNumFAT(unsigned long numSectors) {
    /*
    * Add some headroom
    */
    unsigned long fatSize = (((numSectors * 4) / 512) + 1) * 2;
    numSectors += fatSize + 2;
    /*
    * FAT is aligned to 32 kb with 512b sectors.
    */
    return ROUND_UP_POWER_OF_2(numSectors, 6);
}

static int setupLoopDevice(char* buffer, size_t len, const char* asecFileName, const char* idHash, bool debug) {
    if (Loop::lookupActive(idHash, buffer, len)) {
        if (Loop::create(idHash, asecFileName, buffer, len)) {
            SLOGE("ASEC loop device creation failed for %s (%s)", asecFileName, strerror(errno));
            return -1;
        }
        if (debug) {
            SLOGD("New loop device created at %s", buffer);
        }
    } else {
        if (debug) {
            SLOGD("Found active loopback for %s at %s", asecFileName, buffer);
        }
    }
    return 0;
}

static int setupDevMapperDevice(char* buffer, size_t len, const char* loopDevice, const char* asecFileName, const char* key, const char* idHash , unsigned long numImgSectors, bool* createdDMDevice, bool debug) {
    if (strcmp(key, "none")) {
        if (Devmapper::lookupActive(idHash, buffer, len)) {
            if (Devmapper::create(idHash, loopDevice, key, numImgSectors,
                                  buffer, len)) {
                SLOGE("ASEC device mapping failed for %s (%s)", asecFileName, strerror(errno));
                return -1;
            }
            if (debug) {
                SLOGD("New devmapper instance created at %s", buffer);
            }
        } else {
            if (debug) {
                SLOGD("Found active devmapper for %s at %s", asecFileName, buffer);
            }
        }
        *createdDMDevice = true;
    } else {
        strcpy(buffer, loopDevice);
        *createdDMDevice = false;
    }
    return 0;
}

static void waitForDevMapper(const char *dmDevice) {
    /*
     * Wait for the device mapper node to be created. Sometimes it takes a
     * while. Wait for up to 1 second. We could also inspect incoming uevents,
     * but that would take more effort.
     */
    int tries = 25;
    while (tries--) {
        if (!access(dmDevice, F_OK) || errno != ENOENT) {
            break;
        }
        usleep(40 * 1000);
    }
}

VolumeManager *VolumeManager::sInstance = NULL;

VolumeManager *VolumeManager::Instance() {
    if (!sInstance)
        sInstance = new VolumeManager();
    return sInstance;
}

VolumeManager::VolumeManager() {
    mDebug = false;
    mActiveContainers = new AsecIdCollection();
    mBroadcaster = NULL;
    mUmsSharingCount = 0;
    mSavedDirtyRatio = -1;
    // set dirty ratio to 0 when UMS is active
    mUmsDirtyRatio = 0;
}

VolumeManager::~VolumeManager() {
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
        SLOGE("Target hash buffer size < %d bytes (%zu)",
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

int VolumeManager::setDebug(bool enable) {
    mDebug = enable;
    return 0;
}

int VolumeManager::start() {
    // Always start from a clean slate by unmounting everything in
    // directories that we own, in case we crashed.
    unmountAll();

    // Assume that we always have an emulated volume on internal
    // storage; the framework will decide if it should be mounted.
    CHECK(mInternalEmulated == nullptr);
    mInternalEmulated = std::shared_ptr<android::vold::VolumeBase>(
            new android::vold::EmulatedVolume("/data/media"));
    mInternalEmulated->create();

    return 0;
}

int VolumeManager::stop() {
    CHECK(mInternalEmulated != nullptr);
    mInternalEmulated->destroy();
    mInternalEmulated = nullptr;
    return 0;
}

void VolumeManager::handleBlockEvent(NetlinkEvent *evt) {
    std::lock_guard<std::mutex> lock(mLock);

    if (mDebug) {
        LOG(VERBOSE) << "----------------";
        LOG(VERBOSE) << "handleBlockEvent with action " << (int) evt->getAction();
        evt->dump();
    }

    std::string eventPath(evt->findParam("DEVPATH")?evt->findParam("DEVPATH"):"");
    std::string devType(evt->findParam("DEVTYPE")?evt->findParam("DEVTYPE"):"");

    if (devType != "disk") return;

    int major = atoi(evt->findParam("MAJOR"));
    int minor = atoi(evt->findParam("MINOR"));
    dev_t device = makedev(major, minor);

    switch (evt->getAction()) {
    case NetlinkEvent::Action::kAdd: {
        for (auto source : mDiskSources) {
            if (source->matches(eventPath)) {
                // For now, assume that MMC and virtio-blk (the latter is
                // emulator-specific; see Disk.cpp for details) devices are SD,
                // and that everything else is USB
                int flags = source->getFlags();
                if (major == kMajorBlockMmc
                    || (android::vold::IsRunningInEmulator()
                    && major >= (int) kMajorBlockExperimentalMin
                    && major <= (int) kMajorBlockExperimentalMax)) {
                    flags |= android::vold::Disk::Flags::kSd;
                } else {
                    flags |= android::vold::Disk::Flags::kUsb;
                }

                android::vold::Disk* disk = (source->getPartNum() == -1) ?
                        new android::vold::Disk(eventPath, device,
                                source->getNickname(), flags) :
                        new android::vold::DiskPartition(eventPath, device,
                                source->getNickname(), flags,
                                source->getPartNum(),
                                source->getFsType(), source->getMntOpts());
                disk->create();
                mDisks.push_back(std::shared_ptr<android::vold::Disk>(disk));
                break;
            }
        }
        break;
    }
    case NetlinkEvent::Action::kChange: {
        LOG(DEBUG) << "Disk at " << major << ":" << minor << " changed";
        for (auto disk : mDisks) {
            if (disk->getDevice() == device) {
                disk->readMetadata();
                disk->readPartitions();
            }
        }
        break;
    }
    case NetlinkEvent::Action::kRemove: {
        auto i = mDisks.begin();
        while (i != mDisks.end()) {
            if ((*i)->getDevice() == device) {
                (*i)->destroy();
                i = mDisks.erase(i);
            } else {
                ++i;
            }
        }
        break;
    }
    default: {
        LOG(WARNING) << "Unexpected block event action " << (int) evt->getAction();
        break;
    }
    }
}

void VolumeManager::addDiskSource(const std::shared_ptr<DiskSource>& diskSource) {
    mDiskSources.push_back(diskSource);
}

std::shared_ptr<android::vold::Disk> VolumeManager::findDisk(const std::string& id) {
    for (auto disk : mDisks) {
        if (disk->getId() == id) {
            return disk;
        }
    }
    return nullptr;
}

std::shared_ptr<android::vold::VolumeBase> VolumeManager::findVolume(const std::string& id) {
    if (mInternalEmulated->getId() == id) {
        return mInternalEmulated;
    }
    for (auto disk : mDisks) {
        auto vol = disk->findVolume(id);
        if (vol != nullptr) {
            return vol;
        }
    }
    return nullptr;
}

void VolumeManager::listVolumes(android::vold::VolumeBase::Type type,
        std::list<std::string>& list) {
    list.clear();
    for (auto disk : mDisks) {
        disk->listVolumes(type, list);
    }
}

nsecs_t VolumeManager::benchmarkPrivate(const std::string& id) {
    std::string path;
    if (id == "private" || id == "null") {
        path = "/data";
    } else {
        auto vol = findVolume(id);
        if (vol != nullptr && vol->getState() == android::vold::VolumeBase::State::kMounted) {
            path = vol->getPath();
        }
    }

    if (path.empty()) {
        LOG(WARNING) << "Failed to find volume for " << id;
        return -1;
    }

    return android::vold::BenchmarkPrivate(path);
}

int VolumeManager::forgetPartition(const std::string& partGuid) {
    std::string normalizedGuid;
    if (android::vold::NormalizeHex(partGuid, normalizedGuid)) {
        LOG(WARNING) << "Invalid GUID " << partGuid;
        return -1;
    }

    std::string keyPath = android::vold::BuildKeyPath(normalizedGuid);
    if (unlink(keyPath.c_str()) != 0) {
        LOG(ERROR) << "Failed to unlink " << keyPath;
        return -1;
    }

    return 0;
}

int VolumeManager::linkPrimary(userid_t userId) {
    std::string source(mPrimary->getPath());
    if (mPrimary->getType() == android::vold::VolumeBase::Type::kEmulated) {
        source = StringPrintf("%s/%d", source.c_str(), userId);
        fs_prepare_dir(source.c_str(), 0755, AID_ROOT, AID_ROOT);
    }

    std::string target(StringPrintf("/mnt/user/%d/primary", userId));
    if (TEMP_FAILURE_RETRY(unlink(target.c_str()))) {
        if (errno != ENOENT) {
            SLOGW("Failed to unlink %s: %s", target.c_str(), strerror(errno));
        }
    }
    LOG(DEBUG) << "Linking " << source << " to " << target;
    if (TEMP_FAILURE_RETRY(symlink(source.c_str(), target.c_str()))) {
        SLOGW("Failed to link %s to %s: %s", source.c_str(), target.c_str(),
                strerror(errno));
        return -errno;
    }
    return 0;
}

int VolumeManager::onUserAdded(userid_t userId, int userSerialNumber) {
    mAddedUsers[userId] = userSerialNumber;
    return 0;
}

int VolumeManager::onUserRemoved(userid_t userId) {
    mAddedUsers.erase(userId);
    return 0;
}

int VolumeManager::onUserStarted(userid_t userId) {
    // Note that sometimes the system will spin up processes from Zygote
    // before actually starting the user, so we're okay if Zygote
    // already created this directory.
    std::string path(StringPrintf("%s/%d", kUserMountPath, userId));
    fs_prepare_dir(path.c_str(), 0755, AID_ROOT, AID_ROOT);

    mStartedUsers.insert(userId);
    if (mPrimary) {
        linkPrimary(userId);
    }
    return 0;
}

int VolumeManager::onUserStopped(userid_t userId) {
    mStartedUsers.erase(userId);
    return 0;
}

int VolumeManager::setPrimary(const std::shared_ptr<android::vold::VolumeBase>& vol) {
    mPrimary = vol;
    for (userid_t userId : mStartedUsers) {
        linkPrimary(userId);
    }
    return 0;
}

static int unmount_tree(const char* path) {
    size_t path_len = strlen(path);

    FILE* fp = setmntent("/proc/mounts", "r");
    if (fp == NULL) {
        ALOGE("Error opening /proc/mounts: %s", strerror(errno));
        return -errno;
    }

    // Some volumes can be stacked on each other, so force unmount in
    // reverse order to give us the best chance of success.
    std::list<std::string> toUnmount;
    mntent* mentry;
    while ((mentry = getmntent(fp)) != NULL) {
        if (strncmp(mentry->mnt_dir, path, path_len) == 0) {
            toUnmount.push_front(std::string(mentry->mnt_dir));
        }
    }
    endmntent(fp);

    for (auto path : toUnmount) {
        if (umount2(path.c_str(), MNT_DETACH)) {
            ALOGW("Failed to unmount %s: %s", path.c_str(), strerror(errno));
        }
    }
    return 0;
}

int VolumeManager::remountUid(uid_t uid, const std::string& mode) {
    LOG(DEBUG) << "Remounting " << uid << " as mode " << mode;

    DIR* dir;
    struct dirent* de;
    char rootName[PATH_MAX];
    char pidName[PATH_MAX];
    int pidFd;
    int nsFd;
    struct stat sb;
    pid_t child;

    if (!(dir = opendir("/proc"))) {
        PLOG(ERROR) << "Failed to opendir";
        return -1;
    }

    // Figure out root namespace to compare against below
    if (android::vold::SaneReadLinkAt(dirfd(dir), "1/ns/mnt", rootName, PATH_MAX) == -1) {
        PLOG(ERROR) << "Failed to readlink";
        closedir(dir);
        return -1;
    }

    // Poke through all running PIDs look for apps running as UID
    while ((de = readdir(dir))) {
        pidFd = -1;
        nsFd = -1;

        pidFd = openat(dirfd(dir), de->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (pidFd < 0) {
            goto next;
        }
        if (fstat(pidFd, &sb) != 0) {
            PLOG(WARNING) << "Failed to stat " << de->d_name;
            goto next;
        }
        if (sb.st_uid != uid) {
            goto next;
        }

        // Matches so far, but refuse to touch if in root namespace
        LOG(DEBUG) << "Found matching PID " << de->d_name;
        if (android::vold::SaneReadLinkAt(pidFd, "ns/mnt", pidName, PATH_MAX) == -1) {
            PLOG(WARNING) << "Failed to read namespace for " << de->d_name;
            goto next;
        }
        if (!strcmp(rootName, pidName)) {
            LOG(WARNING) << "Skipping due to root namespace";
            goto next;
        }

        // We purposefully leave the namespace open across the fork
        nsFd = openat(pidFd, "ns/mnt", O_RDONLY);
        if (nsFd < 0) {
            PLOG(WARNING) << "Failed to open namespace for " << de->d_name;
            goto next;
        }

        if (!(child = fork())) {
            if (setns(nsFd, CLONE_NEWNS) != 0) {
                PLOG(ERROR) << "Failed to setns for " << de->d_name;
                _exit(1);
            }

            unmount_tree("/storage");

            std::string storageSource;
            if (mode == "default") {
                storageSource = "/mnt/runtime/default";
            } else if (mode == "read") {
                storageSource = "/mnt/runtime/read";
            } else if (mode == "write") {
                storageSource = "/mnt/runtime/write";
            } else {
                // Sane default of no storage visible
                _exit(0);
            }
            if (TEMP_FAILURE_RETRY(mount(storageSource.c_str(), "/storage",
                    NULL, MS_BIND | MS_REC | MS_SLAVE, NULL)) == -1) {
                PLOG(ERROR) << "Failed to mount " << storageSource << " for "
                        << de->d_name;
                _exit(1);
            }

            // Mount user-specific symlink helper into place
            userid_t user_id = multiuser_get_user_id(uid);
            std::string userSource(StringPrintf("/mnt/user/%d", user_id));
            if (TEMP_FAILURE_RETRY(mount(userSource.c_str(), "/storage/self",
                    NULL, MS_BIND, NULL)) == -1) {
                PLOG(ERROR) << "Failed to mount " << userSource << " for "
                        << de->d_name;
                _exit(1);
            }

            _exit(0);
        }

        if (child == -1) {
            PLOG(ERROR) << "Failed to fork";
            goto next;
        } else {
            TEMP_FAILURE_RETRY(waitpid(child, nullptr, 0));
        }

next:
        close(nsFd);
        close(pidFd);
    }
    closedir(dir);
    return 0;
}

int VolumeManager::reset() {
    // Tear down all existing disks/volumes and start from a blank slate so
    // newly connected framework hears all events.
    mInternalEmulated->destroy();
    mInternalEmulated->create();
    for (auto disk : mDisks) {
        disk->destroy();
        disk->create();
    }
    mAddedUsers.clear();
    mStartedUsers.clear();
    return 0;
}

int VolumeManager::shutdown() {
    mInternalEmulated->destroy();
    for (auto disk : mDisks) {
        disk->destroy();
    }
    mDisks.clear();
    return 0;
}

int VolumeManager::unmountAll() {
    std::lock_guard<std::mutex> lock(mLock);

    // First, try gracefully unmounting all known devices
    if (mInternalEmulated != nullptr) {
        mInternalEmulated->unmount();
    }
    for (auto disk : mDisks) {
        disk->unmountAll();
    }

    // Worst case we might have some stale mounts lurking around, so
    // force unmount those just to be safe.
    FILE* fp = setmntent("/proc/mounts", "r");
    if (fp == NULL) {
        SLOGE("Error opening /proc/mounts: %s", strerror(errno));
        return -errno;
    }

    // Some volumes can be stacked on each other, so force unmount in
    // reverse order to give us the best chance of success.
    std::list<std::string> toUnmount;
    mntent* mentry;
    while ((mentry = getmntent(fp)) != NULL) {
        if (strncmp(mentry->mnt_dir, "/mnt/", 5) == 0
                || strncmp(mentry->mnt_dir, "/storage/", 9) == 0) {
            toUnmount.push_front(std::string(mentry->mnt_dir));
        }
    }
    endmntent(fp);

    for (auto path : toUnmount) {
        SLOGW("Tearing down stale mount %s", path.c_str());
        android::vold::ForceUnmount(path);
    }

    return 0;
}

int VolumeManager::getObbMountPath(const char *sourceFile, char *mountPath, int mountPathLen) {
    char idHash[33];
    if (!asecHash(sourceFile, idHash, sizeof(idHash))) {
        SLOGE("Hash of '%s' failed (%s)", sourceFile, strerror(errno));
        return -1;
    }

    memset(mountPath, 0, mountPathLen);
    int written = snprintf(mountPath, mountPathLen, "%s/%s", VolumeManager::LOOPDIR, idHash);
    if ((written < 0) || (written >= mountPathLen)) {
        errno = EINVAL;
        return -1;
    }

    if (access(mountPath, F_OK)) {
        errno = ENOENT;
        return -1;
    }

    return 0;
}

int VolumeManager::getAsecMountPath(const char *id, char *buffer, int maxlen) {
    char asecFileName[255];

    if (!isLegalAsecId(id)) {
        SLOGE("getAsecMountPath: Invalid asec id \"%s\"", id);
        errno = EINVAL;
        return -1;
    }

    if (findAsec(id, asecFileName, sizeof(asecFileName))) {
        SLOGE("Couldn't find ASEC %s", id);
        return -1;
    }

    memset(buffer, 0, maxlen);
    if (access(asecFileName, F_OK)) {
        errno = ENOENT;
        return -1;
    }

    int written = snprintf(buffer, maxlen, "%s/%s", VolumeManager::ASECDIR, id);
    if ((written < 0) || (written >= maxlen)) {
        SLOGE("getAsecMountPath failed for %s: couldn't construct path in buffer", id);
        errno = EINVAL;
        return -1;
    }

    return 0;
}

int VolumeManager::getAsecFilesystemPath(const char *id, char *buffer, int maxlen) {
    char asecFileName[255];

    if (!isLegalAsecId(id)) {
        SLOGE("getAsecFilesystemPath: Invalid asec id \"%s\"", id);
        errno = EINVAL;
        return -1;
    }

    if (findAsec(id, asecFileName, sizeof(asecFileName))) {
        SLOGE("Couldn't find ASEC %s", id);
        return -1;
    }

    memset(buffer, 0, maxlen);
    if (access(asecFileName, F_OK)) {
        errno = ENOENT;
        return -1;
    }

    int written = snprintf(buffer, maxlen, "%s", asecFileName);
    if ((written < 0) || (written >= maxlen)) {
        errno = EINVAL;
        return -1;
    }

    return 0;
}

int VolumeManager::createAsec(const char *id, unsigned long numSectors, const char *fstype,
        const char *key, const int ownerUid, bool isExternal) {
    struct asec_superblock sb;
    memset(&sb, 0, sizeof(sb));

    if (!isLegalAsecId(id)) {
        SLOGE("createAsec: Invalid asec id \"%s\"", id);
        errno = EINVAL;
        return -1;
    }

    const bool wantFilesystem = strcmp(fstype, "none");
    bool usingExt4 = false;
    if (wantFilesystem) {
        usingExt4 = !strcmp(fstype, "ext4");
        if (usingExt4) {
            sb.c_opts |= ASEC_SB_C_OPTS_EXT4;
        } else if (strcmp(fstype, "fat")) {
            SLOGE("Invalid filesystem type %s", fstype);
            errno = EINVAL;
            return -1;
        }
    }

    sb.magic = ASEC_SB_MAGIC;
    sb.ver = ASEC_SB_VER;

    if (numSectors < ((1024*1024)/512)) {
        SLOGE("Invalid container size specified (%lu sectors)", numSectors);
        errno = EINVAL;
        return -1;
    }

    char asecFileName[255];

    if (!findAsec(id, asecFileName, sizeof(asecFileName))) {
        SLOGE("ASEC file '%s' currently exists - destroy it first! (%s)",
                asecFileName, strerror(errno));
        errno = EADDRINUSE;
        return -1;
    }

    const char *asecDir = isExternal ? VolumeManager::SEC_ASECDIR_EXT : VolumeManager::SEC_ASECDIR_INT;

    int written = snprintf(asecFileName, sizeof(asecFileName), "%s/%s.asec", asecDir, id);
    if ((written < 0) || (size_t(written) >= sizeof(asecFileName))) {
        errno = EINVAL;
        return -1;
    }

    if (!access(asecFileName, F_OK)) {
        SLOGE("ASEC file '%s' currently exists - destroy it first! (%s)",
                asecFileName, strerror(errno));
        errno = EADDRINUSE;
        return -1;
    }

    unsigned long numImgSectors;
    if (usingExt4)
        numImgSectors = adjustSectorNumExt4(numSectors);
    else
        numImgSectors = adjustSectorNumFAT(numSectors);

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
    if (writeSuperBlock(loopDevice, &sb, numImgSectors)) {
        if (cleanupDm) {
            Devmapper::destroy(idHash);
        }
        Loop::destroyByDevice(loopDevice);
        unlink(asecFileName);
        return -1;
    }

    if (wantFilesystem) {
        int formatStatus;
        char mountPoint[255];

        int written = snprintf(mountPoint, sizeof(mountPoint), "%s/%s", VolumeManager::ASECDIR, id);
        if ((written < 0) || (size_t(written) >= sizeof(mountPoint))) {
            SLOGE("ASEC fs format failed: couldn't construct mountPoint");
            if (cleanupDm) {
                Devmapper::destroy(idHash);
            }
            Loop::destroyByDevice(loopDevice);
            unlink(asecFileName);
            return -1;
        }

        if (usingExt4) {
            formatStatus = android::vold::ext4::Format(dmDevice, numImgSectors, mountPoint);
        } else {
            formatStatus = android::vold::vfat::Format(dmDevice, numImgSectors);
        }

        if (formatStatus < 0) {
            SLOGE("ASEC fs format failed (%s)", strerror(errno));
            if (cleanupDm) {
                Devmapper::destroy(idHash);
            }
            Loop::destroyByDevice(loopDevice);
            unlink(asecFileName);
            return -1;
        }

        if (mkdir(mountPoint, 0000)) {
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

        int mountStatus;
        if (usingExt4) {
            mountStatus = android::vold::ext4::Mount(dmDevice, mountPoint,
                    false, false, false);
        } else {
            mountStatus = android::vold::vfat::Mount(dmDevice, mountPoint,
                    false, false, false, ownerUid, 0, 0000, false);
        }

        if (mountStatus) {
            SLOGE("ASEC FAT mount failed (%s)", strerror(errno));
            if (cleanupDm) {
                Devmapper::destroy(idHash);
            }
            Loop::destroyByDevice(loopDevice);
            unlink(asecFileName);
            return -1;
        }

        if (usingExt4) {
            int dirfd = open(mountPoint, O_DIRECTORY | O_CLOEXEC);
            if (dirfd >= 0) {
                if (fchown(dirfd, ownerUid, AID_SYSTEM)
                        || fchmod(dirfd, S_IRUSR | S_IWUSR | S_IXUSR | S_ISGID | S_IRGRP | S_IXGRP)) {
                    SLOGI("Cannot chown/chmod new ASEC mount point %s", mountPoint);
                }
                close(dirfd);
            }
        }
    } else {
        SLOGI("Created raw secure container %s (no filesystem)", id);
    }

    mActiveContainers->push_back(new ContainerData(strdup(id), ASEC));
    return 0;
}

int VolumeManager::resizeAsec(const char *id, unsigned long numSectors, const char *key) {
    char asecFileName[255];
    char mountPoint[255];
    bool cleanupDm = false;

    if (!isLegalAsecId(id)) {
        SLOGE("resizeAsec: Invalid asec id \"%s\"", id);
        errno = EINVAL;
        return -1;
    }

    if (findAsec(id, asecFileName, sizeof(asecFileName))) {
        SLOGE("Couldn't find ASEC %s", id);
        return -1;
    }

    int written = snprintf(mountPoint, sizeof(mountPoint), "%s/%s", VolumeManager::ASECDIR, id);
    if ((written < 0) || (size_t(written) >= sizeof(mountPoint))) {
       SLOGE("ASEC resize failed for %s: couldn't construct mountpoint", id);
       return -1;
    }

    if (isMountpointMounted(mountPoint)) {
       SLOGE("ASEC %s mounted. Unmount before resizing", id);
       errno = EBUSY;
       return -1;
    }

    struct asec_superblock sb;
    int fd;
    unsigned long oldNumSec = 0;

    if ((fd = open(asecFileName, O_RDONLY | O_CLOEXEC)) < 0) {
        SLOGE("Failed to open ASEC file (%s)", strerror(errno));
        return -1;
    }

    struct stat info;
    if (fstat(fd, &info) < 0) {
        SLOGE("Failed to get file size (%s)", strerror(errno));
        close(fd);
        return -1;
    }

    oldNumSec = info.st_size / 512;

    unsigned long numImgSectors;
    if (sb.c_opts & ASEC_SB_C_OPTS_EXT4)
        numImgSectors = adjustSectorNumExt4(numSectors);
    else
        numImgSectors = adjustSectorNumFAT(numSectors);
    /*
     *  add one block for the superblock
     */
    SLOGD("Resizing from %lu sectors to %lu sectors", oldNumSec, numImgSectors + 1);
    if (oldNumSec == numImgSectors + 1) {
        SLOGW("Size unchanged; ignoring resize request");
        return 0;
    } else if (oldNumSec > numImgSectors + 1) {
        SLOGE("Only growing is currently supported.");
        close(fd);
        return -1;
    }

    /*
     * Try to read superblock.
     */
    memset(&sb, 0, sizeof(struct asec_superblock));
    if (lseek(fd, ((oldNumSec - 1) * 512), SEEK_SET) < 0) {
        SLOGE("lseek failed (%s)", strerror(errno));
        close(fd);
        return -1;
    }
    if (read(fd, &sb, sizeof(struct asec_superblock)) != sizeof(struct asec_superblock)) {
        SLOGE("superblock read failed (%s)", strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);

    if (mDebug) {
        SLOGD("Container sb magic/ver (%.8x/%.2x)", sb.magic, sb.ver);
    }
    if (sb.magic != ASEC_SB_MAGIC || sb.ver != ASEC_SB_VER) {
        SLOGE("Bad container magic/version (%.8x/%.2x)", sb.magic, sb.ver);
        errno = EMEDIUMTYPE;
        return -1;
    }

    if (!(sb.c_opts & ASEC_SB_C_OPTS_EXT4)) {
        SLOGE("Only ext4 partitions are supported for resize");
        errno = EINVAL;
        return -1;
    }

    if (Loop::resizeImageFile(asecFileName, numImgSectors + 1)) {
        SLOGE("Resize of ASEC image file failed. Could not resize %s", id);
        return -1;
    }

    /*
     * Drop down a copy of the superblock at the end of the file
     */
    if (writeSuperBlock(asecFileName, &sb, numImgSectors))
        goto fail;

    char idHash[33];
    if (!asecHash(id, idHash, sizeof(idHash))) {
        SLOGE("Hash of '%s' failed (%s)", id, strerror(errno));
        goto fail;
    }

    char loopDevice[255];
    if (setupLoopDevice(loopDevice, sizeof(loopDevice), asecFileName, idHash, mDebug))
        goto fail;

    char dmDevice[255];

    if (setupDevMapperDevice(dmDevice, sizeof(dmDevice), loopDevice, asecFileName, key, idHash, numImgSectors, &cleanupDm, mDebug)) {
        Loop::destroyByDevice(loopDevice);
        goto fail;
    }

    /*
     * Wait for the device mapper node to be created.
     */
    waitForDevMapper(dmDevice);

    if (android::vold::ext4::Resize(dmDevice, numImgSectors)) {
        SLOGE("Unable to resize %s (%s)", id, strerror(errno));
        if (cleanupDm) {
            Devmapper::destroy(idHash);
        }
        Loop::destroyByDevice(loopDevice);
        goto fail;
    }

    return 0;
fail:
    Loop::resizeImageFile(asecFileName, oldNumSec);
    return -1;
}

int VolumeManager::finalizeAsec(const char *id) {
    char asecFileName[255];
    char loopDevice[255];
    char mountPoint[255];

    if (!isLegalAsecId(id)) {
        SLOGE("finalizeAsec: Invalid asec id \"%s\"", id);
        errno = EINVAL;
        return -1;
    }

    if (findAsec(id, asecFileName, sizeof(asecFileName))) {
        SLOGE("Couldn't find ASEC %s", id);
        return -1;
    }

    char idHash[33];
    if (!asecHash(id, idHash, sizeof(idHash))) {
        SLOGE("Hash of '%s' failed (%s)", id, strerror(errno));
        return -1;
    }

    if (Loop::lookupActive(idHash, loopDevice, sizeof(loopDevice))) {
        SLOGE("Unable to finalize %s (%s)", id, strerror(errno));
        return -1;
    }

    unsigned long nr_sec = 0;
    struct asec_superblock sb;

    if (Loop::lookupInfo(loopDevice, &sb, &nr_sec)) {
        return -1;
    }

    int written = snprintf(mountPoint, sizeof(mountPoint), "%s/%s", VolumeManager::ASECDIR, id);
    if ((written < 0) || (size_t(written) >= sizeof(mountPoint))) {
        SLOGE("ASEC finalize failed: couldn't construct mountPoint");
        return -1;
    }

    int result = 0;
    if (sb.c_opts & ASEC_SB_C_OPTS_EXT4) {
        result = android::vold::ext4::Mount(loopDevice, mountPoint,
                true, true, true);
    } else {
        result = android::vold::vfat::Mount(loopDevice, mountPoint,
                true, true, true, 0, 0, 0227, false);
    }

    if (result) {
        SLOGE("ASEC finalize mount failed (%s)", strerror(errno));
        return -1;
    }

    if (mDebug) {
        SLOGD("ASEC %s finalized", id);
    }
    return 0;
}

int VolumeManager::fixupAsecPermissions(const char *id, gid_t gid, const char* filename) {
    char asecFileName[255];
    char loopDevice[255];
    char mountPoint[255];

    if (gid < AID_APP) {
        SLOGE("Group ID is not in application range");
        return -1;
    }

    if (!isLegalAsecId(id)) {
        SLOGE("fixupAsecPermissions: Invalid asec id \"%s\"", id);
        errno = EINVAL;
        return -1;
    }

    if (findAsec(id, asecFileName, sizeof(asecFileName))) {
        SLOGE("Couldn't find ASEC %s", id);
        return -1;
    }

    char idHash[33];
    if (!asecHash(id, idHash, sizeof(idHash))) {
        SLOGE("Hash of '%s' failed (%s)", id, strerror(errno));
        return -1;
    }

    if (Loop::lookupActive(idHash, loopDevice, sizeof(loopDevice))) {
        SLOGE("Unable fix permissions during lookup on %s (%s)", id, strerror(errno));
        return -1;
    }

    unsigned long nr_sec = 0;
    struct asec_superblock sb;

    if (Loop::lookupInfo(loopDevice, &sb, &nr_sec)) {
        return -1;
    }

    int written = snprintf(mountPoint, sizeof(mountPoint), "%s/%s", VolumeManager::ASECDIR, id);
    if ((written < 0) || (size_t(written) >= sizeof(mountPoint))) {
        SLOGE("Unable remount to fix permissions for %s: couldn't construct mountpoint", id);
        return -1;
    }

    int result = 0;
    if ((sb.c_opts & ASEC_SB_C_OPTS_EXT4) == 0) {
        return 0;
    }

    int ret = android::vold::ext4::Mount(loopDevice, mountPoint,
            false /* read-only */,
            true  /* remount */,
            false /* executable */);
    if (ret) {
        SLOGE("Unable remount to fix permissions for %s (%s)", id, strerror(errno));
        return -1;
    }

    char *paths[] = { mountPoint, NULL };

    FTS *fts = fts_open(paths, FTS_PHYSICAL | FTS_NOCHDIR | FTS_XDEV, NULL);
    if (fts) {
        // Traverse the entire hierarchy and chown to system UID.
        for (FTSENT *ftsent = fts_read(fts); ftsent != NULL; ftsent = fts_read(fts)) {
            // We don't care about the lost+found directory.
            if (!strcmp(ftsent->fts_name, "lost+found")) {
                continue;
            }

            /*
             * There can only be one file marked as private right now.
             * This should be more robust, but it satisfies the requirements
             * we have for right now.
             */
            const bool privateFile = !strcmp(ftsent->fts_name, filename);

            int fd = open(ftsent->fts_accpath, O_NOFOLLOW | O_CLOEXEC);
            if (fd < 0) {
                SLOGE("Couldn't open file %s: %s", ftsent->fts_accpath, strerror(errno));
                result = -1;
                continue;
            }

            result |= fchown(fd, AID_SYSTEM, privateFile? gid : AID_SYSTEM);

            if (ftsent->fts_info & FTS_D) {
                result |= fchmod(fd, 0755);
            } else if (ftsent->fts_info & FTS_F) {
                result |= fchmod(fd, privateFile ? 0640 : 0644);
            }

            if (selinux_android_restorecon(ftsent->fts_path, 0) < 0) {
                SLOGE("restorecon failed for %s: %s\n", ftsent->fts_path, strerror(errno));
                result |= -1;
            }

            close(fd);
        }
        fts_close(fts);

        // Finally make the directory readable by everyone.
        int dirfd = open(mountPoint, O_DIRECTORY | O_CLOEXEC);
        if (dirfd < 0 || fchmod(dirfd, 0755)) {
            SLOGE("Couldn't change owner of existing directory %s: %s", mountPoint, strerror(errno));
            result |= -1;
        }
        close(dirfd);
    } else {
        result |= -1;
    }

    result |= android::vold::ext4::Mount(loopDevice, mountPoint,
            true /* read-only */,
            true /* remount */,
            true /* execute */);

    if (result) {
        SLOGE("ASEC fix permissions failed (%s)", strerror(errno));
        return -1;
    }

    if (mDebug) {
        SLOGD("ASEC %s permissions fixed", id);
    }
    return 0;
}

int VolumeManager::renameAsec(const char *id1, const char *id2) {
    char asecFilename1[255];
    char *asecFilename2;
    char mountPoint[255];

    const char *dir;

    if (!isLegalAsecId(id1)) {
        SLOGE("renameAsec: Invalid asec id1 \"%s\"", id1);
        errno = EINVAL;
        return -1;
    }

    if (!isLegalAsecId(id2)) {
        SLOGE("renameAsec: Invalid asec id2 \"%s\"", id2);
        errno = EINVAL;
        return -1;
    }

    if (findAsec(id1, asecFilename1, sizeof(asecFilename1), &dir)) {
        SLOGE("Couldn't find ASEC %s", id1);
        return -1;
    }

    asprintf(&asecFilename2, "%s/%s.asec", dir, id2);

    int written = snprintf(mountPoint, sizeof(mountPoint), "%s/%s", VolumeManager::ASECDIR, id1);
    if ((written < 0) || (size_t(written) >= sizeof(mountPoint))) {
        SLOGE("Rename failed: couldn't construct mountpoint");
        goto out_err;
    }

    if (isMountpointMounted(mountPoint)) {
        SLOGW("Rename attempt when src mounted");
        errno = EBUSY;
        goto out_err;
    }

    written = snprintf(mountPoint, sizeof(mountPoint), "%s/%s", VolumeManager::ASECDIR, id2);
    if ((written < 0) || (size_t(written) >= sizeof(mountPoint))) {
        SLOGE("Rename failed: couldn't construct mountpoint2");
        goto out_err;
    }

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

    free(asecFilename2);
    return 0;

out_err:
    free(asecFilename2);
    return -1;
}

#define UNMOUNT_RETRIES 5
#define UNMOUNT_SLEEP_BETWEEN_RETRY_MS (1000 * 1000)
int VolumeManager::unmountAsec(const char *id, bool force) {
    char asecFileName[255];
    char mountPoint[255];

    if (!isLegalAsecId(id)) {
        SLOGE("unmountAsec: Invalid asec id \"%s\"", id);
        errno = EINVAL;
        return -1;
    }

    if (findAsec(id, asecFileName, sizeof(asecFileName))) {
        SLOGE("Couldn't find ASEC %s", id);
        return -1;
    }

    int written = snprintf(mountPoint, sizeof(mountPoint), "%s/%s", VolumeManager::ASECDIR, id);
    if ((written < 0) || (size_t(written) >= sizeof(mountPoint))) {
        SLOGE("ASEC unmount failed for %s: couldn't construct mountpoint", id);
        return -1;
    }

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

    int written = snprintf(mountPoint, sizeof(mountPoint), "%s/%s", VolumeManager::LOOPDIR, idHash);
    if ((written < 0) || (size_t(written) >= sizeof(mountPoint))) {
        SLOGE("OBB unmount failed for %s: couldn't construct mountpoint", fileName);
        return -1;
    }

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

        int signal = 0; // default is to just complain

        if (force) {
            if (i > (UNMOUNT_RETRIES - 2))
                signal = SIGKILL;
            else if (i > (UNMOUNT_RETRIES - 3))
                signal = SIGTERM;
        }

        Process::killProcessesWithOpenFiles(mountPoint, signal);
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

    for (i=1; i <= UNMOUNT_RETRIES; i++) {
        if (Devmapper::destroy(idHash) && errno != ENXIO) {
            SLOGE("Failed to destroy devmapper instance (%s)", strerror(errno));
            usleep(UNMOUNT_SLEEP_BETWEEN_RETRY_MS);
            continue;
        } else {
          break;
        }
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

    if (!isLegalAsecId(id)) {
        SLOGE("destroyAsec: Invalid asec id \"%s\"", id);
        errno = EINVAL;
        return -1;
    }

    if (findAsec(id, asecFileName, sizeof(asecFileName))) {
        SLOGE("Couldn't find ASEC %s", id);
        return -1;
    }

    int written = snprintf(mountPoint, sizeof(mountPoint), "%s/%s", VolumeManager::ASECDIR, id);
    if ((written < 0) || (size_t(written) >= sizeof(mountPoint))) {
        SLOGE("ASEC destroy failed for %s: couldn't construct mountpoint", id);
        return -1;
    }

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

/*
 * Legal ASEC ids consist of alphanumeric characters, '-',
 * '_', or '.'. ".." is not allowed. The first or last character
 * of the ASEC id cannot be '.' (dot).
 */
bool VolumeManager::isLegalAsecId(const char *id) const {
    size_t i;
    size_t len = strlen(id);

    if (len == 0) {
        return false;
    }
    if ((id[0] == '.') || (id[len - 1] == '.')) {
        return false;
    }

    for (i = 0; i < len; i++) {
        if (id[i] == '.') {
            // i=0 is guaranteed never to have a dot. See above.
            if (id[i-1] == '.') return false;
            continue;
        }
        if (id[i] == '_' || id[i] == '-') continue;
        if (id[i] >= 'a' && id[i] <= 'z') continue;
        if (id[i] >= 'A' && id[i] <= 'Z') continue;
        if (id[i] >= '0' && id[i] <= '9') continue;
        return false;
    }

    return true;
}

bool VolumeManager::isAsecInDirectory(const char *dir, const char *asecName) const {
    int dirfd = open(dir, O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0) {
        SLOGE("Couldn't open internal ASEC dir (%s)", strerror(errno));
        return false;
    }

    struct stat sb;
    bool ret = (fstatat(dirfd, asecName, &sb, AT_SYMLINK_NOFOLLOW) == 0)
        && S_ISREG(sb.st_mode);

    close(dirfd);

    return ret;
}

int VolumeManager::findAsec(const char *id, char *asecPath, size_t asecPathLen,
        const char **directory) const {
    char *asecName;

    if (!isLegalAsecId(id)) {
        SLOGE("findAsec: Invalid asec id \"%s\"", id);
        errno = EINVAL;
        return -1;
    }

    if (asprintf(&asecName, "%s.asec", id) < 0) {
        SLOGE("Couldn't allocate string to write ASEC name");
        return -1;
    }

    const char *dir;
    if (isAsecInDirectory(VolumeManager::SEC_ASECDIR_INT, asecName)) {
        dir = VolumeManager::SEC_ASECDIR_INT;
    } else if (isAsecInDirectory(VolumeManager::SEC_ASECDIR_EXT, asecName)) {
        dir = VolumeManager::SEC_ASECDIR_EXT;
    } else {
        free(asecName);
        return -1;
    }

    if (directory != NULL) {
        *directory = dir;
    }

    if (asecPath != NULL) {
        int written = snprintf(asecPath, asecPathLen, "%s/%s", dir, asecName);
        if ((written < 0) || (size_t(written) >= asecPathLen)) {
            SLOGE("findAsec failed for %s: couldn't construct ASEC path", id);
            free(asecName);
            return -1;
        }
    }

    free(asecName);
    return 0;
}

int VolumeManager::mountAsec(const char *id, const char *key, int ownerUid, bool readOnly) {
    char asecFileName[255];
    char mountPoint[255];

    if (!isLegalAsecId(id)) {
        SLOGE("mountAsec: Invalid asec id \"%s\"", id);
        errno = EINVAL;
        return -1;
    }

    if (findAsec(id, asecFileName, sizeof(asecFileName))) {
        SLOGE("Couldn't find ASEC %s", id);
        return -1;
    }

    int written = snprintf(mountPoint, sizeof(mountPoint), "%s/%s", VolumeManager::ASECDIR, id);
    if ((written < 0) || (size_t(written) >= sizeof(mountPoint))) {
        SLOGE("ASEC mount failed for %s: couldn't construct mountpoint", id);
        return -1;
    }

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
    if (setupLoopDevice(loopDevice, sizeof(loopDevice), asecFileName, idHash, mDebug))
        return -1;

    char dmDevice[255];
    bool cleanupDm = false;

    unsigned long nr_sec = 0;
    struct asec_superblock sb;

    if (Loop::lookupInfo(loopDevice, &sb, &nr_sec)) {
        return -1;
    }

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

    if (setupDevMapperDevice(dmDevice, sizeof(dmDevice), loopDevice, asecFileName, key, idHash , nr_sec, &cleanupDm, mDebug)) {
        Loop::destroyByDevice(loopDevice);
        return -1;
    }

    if (mkdir(mountPoint, 0000)) {
        if (errno != EEXIST) {
            SLOGE("Mountpoint creation failed (%s)", strerror(errno));
            if (cleanupDm) {
                Devmapper::destroy(idHash);
            }
            Loop::destroyByDevice(loopDevice);
            return -1;
        }
    }

    /*
     * Wait for the device mapper node to be created.
     */
    waitForDevMapper(dmDevice);

    int result;
    if (sb.c_opts & ASEC_SB_C_OPTS_EXT4) {
        result = android::vold::ext4::Mount(dmDevice, mountPoint,
                readOnly, false, readOnly);
    } else {
        result = android::vold::vfat::Mount(dmDevice, mountPoint,
                readOnly, false, readOnly, ownerUid, 0, 0222, false);
    }

    if (result) {
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
int VolumeManager::mountObb(const char *img, const char *key, int ownerGid) {
    char mountPoint[255];

    char idHash[33];
    if (!asecHash(img, idHash, sizeof(idHash))) {
        SLOGE("Hash of '%s' failed (%s)", img, strerror(errno));
        return -1;
    }

    int written = snprintf(mountPoint, sizeof(mountPoint), "%s/%s", VolumeManager::LOOPDIR, idHash);
    if ((written < 0) || (size_t(written) >= sizeof(mountPoint))) {
        SLOGE("OBB mount failed for %s: couldn't construct mountpoint", img);
        return -1;
    }

    if (isMountpointMounted(mountPoint)) {
        SLOGE("Image %s already mounted", img);
        errno = EBUSY;
        return -1;
    }

    char loopDevice[255];
    if (setupLoopDevice(loopDevice, sizeof(loopDevice), img, idHash, mDebug))
        return -1;

    char dmDevice[255];
    bool cleanupDm = false;
    int fd;
    unsigned long nr_sec = 0;

    if ((fd = open(loopDevice, O_RDWR | O_CLOEXEC)) < 0) {
        SLOGE("Failed to open loopdevice (%s)", strerror(errno));
        Loop::destroyByDevice(loopDevice);
        return -1;
    }

    get_blkdev_size(fd, &nr_sec);
    if (nr_sec == 0) {
        SLOGE("Failed to get loop size (%s)", strerror(errno));
        Loop::destroyByDevice(loopDevice);
        close(fd);
        return -1;
    }

    close(fd);

    if (setupDevMapperDevice(dmDevice, sizeof(loopDevice), loopDevice, img,key, idHash, nr_sec, &cleanupDm, mDebug)) {
        Loop::destroyByDevice(loopDevice);
        return -1;
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

    /*
     * Wait for the device mapper node to be created.
     */
    waitForDevMapper(dmDevice);

    if (android::vold::vfat::Mount(dmDevice, mountPoint,
            true, false, true, 0, ownerGid, 0227, false)) {
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

int VolumeManager::listMountedObbs(SocketClient* cli) {
    FILE *fp = setmntent("/proc/mounts", "r");
    if (fp == NULL) {
        SLOGE("Error opening /proc/mounts (%s)", strerror(errno));
        return -1;
    }

    // Create a string to compare against that has a trailing slash
    int loopDirLen = strlen(VolumeManager::LOOPDIR);
    char loopDir[loopDirLen + 2];
    strcpy(loopDir, VolumeManager::LOOPDIR);
    loopDir[loopDirLen++] = '/';
    loopDir[loopDirLen] = '\0';

    mntent* mentry;
    while ((mentry = getmntent(fp)) != NULL) {
        if (!strncmp(mentry->mnt_dir, loopDir, loopDirLen)) {
            int fd = open(mentry->mnt_fsname, O_RDONLY | O_CLOEXEC);
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
    endmntent(fp);
    return 0;
}

extern "C" int vold_unmountAll(void) {
    VolumeManager *vm = VolumeManager::Instance();
    return vm->unmountAll();
}

bool VolumeManager::isMountpointMounted(const char *mp)
{
    FILE *fp = setmntent("/proc/mounts", "r");
    if (fp == NULL) {
        SLOGE("Error opening /proc/mounts (%s)", strerror(errno));
        return false;
    }

    bool found_mp = false;
    mntent* mentry;
    while ((mentry = getmntent(fp)) != NULL) {
        if (strcmp(mentry->mnt_dir, mp) == 0) {
            found_mp = true;
            break;
        }
    }
    endmntent(fp);
    return found_mp;
}

int VolumeManager::mkdirs(char* path) {
    // Only offer to create directories for paths managed by vold
    if (strncmp(path, "/storage/", 9) == 0) {
        // fs_mkdirs() does symlink checking and relative path enforcement
        return fs_mkdirs(path, 0700);
    } else {
        SLOGE("Failed to find mounted volume for %s", path);
        return -EINVAL;
    }
}
