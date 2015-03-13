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

#include "Disk.h"
#include "PublicVolume.h"
#include "Utils.h"
#include "VolumeBase.h"
#include "VolumeManager.h"
#include "ResponseCode.h"

#include <base/file.h>
#include <base/stringprintf.h>
#include <base/logging.h>
#include <diskconfig/diskconfig.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>

using android::base::ReadFileToString;
using android::base::StringPrintf;

namespace android {
namespace vold {

static const char* kSgdiskPath = "/system/bin/sgdisk";
static const char* kSgdiskToken = " \t\n";

static const char* kSysfsMmcMaxMinors = "/sys/module/mmcblk/parameters/perdev_minors";

static const unsigned int kMajorBlockScsi = 8;
static const unsigned int kMajorBlockMmc = 179;

static const char* kGptBasicData = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7";
static const char* kGptAndroidMeta = "19A710A2-B3CA-11E4-B026-10604B889DCF";
static const char* kGptAndroidExt = "193D1EA4-B3CA-11E4-B075-10604B889DCF";

enum class Table {
    kUnknown,
    kMbr,
    kGpt,
};

Disk::Disk(const std::string& eventPath, dev_t device, const std::string& nickname, int flags) :
        mDevice(device), mSize(-1), mNickname(nickname), mFlags(flags), mCreated(false) {
    mId = StringPrintf("disk:%u,%u", major(device), minor(device));
    mEventPath = eventPath;
    mSysPath = StringPrintf("/sys/%s", eventPath.c_str());
    mDevPath = StringPrintf("/dev/block/vold/%s", mId.c_str());
    CreateDeviceNode(mDevPath, mDevice);
}

Disk::~Disk() {
    CHECK(!mCreated);
    DestroyDeviceNode(mDevPath);
}

std::shared_ptr<VolumeBase> Disk::findVolume(const std::string& id) {
    for (auto vol : mVolumes) {
        if (vol->getId() == id) {
            return vol;
        }
        auto stackedVol = vol->findVolume(id);
        if (stackedVol != nullptr) {
            return stackedVol;
        }
    }
    return nullptr;
}

status_t Disk::create() {
    CHECK(!mCreated);
    mCreated = true;
    VolumeManager::Instance()->getBroadcaster()->sendBroadcast(
            ResponseCode::DiskCreated,
            StringPrintf("%s %d", getId().c_str(), mFlags).c_str(), false);
    readMetadata();
    readPartitions();
    return OK;
}

status_t Disk::destroy() {
    CHECK(mCreated);
    destroyAllVolumes();
    mCreated = false;
    VolumeManager::Instance()->getBroadcaster()->sendBroadcast(
            ResponseCode::DiskDestroyed, getId().c_str(), false);
    return OK;
}

void Disk::createPublicVolume(dev_t device) {
    auto vol = new PublicVolume(device);
    vol->create();

    mVolumes.push_back(std::shared_ptr<VolumeBase>(vol));
    VolumeManager::Instance()->getBroadcaster()->sendBroadcast(
            ResponseCode::DiskVolumeCreated,
            StringPrintf("%s %s", getId().c_str(), vol->getId().c_str()).c_str(), false);
}

void Disk::createPrivateVolume(dev_t device) {
    // TODO: create and add
}

void Disk::destroyAllVolumes() {
    for (auto vol : mVolumes) {
        vol->destroy();
    }
    mVolumes.clear();
}

status_t Disk::readMetadata() {
    mSize = -1;
    mLabel.clear();

    int fd = open(mDevPath.c_str(), O_RDONLY);
    if (fd != -1) {
        if (ioctl(fd, BLKGETSIZE64, &mSize)) {
            mSize = -1;
        }
        close(fd);
    }

    switch (major(mDevice)) {
    case kMajorBlockScsi: {
        std::string path(mSysPath + "/device/vendor");
        std::string tmp;
        if (!ReadFileToString(path, &tmp)) {
            PLOG(WARNING) << "Failed to read vendor from " << path;
            return -errno;
        }
        mLabel = tmp;
        break;
    }
    case kMajorBlockMmc: {
        std::string path(mSysPath + "/device/manfid");
        std::string tmp;
        if (!ReadFileToString(path, &tmp)) {
            PLOG(WARNING) << "Failed to read manufacturer from " << path;
            return -errno;
        }
        uint64_t manfid = strtoll(tmp.c_str(), nullptr, 16);
        // Our goal here is to give the user a meaningful label, ideally
        // matching whatever is silk-screened on the card.  To reduce
        // user confusion, this list doesn't contain white-label manfid.
        switch (manfid) {
        case 0x000003: mLabel = "SanDisk"; break;
        case 0x00001b: mLabel = "Samsung"; break;
        case 0x000028: mLabel = "Lexar"; break;
        case 0x000074: mLabel = "Transcend"; break;
        }
        break;
    }
    default: {
        LOG(WARNING) << "Unsupported block major type" << major(mDevice);
        return -ENOTSUP;
    }
    }

    VolumeManager::Instance()->getBroadcaster()->sendBroadcast(
            ResponseCode::DiskSizeChanged,
            StringPrintf("%s %lld", getId().c_str(), mSize).c_str(), false);
    VolumeManager::Instance()->getBroadcaster()->sendBroadcast(
            ResponseCode::DiskLabelChanged,
            StringPrintf("%s %s", getId().c_str(), mLabel.c_str()).c_str(), false);

    return OK;
}

status_t Disk::readPartitions() {
    int8_t maxMinors = getMaxMinors();
    if (maxMinors < 0) {
        return -ENOTSUP;
    }

    destroyAllVolumes();

    // Parse partition table
    std::string path(kSgdiskPath);
    path += " --android-dump ";
    path += mDevPath;
    FILE* fp = popen(path.c_str(), "r");
    if (!fp) {
        PLOG(ERROR) << "Failed to run " << path;
        return -errno;
    }

    char line[1024];
    Table table = Table::kUnknown;
    bool foundParts = false;
    while (fgets(line, sizeof(line), fp) != nullptr) {
        LOG(DEBUG) << "sgdisk: " << line;

        char* token = strtok(line, kSgdiskToken);
        if (token == nullptr) continue;

        if (!strcmp(token, "DISK")) {
            const char* type = strtok(nullptr, kSgdiskToken);
            if (!strcmp(type, "mbr")) {
                table = Table::kMbr;
            } else if (!strcmp(type, "gpt")) {
                table = Table::kGpt;
            }
        } else if (!strcmp(token, "PART")) {
            foundParts = true;
            int i = strtol(strtok(nullptr, kSgdiskToken), nullptr, 10);
            if (i <= 0 || i > maxMinors) {
                LOG(WARNING) << mId << " is ignoring partition " << i
                        << " beyond max supported devices";
                continue;
            }
            dev_t partDevice = makedev(major(mDevice), minor(mDevice) + i);

            if (table == Table::kMbr) {
                const char* type = strtok(nullptr, kSgdiskToken);

                switch (strtol(type, nullptr, 16)) {
                case 0x06: // FAT16
                case 0x0b: // W95 FAT32 (LBA)
                case 0x0c: // W95 FAT32 (LBA)
                case 0x0e: // W95 FAT16 (LBA)
                    createPublicVolume(partDevice);
                    break;
                }
            } else if (table == Table::kGpt) {
                const char* typeGuid = strtok(nullptr, kSgdiskToken);
                const char* partGuid = strtok(nullptr, kSgdiskToken);

                if (!strcasecmp(typeGuid, kGptBasicData)) {
                    createPublicVolume(partDevice);
                } else if (!strcasecmp(typeGuid, kGptAndroidExt)) {
                    createPrivateVolume(partDevice);
                }
            }
        }
    }

    // Ugly last ditch effort, treat entire disk as partition
    if (table == Table::kUnknown || !foundParts) {
        LOG(WARNING) << mId << " has unknown partition table; trying entire device";
        createPublicVolume(mDevice);
    }

    pclose(fp);
    return OK;
}

status_t Disk::partitionPublic() {
    // TODO: improve this code
    destroyAllVolumes();

    struct disk_info dinfo;
    memset(&dinfo, 0, sizeof(dinfo));

    if (!(dinfo.part_lst = (struct part_info *) malloc(
            MAX_NUM_PARTS * sizeof(struct part_info)))) {
        return -1;
    }

    memset(dinfo.part_lst, 0, MAX_NUM_PARTS * sizeof(struct part_info));
    dinfo.device = strdup(mDevPath.c_str());
    dinfo.scheme = PART_SCHEME_MBR;
    dinfo.sect_size = 512;
    dinfo.skip_lba = 2048;
    dinfo.num_lba = 0;
    dinfo.num_parts = 1;

    struct part_info *pinfo = &dinfo.part_lst[0];

    pinfo->name = strdup("android_sdcard");
    pinfo->flags |= PART_ACTIVE_FLAG;
    pinfo->type = PC_PART_TYPE_FAT32;
    pinfo->len_kb = -1;

    int rc = apply_disk_config(&dinfo, 0);
    if (rc) {
        LOG(ERROR) << "Failed to apply disk configuration: " << rc;
        goto out;
    }

out:
    free(pinfo->name);
    free(dinfo.device);
    free(dinfo.part_lst);

    return rc;
}

status_t Disk::partitionPrivate() {
    destroyAllVolumes();
    return -ENOTSUP;
}

status_t Disk::partitionMixed(int8_t ratio) {
    destroyAllVolumes();
    return -ENOTSUP;
}

int Disk::getMaxMinors() {
    // Figure out maximum partition devices supported
    switch (major(mDevice)) {
    case kMajorBlockScsi: {
        // Per Documentation/devices.txt this is static
        return 15;
    }
    case kMajorBlockMmc: {
        // Per Documentation/devices.txt this is dynamic
        std::string tmp;
        if (!ReadFileToString(kSysfsMmcMaxMinors, &tmp)) {
            LOG(ERROR) << "Failed to read max minors";
            return -errno;
        }
        return atoi(tmp.c_str());
    }
    }

    LOG(ERROR) << "Unsupported block major type " << major(mDevice);
    return -ENOTSUP;
}

}  // namespace vold
}  // namespace android
