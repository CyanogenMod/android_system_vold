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

#define LOG_TAG "Vold"

#include "Disk.h"
#include "PublicVolume.h"
#include "Utils.h"
#include "VolumeBase.h"

#include <cutils/log.h>
#include <diskconfig/diskconfig.h>
#include <utils/file.h>
#include <utils/stringprintf.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>

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

Disk::Disk(const std::string& eventPath, dev_t device) :
        mDevice(device), mSize(-1) {
    mId = StringPrintf("disk:%ud:%ud", major(device), minor(device));
    mSysPath = StringPrintf("/sys/%s", eventPath.c_str());
    mDevPath = StringPrintf("/dev/block/vold/%ud:%ud", major(device), minor(device));

    CreateDeviceNode(mDevPath, mDevice);
}

Disk::~Disk() {
    DestroyDeviceNode(mDevPath);
}

std::shared_ptr<VolumeBase> Disk::findVolume(const std::string& id) {
    for (std::shared_ptr<VolumeBase>& v : mParts) {
        if (!id.compare(v->getId())) {
            return v;
        }
    }
    return nullptr;
}

status_t Disk::readMetadata() {
    mSize = -1;
    mLabel = "";

    {
        std::string path(mSysPath + "/size");
        std::string tmp;
        if (!ReadFileToString(path, &tmp)) {
            ALOGW("Failed to read size from %s: %s", path.c_str(), strerror(errno));
            return -errno;
        }
        mSize = strtoll(tmp.c_str(), nullptr, 10);
    }

    switch (major(mDevice)) {
    case kMajorBlockScsi: {
        std::string path(mSysPath + "/device/vendor");
        std::string tmp;
        if (!ReadFileToString(path, &tmp)) {
            ALOGW("Failed to read vendor from %s: %s", path.c_str(), strerror(errno));
            return -errno;
        }
        mLabel = tmp;
        break;
    }
    case kMajorBlockMmc: {
        std::string path(mSysPath + "/device/manfid");
        std::string tmp;
        if (!ReadFileToString(path, &tmp)) {
            ALOGW("Failed to read manufacturer from %s: %s", path.c_str(), strerror(errno));
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
        ALOGW("Unsupported block major type %d", major(mDevice));
        return -ENOTSUP;
    }
    }

    return OK;
}

status_t Disk::readPartitions() {
    int8_t maxMinors = getMaxMinors();
    if (maxMinors < 0) {
        return -ENOTSUP;
    }

    mParts.clear();

    // Parse partition table
    std::string path(kSgdiskPath);
    path += " --android-dump ";
    path += mDevPath;
    FILE* fp = popen(path.c_str(), "r");
    if (!fp) {
        ALOGE("Failed to run %s: %s", path.c_str(), strerror(errno));
        return -errno;
    }

    char line[1024];
    Table table = Table::kUnknown;
    while (fgets(line, sizeof(line), fp) != nullptr) {
        char* token = strtok(line, kSgdiskToken);
        if (!strcmp(token, "DISK")) {
            const char* type = strtok(nullptr, kSgdiskToken);
            ALOGD("%s: found %s partition table", mId.c_str(), type);
            if (!strcmp(type, "mbr")) {
                table = Table::kMbr;
            } else if (!strcmp(type, "gpt")) {
                table = Table::kGpt;
            }
        } else if (!strcmp(token, "PART")) {
            int i = strtol(strtok(nullptr, kSgdiskToken), nullptr, 10);
            if (i <= 0 || i > maxMinors) {
                ALOGW("%s: ignoring partition %d beyond max supported devices",
                        mId.c_str(), i);
                continue;
            }
            dev_t partDevice = makedev(major(mDevice), minor(mDevice) + i);

            VolumeBase* vol = nullptr;
            if (table == Table::kMbr) {
                const char* type = strtok(nullptr, kSgdiskToken);
                ALOGD("%s: MBR partition %d type %s", mId.c_str(), i, type);

                switch (strtol(type, nullptr, 16)) {
                case 0x06: // FAT16
                case 0x0b: // W95 FAT32 (LBA)
                case 0x0c: // W95 FAT32 (LBA)
                case 0x0e: // W95 FAT16 (LBA)
                    vol = new PublicVolume(partDevice);
                    break;
                }
            } else if (table == Table::kGpt) {
                const char* typeGuid = strtok(nullptr, kSgdiskToken);
                const char* partGuid = strtok(nullptr, kSgdiskToken);
                ALOGD("%s: GPT partition %d type %s, GUID %s", mId.c_str(), i,
                        typeGuid, partGuid);

                if (!strcasecmp(typeGuid, kGptBasicData)) {
                    vol = new PublicVolume(partDevice);
                } else if (!strcasecmp(typeGuid, kGptAndroidExt)) {
                    //vol = new PrivateVolume();
                }
            }

            if (vol != nullptr) {
                mParts.push_back(std::shared_ptr<VolumeBase>(vol));
            }
        }
    }

    // Ugly last ditch effort, treat entire disk as partition
    if (table == Table::kUnknown) {
        ALOGD("%s: unknown partition table; trying entire device", mId.c_str());
        VolumeBase* vol = new PublicVolume(mDevice);
        mParts.push_back(std::shared_ptr<VolumeBase>(vol));
    }

    pclose(fp);
    return OK;
}

status_t Disk::partitionPublic() {
    // TODO: improve this code

    struct disk_info dinfo;
    memset(&dinfo, 0, sizeof(dinfo));

    if (!(dinfo.part_lst = (struct part_info *) malloc(
            MAX_NUM_PARTS * sizeof(struct part_info)))) {
        SLOGE("Failed to malloc prt_lst");
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
        SLOGE("Failed to apply disk configuration (%d)", rc);
        goto out;
    }

out:
    free(pinfo->name);
    free(dinfo.device);
    free(dinfo.part_lst);

    return rc;
}

status_t Disk::partitionPrivate() {
    return -ENOTSUP;
}

status_t Disk::partitionMixed(int8_t ratio) {
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
            ALOGW("Failed to read max minors");
            return -errno;
        }
        return atoi(tmp.c_str());
    }
    }

    ALOGW("Unsupported block major type %d", major(mDevice));
    return -ENOTSUP;
}

}  // namespace vold
}  // namespace android
