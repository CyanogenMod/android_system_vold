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
#include "PrivateVolume.h"
#include "Utils.h"
#include "VolumeBase.h"
#include "VolumeManager.h"
#include "ResponseCode.h"
#include "Ext4Crypt.h"

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/logging.h>
#include <diskconfig/diskconfig.h>

#include <vector>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>

using android::base::ReadFileToString;
using android::base::WriteStringToFile;
using android::base::StringPrintf;

namespace android {
namespace vold {

#ifdef MINIVOLD
static const char* kSgdiskPath = "/sbin/sgdisk";
#else
static const char* kSgdiskPath = "/system/bin/sgdisk";
#endif
static const char* kSgdiskToken = " \t\n";

static const char* kSysfsMmcMaxMinors = "/sys/module/mmcblk/parameters/perdev_minors";

static const unsigned int kMajorBlockScsiA = 8;
static const unsigned int kMajorBlockScsiB = 65;
static const unsigned int kMajorBlockScsiC = 66;
static const unsigned int kMajorBlockScsiD = 67;
static const unsigned int kMajorBlockScsiE = 68;
static const unsigned int kMajorBlockScsiF = 69;
static const unsigned int kMajorBlockScsiG = 70;
static const unsigned int kMajorBlockScsiH = 71;
static const unsigned int kMajorBlockScsiI = 128;
static const unsigned int kMajorBlockScsiJ = 129;
static const unsigned int kMajorBlockScsiK = 130;
static const unsigned int kMajorBlockScsiL = 131;
static const unsigned int kMajorBlockScsiM = 132;
static const unsigned int kMajorBlockScsiN = 133;
static const unsigned int kMajorBlockScsiO = 134;
static const unsigned int kMajorBlockScsiP = 135;
static const unsigned int kMajorBlockMmc = 179;
static const unsigned int kMajorBlockExperimentalMin = 240;
static const unsigned int kMajorBlockExperimentalMax = 254;

static const char* kGptBasicData = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7";
static const char* kGptAndroidMeta = "19A710A2-B3CA-11E4-B026-10604B889DCF";
static const char* kGptAndroidExpand = "193D1EA4-B3CA-11E4-B075-10604B889DCF";

enum class Table {
    kUnknown,
    kMbr,
    kGpt,
};

static bool isVirtioBlkDevice(unsigned int major) {
    /*
     * The new emulator's "ranchu" virtual board no longer includes a goldfish
     * MMC-based SD card device; instead, it emulates SD cards with virtio-blk,
     * which has been supported by upstream kernel and QEMU for quite a while.
     * Unfortunately, the virtio-blk block device driver does not use a fixed
     * major number, but relies on the kernel to assign one from a specific
     * range of block majors, which are allocated for "LOCAL/EXPERIMENAL USE"
     * per Documentation/devices.txt. This is true even for the latest Linux
     * kernel (4.4; see init() in drivers/block/virtio_blk.c).
     *
     * This makes it difficult for vold to detect a virtio-blk based SD card.
     * The current solution checks two conditions (both must be met):
     *
     *  a) If the running environment is the emulator;
     *  b) If the major number is an experimental block device major number (for
     *     x86/x86_64 3.10 ranchu kernels, virtio-blk always gets major number
     *     253, but it is safer to match the range than just one value).
     *
     * Other conditions could be used, too, e.g. the hardware name should be
     * "ranchu", the device's sysfs path should end with "/block/vd[d-z]", etc.
     * But just having a) and b) is enough for now.
     */
    return IsRunningInEmulator() && major >= kMajorBlockExperimentalMin
            && major <= kMajorBlockExperimentalMax;
}

Disk::Disk(const std::string& eventPath, dev_t device,
        const std::string& nickname, int flags) :
        mDevice(device), mSize(-1), mNickname(nickname), mFlags(flags), mCreated(
                false), mJustPartitioned(false), mSkipChange(false) {
    mId = StringPrintf("disk:%u_%u", major(device), minor(device));
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

void Disk::listVolumes(VolumeBase::Type type, std::list<std::string>& list) {
    for (auto vol : mVolumes) {
        if (vol->getType() == type) {
            list.push_back(vol->getId());
        }
        // TODO: consider looking at stacked volumes
    }
}

status_t Disk::create() {
    CHECK(!mCreated);
    mCreated = true;
    notifyEvent(ResponseCode::DiskCreated, StringPrintf("%d", mFlags));
    readMetadata();
    readPartitions();
    return OK;
}

status_t Disk::destroy() {
    CHECK(mCreated);
    destroyAllVolumes();
    mCreated = false;
    notifyEvent(ResponseCode::DiskDestroyed);
    return OK;
}

void Disk::createPublicVolume(dev_t device,
                const std::string& fstype /* = "" */,
                const std::string& mntopts /* = "" */) {
    auto vol = std::shared_ptr<VolumeBase>(new PublicVolume(device, mNickname, fstype, mntopts));
    if (mJustPartitioned) {
        LOG(DEBUG) << "Device just partitioned; silently formatting";
        vol->setSilent(true);
        vol->create();
        vol->format("auto");
        vol->destroy();
        vol->setSilent(false);
    }

    mVolumes.push_back(vol);
    vol->setDiskId(getId());
    vol->create();
}

void Disk::createPrivateVolume(dev_t device, const std::string& partGuid) {
    std::string normalizedGuid;
    if (NormalizeHex(partGuid, normalizedGuid)) {
        LOG(WARNING) << "Invalid GUID " << partGuid;
        return;
    }

    std::string keyRaw;
    if (!ReadFileToString(BuildKeyPath(normalizedGuid), &keyRaw)) {
        PLOG(ERROR) << "Failed to load key for GUID " << normalizedGuid;
        return;
    }

    LOG(DEBUG) << "Found key for GUID " << normalizedGuid;

    auto vol = std::shared_ptr<VolumeBase>(new PrivateVolume(device, keyRaw));
    if (mJustPartitioned) {
        LOG(DEBUG) << "Device just partitioned; silently formatting";
        vol->setSilent(true);
        vol->create();
        vol->format("auto");
        vol->destroy();
        vol->setSilent(false);
    }

    mVolumes.push_back(vol);
    vol->setDiskId(getId());
    vol->setPartGuid(partGuid);
    vol->create();
}

void Disk::destroyAllVolumes() {
    for (auto vol : mVolumes) {
        vol->destroy();
    }
    mVolumes.clear();
}

status_t Disk::readMetadata() {

    if (mSkipChange) {
        return OK;
    }

    mSize = -1;
    mLabel.clear();

    int fd = open(mDevPath.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd != -1) {
        if (ioctl(fd, BLKGETSIZE64, &mSize)) {
            mSize = -1;
        }
        close(fd);
    }

    unsigned int majorId = major(mDevice);
    switch (majorId) {
    case kMajorBlockScsiA: case kMajorBlockScsiB: case kMajorBlockScsiC: case kMajorBlockScsiD:
    case kMajorBlockScsiE: case kMajorBlockScsiF: case kMajorBlockScsiG: case kMajorBlockScsiH:
    case kMajorBlockScsiI: case kMajorBlockScsiJ: case kMajorBlockScsiK: case kMajorBlockScsiL:
    case kMajorBlockScsiM: case kMajorBlockScsiN: case kMajorBlockScsiO: case kMajorBlockScsiP: {
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
        if (isVirtioBlkDevice(majorId)) {
            LOG(DEBUG) << "Recognized experimental block major ID " << majorId
                    << " as virtio-blk (emulator's virtual SD card device)";
            mLabel = "Virtual";
            break;
        }
        LOG(WARNING) << "Unsupported block major type " << majorId;
        return -ENOTSUP;
    }
    }

    notifyEvent(ResponseCode::DiskSizeChanged, StringPrintf("%" PRIu64, mSize));
    notifyEvent(ResponseCode::DiskLabelChanged, mLabel);
    notifyEvent(ResponseCode::DiskSysPathChanged, mSysPath);
    return OK;
}

status_t Disk::readPartitions() {
    int8_t maxMinors = getMaxMinors();
    if (maxMinors < 0) {
        return -ENOTSUP;
    }

    if (mSkipChange) {
        mSkipChange = false;
        LOG(INFO) << "Skip first change";
        return OK;
    }

    destroyAllVolumes();

    // Parse partition table

    std::vector<std::string> cmd;
    cmd.push_back(kSgdiskPath);
    cmd.push_back("--android-dump");
    cmd.push_back(mDevPath);

    std::vector<std::string> output;
    status_t res = ForkExecvp(cmd, output);
    if (res != OK) {
        LOG(WARNING) << "sgdisk failed to scan " << mDevPath;
        notifyEvent(ResponseCode::DiskScanned);
        mJustPartitioned = false;
        return res;
    }

    Table table = Table::kUnknown;
    bool foundParts = false;
    for (auto line : output) {
        char* cline = (char*) line.c_str();
        char* token = strtok(cline, kSgdiskToken);
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
                case 0x07: // NTFS/exFAT
                case 0x0b: // W95 FAT32 (LBA)
                case 0x0c: // W95 FAT32 (LBA)
                case 0x0e: // W95 FAT16 (LBA)
                case 0x83: // Linux EXT4/F2FS/...
                    createPublicVolume(partDevice);
                    break;
                }
            } else if (table == Table::kGpt) {
                const char* typeGuid = strtok(nullptr, kSgdiskToken);
                const char* partGuid = strtok(nullptr, kSgdiskToken);

                if (!strcasecmp(typeGuid, kGptBasicData)) {
                    createPublicVolume(partDevice);
                } else if (!strcasecmp(typeGuid, kGptAndroidExpand)) {
                    createPrivateVolume(partDevice, partGuid);
                }
            }
        }
    }

    // Ugly last ditch effort, treat entire disk as partition
    if (table == Table::kUnknown || !foundParts) {
        LOG(WARNING) << mId << " has unknown partition table; trying entire device";

        std::string fsType;
        std::string unused;
        if (ReadMetadataUntrusted(mDevPath, fsType, unused, unused) == OK) {
            createPublicVolume(mDevice);
        } else {
            LOG(WARNING) << mId << " failed to identify, giving up";
        }
    }

    notifyEvent(ResponseCode::DiskScanned);
    mJustPartitioned = false;
    return OK;
}

status_t Disk::unmountAll() {
    for (auto vol : mVolumes) {
        vol->unmount();
    }
    return OK;
}

status_t Disk::partitionPublic() {
    int res;

    // TODO: improve this code
    destroyAllVolumes();
    mJustPartitioned = true;

    // Determine if we're coming from MBR
    std::vector<std::string> cmd;
    cmd.push_back(kSgdiskPath);
    cmd.push_back("--android-dump");
    cmd.push_back(mDevPath);

    std::vector<std::string> output;
    res = ForkExecvp(cmd, output);
    if (res != OK) {
        LOG(WARNING) << "sgdisk failed to scan " << mDevPath;
        mJustPartitioned = false;
        return res;
    }

    Table table = Table::kUnknown;
    for (auto line : output) {
        char* cline = (char*) line.c_str();
        char* token = strtok(cline, kSgdiskToken);
        if (token == nullptr) continue;

        if (!strcmp(token, "DISK")) {
            const char* type = strtok(nullptr, kSgdiskToken);
            if (!strcmp(type, "mbr")) {
                table = Table::kMbr;
                break;
            } else if (!strcmp(type, "gpt")) {
                table = Table::kGpt;
                break;
            }
        }
    }

    if (table == Table::kMbr) {
        LOG(INFO) << "skip first disk change event due to MBR -> GPT switch";
        mSkipChange = true;
    }

    // First nuke any existing partition table
    cmd.clear();
    cmd.push_back(kSgdiskPath);
    cmd.push_back("--zap-all");
    cmd.push_back(mDevPath);

    // Zap sometimes returns an error when it actually succeeded, so
    // just log as warning and keep rolling forward.
    if ((res = ForkExecvp(cmd)) != 0) {
        LOG(WARNING) << "Failed to zap; status " << res;
    }

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
    return partitionMixed(0);
}

status_t Disk::partitionMixed(int8_t ratio) {
    int res;

    if (e4crypt_is_native()) {
        LOG(ERROR) << "Private volumes not yet supported on FBE devices";
        return -EINVAL;
    }

    destroyAllVolumes();
    mJustPartitioned = true;

    // First nuke any existing partition table
    std::vector<std::string> cmd;
    cmd.push_back(kSgdiskPath);
    cmd.push_back("--zap-all");
    cmd.push_back(mDevPath);

    // Zap sometimes returns an error when it actually succeeded, so
    // just log as warning and keep rolling forward.
    if ((res = ForkExecvp(cmd)) != 0) {
        LOG(WARNING) << "Failed to zap; status " << res;
    }

    // We've had some success above, so generate both the private partition
    // GUID and encryption key and persist them.
    std::string partGuidRaw;
    std::string keyRaw;
    if (ReadRandomBytes(16, partGuidRaw) || ReadRandomBytes(16, keyRaw)) {
        LOG(ERROR) << "Failed to generate GUID or key";
        return -EIO;
    }

    std::string partGuid;
    StrToHex(partGuidRaw, partGuid);

    if (!WriteStringToFile(keyRaw, BuildKeyPath(partGuid))) {
        LOG(ERROR) << "Failed to persist key";
        return -EIO;
    } else {
        LOG(DEBUG) << "Persisted key for GUID " << partGuid;
    }

    // Now let's build the new GPT table. We heavily rely on sgdisk to
    // force optimal alignment on the created partitions.
    cmd.clear();
    cmd.push_back(kSgdiskPath);

    // If requested, create a public partition first. Mixed-mode partitioning
    // like this is an experimental feature.
    if (ratio > 0) {
        if (ratio < 10 || ratio > 90) {
            LOG(ERROR) << "Mixed partition ratio must be between 10-90%";
            return -EINVAL;
        }

        uint64_t splitMb = ((mSize / 100) * ratio) / 1024 / 1024;
        cmd.push_back(StringPrintf("--new=0:0:+%" PRId64 "M", splitMb));
        cmd.push_back(StringPrintf("--typecode=0:%s", kGptBasicData));
        cmd.push_back("--change-name=0:shared");
    }

    // Define a metadata partition which is designed for future use; there
    // should only be one of these per physical device, even if there are
    // multiple private volumes.
    cmd.push_back("--new=0:0:+16M");
    cmd.push_back(StringPrintf("--typecode=0:%s", kGptAndroidMeta));
    cmd.push_back("--change-name=0:android_meta");

    // Define a single private partition filling the rest of disk.
    cmd.push_back("--new=0:0:-0");
    cmd.push_back(StringPrintf("--typecode=0:%s", kGptAndroidExpand));
    cmd.push_back(StringPrintf("--partition-guid=0:%s", partGuid.c_str()));
    cmd.push_back("--change-name=0:android_expand");

    cmd.push_back(mDevPath);

    if ((res = ForkExecvp(cmd)) != 0) {
        LOG(ERROR) << "Failed to partition; status " << res;
        return res;
    }

    return OK;
}

void Disk::notifyEvent(int event) {
    VolumeManager::Instance()->getBroadcaster()->sendBroadcast(event,
            getId().c_str(), false);
}

void Disk::notifyEvent(int event, const std::string& value) {
    VolumeManager::Instance()->getBroadcaster()->sendBroadcast(event,
            StringPrintf("%s %s", getId().c_str(), value.c_str()).c_str(), false);
}

int Disk::getMaxMinors() {
    // Figure out maximum partition devices supported
    unsigned int majorId = major(mDevice);
    switch (majorId) {
    case kMajorBlockScsiA: case kMajorBlockScsiB: case kMajorBlockScsiC: case kMajorBlockScsiD:
    case kMajorBlockScsiE: case kMajorBlockScsiF: case kMajorBlockScsiG: case kMajorBlockScsiH:
    case kMajorBlockScsiI: case kMajorBlockScsiJ: case kMajorBlockScsiK: case kMajorBlockScsiL:
    case kMajorBlockScsiM: case kMajorBlockScsiN: case kMajorBlockScsiO: case kMajorBlockScsiP: {
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
    default: {
        if (isVirtioBlkDevice(majorId)) {
            // drivers/block/virtio_blk.c has "#define PART_BITS 4", so max is
            // 2^4 - 1 = 15
            return 15;
        }
    }
    }

    LOG(ERROR) << "Unsupported block major type " << majorId;
    return -ENOTSUP;
}

}  // namespace vold
}  // namespace android
