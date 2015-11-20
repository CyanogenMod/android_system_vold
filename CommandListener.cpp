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

#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fs_mgr.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#define LOG_TAG "VoldCmdListener"

#include <base/stringprintf.h>
#include <cutils/fs.h>
#include <cutils/log.h>

#include <sysutils/SocketClient.h>
#include <private/android_filesystem_config.h>

#include "CommandListener.h"
#include "VolumeManager.h"
#include "VolumeBase.h"
#include "ResponseCode.h"
#include "Process.h"
#include "Loop.h"
#include "Devmapper.h"
#include "cryptfs.h"
#include "MoveTask.h"
#include "TrimTask.h"

#define DUMP_ARGS 0

CommandListener::CommandListener() :
                 FrameworkListener("vold", true) {
    registerCmd(new DumpCmd());
    registerCmd(new VolumeCmd());
    registerCmd(new AsecCmd());
    registerCmd(new ObbCmd());
    registerCmd(new StorageCmd());
    registerCmd(new FstrimCmd());
}

#if DUMP_ARGS
void CommandListener::dumpArgs(int argc, char **argv, int argObscure) {
    char buffer[4096];
    char *p = buffer;

    memset(buffer, 0, sizeof(buffer));
    int i;
    for (i = 0; i < argc; i++) {
        unsigned int len = strlen(argv[i]) + 1; // Account for space
        if (i == argObscure) {
            len += 2; // Account for {}
        }
        if (((p - buffer) + len) < (sizeof(buffer)-1)) {
            if (i == argObscure) {
                *p++ = '{';
                *p++ = '}';
                *p++ = ' ';
                continue;
            }
            strcpy(p, argv[i]);
            p+= strlen(argv[i]);
            if (i != (argc -1)) {
                *p++ = ' ';
            }
        }
    }
    SLOGD("%s", buffer);
}
#else
void CommandListener::dumpArgs(int /*argc*/, char ** /*argv*/, int /*argObscure*/) { }
#endif

int CommandListener::sendGenericOkFail(SocketClient *cli, int cond) {
    if (!cond) {
        return cli->sendMsg(ResponseCode::CommandOkay, "Command succeeded", false);
    } else {
        return cli->sendMsg(ResponseCode::OperationFailed, "Command failed", false);
    }
}

CommandListener::DumpCmd::DumpCmd() :
                 VoldCommand("dump") {
}

int CommandListener::DumpCmd::runCommand(SocketClient *cli,
                                         int /*argc*/, char ** /*argv*/) {
    cli->sendMsg(0, "Dumping loop status", false);
    if (Loop::dumpState(cli)) {
        cli->sendMsg(ResponseCode::CommandOkay, "Loop dump failed", true);
    }
    cli->sendMsg(0, "Dumping DM status", false);
    if (Devmapper::dumpState(cli)) {
        cli->sendMsg(ResponseCode::CommandOkay, "Devmapper dump failed", true);
    }
    cli->sendMsg(0, "Dumping mounted filesystems", false);
    FILE *fp = fopen("/proc/mounts", "r");
    if (fp) {
        char line[1024];
        while (fgets(line, sizeof(line), fp)) {
            line[strlen(line)-1] = '\0';
            cli->sendMsg(0, line, false);;
        }
        fclose(fp);
    }

    cli->sendMsg(ResponseCode::CommandOkay, "dump complete", false);
    return 0;
}

CommandListener::VolumeCmd::VolumeCmd() :
                 VoldCommand("volume") {
}

int CommandListener::VolumeCmd::runCommand(SocketClient *cli,
                                           int argc, char **argv) {
    dumpArgs(argc, argv, -1);

    if (argc < 2) {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing Argument", false);
        return 0;
    }

    VolumeManager *vm = VolumeManager::Instance();
    std::lock_guard<std::mutex> lock(vm->getLock());

    // TODO: tease out methods not directly related to volumes

    std::string cmd(argv[1]);
    if (cmd == "reset") {
        return sendGenericOkFail(cli, vm->reset());

    } else if (cmd == "shutdown") {
        return sendGenericOkFail(cli, vm->shutdown());

    } else if (cmd == "debug") {
        return sendGenericOkFail(cli, vm->setDebug(true));

    } else if (cmd == "partition" && argc > 3) {
        // partition [diskId] [public|private|mixed] [ratio]
        std::string id(argv[2]);
        auto disk = vm->findDisk(id);
        if (disk == nullptr) {
            return cli->sendMsg(ResponseCode::CommandSyntaxError, "Unknown disk", false);
        }

        std::string type(argv[3]);
        if (type == "public") {
            return sendGenericOkFail(cli, disk->partitionPublic());
        } else if (type == "private") {
            return sendGenericOkFail(cli, disk->partitionPrivate());
        } else if (type == "mixed") {
            if (argc < 4) {
                return cli->sendMsg(ResponseCode::CommandSyntaxError, nullptr, false);
            }
            int frac = atoi(argv[4]);
            return sendGenericOkFail(cli, disk->partitionMixed(frac));
        } else {
            return cli->sendMsg(ResponseCode::CommandSyntaxError, nullptr, false);
        }

    } else if (cmd == "mkdirs" && argc > 2) {
        // mkdirs [path]
        return sendGenericOkFail(cli, vm->mkdirs(argv[2]));

    } else if (cmd == "user_added" && argc > 3) {
        // user_added [user] [serial]
        return sendGenericOkFail(cli, vm->onUserAdded(atoi(argv[2]), atoi(argv[3])));

    } else if (cmd == "user_removed" && argc > 2) {
        // user_removed [user]
        return sendGenericOkFail(cli, vm->onUserRemoved(atoi(argv[2])));

    } else if (cmd == "user_started" && argc > 2) {
        // user_started [user]
        return sendGenericOkFail(cli, vm->onUserStarted(atoi(argv[2])));

    } else if (cmd == "user_stopped" && argc > 2) {
        // user_stopped [user]
        return sendGenericOkFail(cli, vm->onUserStopped(atoi(argv[2])));

    } else if (cmd == "mount" && argc > 2) {
        // mount [volId] [flags] [user]
        std::string id(argv[2]);
        auto vol = vm->findVolume(id);
        if (vol == nullptr) {
            return cli->sendMsg(ResponseCode::CommandSyntaxError, "Unknown volume", false);
        }

        int mountFlags = (argc > 3) ? atoi(argv[3]) : 0;
        userid_t mountUserId = (argc > 4) ? atoi(argv[4]) : -1;

        vol->setMountFlags(mountFlags);
        vol->setMountUserId(mountUserId);

        int res = vol->mount();
        if (mountFlags & android::vold::VolumeBase::MountFlags::kPrimary) {
            vm->setPrimary(vol);
        }
        return sendGenericOkFail(cli, res);

    } else if (cmd == "unmount" && argc > 2) {
        // unmount [volId] [detach]
        std::string id(argv[2]);
        auto vol = vm->findVolume(id);
        if (vol == nullptr) {
            return cli->sendMsg(ResponseCode::CommandSyntaxError, "Unknown volume", false);
        }
        bool detach = (argc > 3 && !strcmp(argv[3], "detach"));

        return sendGenericOkFail(cli, vol->unmount(detach));

    } else if (cmd == "format" && argc > 3) {
        // format [volId] [fsType|auto]
        std::string id(argv[2]);
        std::string fsType(argv[3]);
        auto vol = vm->findVolume(id);
        if (vol == nullptr) {
            return cli->sendMsg(ResponseCode::CommandSyntaxError, "Unknown volume", false);
        }

        return sendGenericOkFail(cli, vol->format(fsType));

    } else if (cmd == "move_storage" && argc > 3) {
        // move_storage [fromVolId] [toVolId]
        auto fromVol = vm->findVolume(std::string(argv[2]));
        auto toVol = vm->findVolume(std::string(argv[3]));
        if (fromVol == nullptr || toVol == nullptr) {
            return cli->sendMsg(ResponseCode::CommandSyntaxError, "Unknown volume", false);
        }

        (new android::vold::MoveTask(fromVol, toVol))->start();
        return sendGenericOkFail(cli, 0);

    } else if (cmd == "benchmark" && argc > 2) {
        // benchmark [volId]
        std::string id(argv[2]);
        nsecs_t res = vm->benchmarkPrivate(id);
        return cli->sendMsg(ResponseCode::CommandOkay,
                android::base::StringPrintf("%" PRId64, res).c_str(), false);

    } else if (cmd == "forget_partition" && argc > 2) {
        // forget_partition [partGuid]
        std::string partGuid(argv[2]);
        return sendGenericOkFail(cli, vm->forgetPartition(partGuid));

    } else if (cmd == "remount_uid" && argc > 3) {
        // remount_uid [uid] [none|default|read|write]
        uid_t uid = atoi(argv[2]);
        std::string mode(argv[3]);
        return sendGenericOkFail(cli, vm->remountUid(uid, mode));
    }

    return cli->sendMsg(ResponseCode::CommandSyntaxError, nullptr, false);
}

CommandListener::StorageCmd::StorageCmd() :
                 VoldCommand("storage") {
}

int CommandListener::StorageCmd::runCommand(SocketClient *cli,
                                                      int argc, char **argv) {
    /* Guarantied to be initialized by vold's main() before the CommandListener is active */
    extern struct fstab *fstab;

    dumpArgs(argc, argv, -1);

    if (argc < 2) {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing Argument", false);
        return 0;
    }

    if (!strcmp(argv[1], "mountall")) {
        if (argc != 2) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Usage: mountall", false);
            return 0;
        }
        fs_mgr_mount_all(fstab);
        cli->sendMsg(ResponseCode::CommandOkay, "Mountall ran successfully", false);
        return 0;
    }
    if (!strcmp(argv[1], "users")) {
        DIR *dir;
        struct dirent *de;

        if (argc < 3) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing Argument: user <mountpoint>", false);
            return 0;
        }
        if (!(dir = opendir("/proc"))) {
            cli->sendMsg(ResponseCode::OperationFailed, "Failed to open /proc", true);
            return 0;
        }

        while ((de = readdir(dir))) {
            int pid = Process::getPid(de->d_name);

            if (pid < 0) {
                continue;
            }

            char processName[255];
            Process::getProcessName(pid, processName, sizeof(processName));

            if (Process::checkFileDescriptorSymLinks(pid, argv[2]) ||
                Process::checkFileMaps(pid, argv[2]) ||
                Process::checkSymLink(pid, argv[2], "cwd") ||
                Process::checkSymLink(pid, argv[2], "root") ||
                Process::checkSymLink(pid, argv[2], "exe")) {

                char msg[1024];
                snprintf(msg, sizeof(msg), "%d %s", pid, processName);
                cli->sendMsg(ResponseCode::StorageUsersListResult, msg, false);
            }
        }
        closedir(dir);
        cli->sendMsg(ResponseCode::CommandOkay, "Storage user list complete", false);
    } else {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Unknown storage cmd", false);
    }
    return 0;
}

CommandListener::AsecCmd::AsecCmd() :
                 VoldCommand("asec") {
}

void CommandListener::AsecCmd::listAsecsInDirectory(SocketClient *cli, const char *directory) {
    DIR *d = opendir(directory);

    if (!d) {
        cli->sendMsg(ResponseCode::OperationFailed, "Failed to open asec dir", true);
        return;
    }

    size_t dirent_len = offsetof(struct dirent, d_name) +
            fpathconf(dirfd(d), _PC_NAME_MAX) + 1;

    struct dirent *dent = (struct dirent *) malloc(dirent_len);
    if (dent == NULL) {
        cli->sendMsg(ResponseCode::OperationFailed, "Failed to allocate memory", true);
        return;
    }

    struct dirent *result;

    while (!readdir_r(d, dent, &result) && result != NULL) {
        if (dent->d_name[0] == '.')
            continue;
        if (dent->d_type != DT_REG)
            continue;
        size_t name_len = strlen(dent->d_name);
        if (name_len > 5 && name_len < 260 &&
                !strcmp(&dent->d_name[name_len - 5], ".asec")) {
            char id[255];
            memset(id, 0, sizeof(id));
            strlcpy(id, dent->d_name, name_len - 4);
            cli->sendMsg(ResponseCode::AsecListResult, id, false);
        }
    }
    closedir(d);

    free(dent);
}

int CommandListener::AsecCmd::runCommand(SocketClient *cli,
                                                      int argc, char **argv) {
    if (argc < 2) {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing Argument", false);
        return 0;
    }

    VolumeManager *vm = VolumeManager::Instance();
    int rc = 0;

    if (!strcmp(argv[1], "list")) {
        dumpArgs(argc, argv, -1);

        listAsecsInDirectory(cli, VolumeManager::SEC_ASECDIR_EXT);
        listAsecsInDirectory(cli, VolumeManager::SEC_ASECDIR_INT);
    } else if (!strcmp(argv[1], "create")) {
        dumpArgs(argc, argv, 5);
        if (argc != 8) {
            cli->sendMsg(ResponseCode::CommandSyntaxError,
                    "Usage: asec create <container-id> <size_mb> <fstype> <key> <ownerUid> "
                    "<isExternal>", false);
            return 0;
        }

        unsigned int numSectors = (atoi(argv[3]) * (1024 * 1024)) / 512;
        const bool isExternal = (atoi(argv[7]) == 1);
        rc = vm->createAsec(argv[2], numSectors, argv[4], argv[5], atoi(argv[6]), isExternal);
    } else if (!strcmp(argv[1], "resize")) {
        dumpArgs(argc, argv, -1);
        if (argc != 5) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Usage: asec resize <container-id> <size_mb> <key>", false);
            return 0;
        }
        unsigned int numSectors = (atoi(argv[3]) * (1024 * 1024)) / 512;
        rc = vm->resizeAsec(argv[2], numSectors, argv[4]);
    } else if (!strcmp(argv[1], "finalize")) {
        dumpArgs(argc, argv, -1);
        if (argc != 3) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Usage: asec finalize <container-id>", false);
            return 0;
        }
        rc = vm->finalizeAsec(argv[2]);
    } else if (!strcmp(argv[1], "fixperms")) {
        dumpArgs(argc, argv, -1);
        if  (argc != 5) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Usage: asec fixperms <container-id> <gid> <filename>", false);
            return 0;
        }

        char *endptr;
        gid_t gid = (gid_t) strtoul(argv[3], &endptr, 10);
        if (*endptr != '\0') {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Usage: asec fixperms <container-id> <gid> <filename>", false);
            return 0;
        }

        rc = vm->fixupAsecPermissions(argv[2], gid, argv[4]);
    } else if (!strcmp(argv[1], "destroy")) {
        dumpArgs(argc, argv, -1);
        if (argc < 3) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Usage: asec destroy <container-id> [force]", false);
            return 0;
        }
        bool force = false;
        if (argc > 3 && !strcmp(argv[3], "force")) {
            force = true;
        }
        rc = vm->destroyAsec(argv[2], force);
    } else if (!strcmp(argv[1], "mount")) {
        dumpArgs(argc, argv, 3);
        if (argc != 6) {
            cli->sendMsg(ResponseCode::CommandSyntaxError,
                    "Usage: asec mount <namespace-id> <key> <ownerUid> <ro|rw>", false);
            return 0;
        }
        bool readOnly = true;
        if (!strcmp(argv[5], "rw")) {
            readOnly = false;
        }
        rc = vm->mountAsec(argv[2], argv[3], atoi(argv[4]), readOnly);
    } else if (!strcmp(argv[1], "unmount")) {
        dumpArgs(argc, argv, -1);
        if (argc < 3) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Usage: asec unmount <container-id> [force]", false);
            return 0;
        }
        bool force = false;
        if (argc > 3 && !strcmp(argv[3], "force")) {
            force = true;
        }
        rc = vm->unmountAsec(argv[2], force);
    } else if (!strcmp(argv[1], "rename")) {
        dumpArgs(argc, argv, -1);
        if (argc != 4) {
            cli->sendMsg(ResponseCode::CommandSyntaxError,
                    "Usage: asec rename <old_id> <new_id>", false);
            return 0;
        }
        rc = vm->renameAsec(argv[2], argv[3]);
    } else if (!strcmp(argv[1], "path")) {
        dumpArgs(argc, argv, -1);
        if (argc != 3) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Usage: asec path <container-id>", false);
            return 0;
        }
        char path[255];

        if (!(rc = vm->getAsecMountPath(argv[2], path, sizeof(path)))) {
            cli->sendMsg(ResponseCode::AsecPathResult, path, false);
            return 0;
        }
    } else if (!strcmp(argv[1], "fspath")) {
        dumpArgs(argc, argv, -1);
        if (argc != 3) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Usage: asec fspath <container-id>", false);
            return 0;
        }
        char path[255];

        if (!(rc = vm->getAsecFilesystemPath(argv[2], path, sizeof(path)))) {
            cli->sendMsg(ResponseCode::AsecPathResult, path, false);
            return 0;
        }
    } else {
        dumpArgs(argc, argv, -1);
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Unknown asec cmd", false);
    }

    if (!rc) {
        cli->sendMsg(ResponseCode::CommandOkay, "asec operation succeeded", false);
    } else {
        rc = ResponseCode::convertFromErrno();
        cli->sendMsg(rc, "asec operation failed", true);
    }

    return 0;
}

CommandListener::ObbCmd::ObbCmd() :
                 VoldCommand("obb") {
}

int CommandListener::ObbCmd::runCommand(SocketClient *cli,
                                                      int argc, char **argv) {
    if (argc < 2) {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing Argument", false);
        return 0;
    }

    VolumeManager *vm = VolumeManager::Instance();
    int rc = 0;

    if (!strcmp(argv[1], "list")) {
        dumpArgs(argc, argv, -1);

        rc = vm->listMountedObbs(cli);
    } else if (!strcmp(argv[1], "mount")) {
            dumpArgs(argc, argv, 3);
            if (argc != 5) {
                cli->sendMsg(ResponseCode::CommandSyntaxError,
                        "Usage: obb mount <filename> <key> <ownerGid>", false);
                return 0;
            }
            rc = vm->mountObb(argv[2], argv[3], atoi(argv[4]));
    } else if (!strcmp(argv[1], "unmount")) {
        dumpArgs(argc, argv, -1);
        if (argc < 3) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Usage: obb unmount <source file> [force]", false);
            return 0;
        }
        bool force = false;
        if (argc > 3 && !strcmp(argv[3], "force")) {
            force = true;
        }
        rc = vm->unmountObb(argv[2], force);
    } else if (!strcmp(argv[1], "path")) {
        dumpArgs(argc, argv, -1);
        if (argc != 3) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Usage: obb path <source file>", false);
            return 0;
        }
        char path[255];

        if (!(rc = vm->getObbMountPath(argv[2], path, sizeof(path)))) {
            cli->sendMsg(ResponseCode::AsecPathResult, path, false);
            return 0;
        }
    } else {
        dumpArgs(argc, argv, -1);
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Unknown obb cmd", false);
    }

    if (!rc) {
        cli->sendMsg(ResponseCode::CommandOkay, "obb operation succeeded", false);
    } else {
        rc = ResponseCode::convertFromErrno();
        cli->sendMsg(rc, "obb operation failed", true);
    }

    return 0;
}

CommandListener::FstrimCmd::FstrimCmd() :
                 VoldCommand("fstrim") {
}
int CommandListener::FstrimCmd::runCommand(SocketClient *cli,
                                                      int argc, char **argv) {
    if ((cli->getUid() != 0) && (cli->getUid() != AID_SYSTEM)) {
        cli->sendMsg(ResponseCode::CommandNoPermission, "No permission to run fstrim commands", false);
        return 0;
    }

    if (argc < 2) {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing Argument", false);
        return 0;
    }

    VolumeManager *vm = VolumeManager::Instance();
    std::lock_guard<std::mutex> lock(vm->getLock());

    int flags = 0;

    std::string cmd(argv[1]);
    if (cmd == "dotrim") {
        flags = 0;
    } else if (cmd == "dotrimbench") {
        flags = android::vold::TrimTask::Flags::kBenchmarkAfter;
    } else if (cmd == "dodtrim") {
        flags = android::vold::TrimTask::Flags::kDeepTrim;
    } else if (cmd == "dodtrimbench") {
        flags = android::vold::TrimTask::Flags::kDeepTrim
                | android::vold::TrimTask::Flags::kBenchmarkAfter;
    }

    (new android::vold::TrimTask(flags))->start();
    return sendGenericOkFail(cli, 0);
}
