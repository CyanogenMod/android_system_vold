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

#define LOG_TAG "CommandListener"
#include <cutils/log.h>

#include <sysutils/SocketClient.h>

#include "CommandListener.h"
#include "VolumeManager.h"
#include "ResponseCode.h"

CommandListener::CommandListener() :
                 FrameworkListener("vold") {
    registerCmd(new VolumeCmd());
    registerCmd(new AsecCmd());
    registerCmd(new ShareCmd());
}

CommandListener::VolumeCmd::VolumeCmd() :
                 VoldCommand("volume") {
}

int CommandListener::VolumeCmd::runCommand(SocketClient *cli,
                                                      int argc, char **argv) {
    if (argc < 2) {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing Argument", false);
        return 0;
    }

    VolumeManager *vm = VolumeManager::Instance();
    int rc = 0;

    if (!strcmp(argv[1], "list")) {
        return vm->listVolumes(cli);
    } else if (!strcmp(argv[1], "mount")) {
        rc = vm->mountVolume(argv[2]);
    } else if (!strcmp(argv[1], "unmount")) {
        rc = vm->unmountVolume(argv[2]);
    } else if (!strcmp(argv[1], "format")) {
        rc = vm->formatVolume(argv[2]);
    } else if (!strcmp(argv[1], "share")) {
        rc = vm->shareVolume(argv[1], argv[2]);
    } else if (!strcmp(argv[1], "unshare")) {
        rc = vm->unshareVolume(argv[1], argv[2]);
    } else if (!strcmp(argv[1], "shared")) {
        bool enabled = false;

        if (vm->shareEnabled(argv[1], argv[2], &enabled)) {
            cli->sendMsg(
                    ResponseCode::OperationFailed, "Failed to determine share enable state", true);
        } else {
            cli->sendMsg(ResponseCode::ShareEnabledResult,
                    (enabled ? "Share enabled" : "Share disabled"), false);
        }
    } else {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Unknown volume cmd", false);
    }

    if (!rc) {
        cli->sendMsg(ResponseCode::CommandOkay, "volume operation succeeded", false);
    } else {
        /*
         * Failed
         */
        if (errno == ENODEV) {
            rc = ResponseCode::OpFailedNoMedia;
        } else if (errno == ENODATA) {
            rc = ResponseCode::OpFailedMediaBlank;
        } else if (errno == EIO) {
            rc = ResponseCode::OpFailedMediaCorrupt;
        } else if (errno == EBUSY) {
            rc = ResponseCode::OpFailedVolBusy;
        } else {
            rc = ResponseCode::OperationFailed;
        }
        cli->sendMsg(rc, "volume operation failed", true);
    }

    return 0;
}

CommandListener::ShareCmd::ShareCmd() :
                 VoldCommand("share") {
}

int CommandListener::ShareCmd::runCommand(SocketClient *cli,
                                                      int argc, char **argv) {
    if (argc < 2) {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing Argument", false);
        return 0;
    }

    VolumeManager *vm = VolumeManager::Instance();
    int rc = 0;

    if (!strcmp(argv[1], "status")) {
        bool avail = false;

        if (vm->shareAvailable(argv[2], &avail)) {
            cli->sendMsg(
                    ResponseCode::OperationFailed, "Failed to determine share availability", true);
        } else {
            cli->sendMsg(ResponseCode::ShareStatusResult,
                    (avail ? "Share available" : "Share unavailable"), false);
        }
    } else {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Unknown share cmd", false);
    }

    return 0;
}

CommandListener::AsecCmd::AsecCmd() :
                 VoldCommand("asec") {
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
        DIR *d = opendir("/sdcard/android_secure");

        if (!d) {
            cli->sendMsg(ResponseCode::OperationFailed, "Failed to open asec dir", true);
            return 0;
        }

        struct dirent *dent;
        while ((dent = readdir(d))) {
            if (dent->d_name[0] == '.')
                continue;
            if (!strcmp(&dent->d_name[strlen(dent->d_name)-5], ".asec")) {
                char id[255];
                memset(id, 0, sizeof(id));
                strncpy(id, dent->d_name, strlen(dent->d_name) -5);
                cli->sendMsg(ResponseCode::AsecListResult, id, false);
            }
        }
        closedir(d);
        cli->sendMsg(ResponseCode::CommandOkay, "ASEC listing complete", false);
    } else if (!strcmp(argv[1], "create")) {
        if (argc != 7) {
            cli->sendMsg(ResponseCode::CommandSyntaxError,
                    "Usage: asec create <container-id> <size_mb> <fstype> <key> <ownerUid>", false);
            return 0;
        }

        unsigned int numSectors = (atoi(argv[3]) * (1024 * 1024)) / 512;
        if (vm->createAsec(argv[2], numSectors, argv[4], argv[5], atoi(argv[6]))) {
            cli->sendMsg(ResponseCode::OperationFailed, "Container creation failed", true);
        } else {
            cli->sendMsg(ResponseCode::CommandOkay, "Container created", false);
        }
    } else if (!strcmp(argv[1], "finalize")) {
        if (argc != 3) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Usage: asec finalize <container-id>", false);
            return 0;
        }
        if (vm->finalizeAsec(argv[2])) {
            cli->sendMsg(ResponseCode::OperationFailed, "Container finalize failed", true);
        } else {
            cli->sendMsg(ResponseCode::CommandOkay, "Container finalized", false);
        }
    } else if (!strcmp(argv[1], "destroy")) {
        if (argc != 3) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Usage: asec destroy <container-id>", false);
            return 0;
        }
        if (vm->destroyAsec(argv[2])) {
            cli->sendMsg(ResponseCode::OperationFailed, "Container destroy failed", true);
        } else {
            cli->sendMsg(ResponseCode::CommandOkay, "Container destroyed", false);
        }
    } else if (!strcmp(argv[1], "mount")) {
        if (argc != 5) {
            cli->sendMsg(ResponseCode::CommandSyntaxError,
                    "Usage: asec mount <namespace-id> <key> <ownerUid>", false);
            return 0;
        }

        int rc = vm->mountAsec(argv[2], argv[3], atoi(argv[4]));

        if (rc < 0) {
            cli->sendMsg(ResponseCode::OperationFailed, "Mount failed", true);
        } else {
            cli->sendMsg(ResponseCode::CommandOkay, "Mount succeeded", false);
        }

    } else if (!strcmp(argv[1], "unmount")) {
        if (argc != 3) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Usage: asec unmount <container-id>", false);
            return 0;
        }
        if (vm->unmountAsec(argv[2])) {
            cli->sendMsg(ResponseCode::OperationFailed, "Container unmount failed", true);
        } else {
            cli->sendMsg(ResponseCode::CommandOkay, "Container unmounted", false);
        }
    } else if (!strcmp(argv[1], "rename")) {
        if (argc != 4) {
            cli->sendMsg(ResponseCode::CommandSyntaxError,
                    "Usage: asec rename <old_id> <new_id>", false);
            return 0;
        }
        if (vm->renameAsec(argv[2], argv[3])) {
            cli->sendMsg(ResponseCode::OperationFailed, "Container rename failed", true);
        } else {
            cli->sendMsg(ResponseCode::CommandOkay, "Container renamed", false);
        }
    } else if (!strcmp(argv[1], "path")) {
        if (argc != 3) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Usage: asec path <container-id>", false);
            return 0;
        }
        char path[255];

        if (vm->getAsecMountPath(argv[2], path, sizeof(path))) {
            cli->sendMsg(ResponseCode::OperationFailed, "Failed to get path", true);
        } else {
            cli->sendMsg(ResponseCode::AsecPathResult, path, false);
        }
    } else {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Unknown asec cmd", false);
    }

    return 0;
}
