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
    registerCmd(new ListVolumesCmd());
    registerCmd(new MountCmd());
    registerCmd(new UnmountCmd());
    registerCmd(new ShareCmd());
    registerCmd(new UnshareCmd());
    registerCmd(new ShareAvailableCmd());
    registerCmd(new SimulateCmd());
    registerCmd(new FormatCmd());
    registerCmd(new CreateAsecCmd());
    registerCmd(new FinalizeAsecCmd());
    registerCmd(new DestroyAsecCmd());
    registerCmd(new MountAsecCmd());
    registerCmd(new ListAsecCmd());
    registerCmd(new AsecPathCmd());
}

CommandListener::ListVolumesCmd::ListVolumesCmd() :
                 VoldCommand("list_volumes") {
}

int CommandListener::ListVolumesCmd::runCommand(SocketClient *cli,
                                                      int argc, char **argv) {
    return VolumeManager::Instance()->listVolumes(cli);
}

CommandListener::MountCmd::MountCmd() :
                 VoldCommand("mount") {
}

int CommandListener::MountCmd::runCommand(SocketClient *cli,
                                                      int argc, char **argv) {
    /* Synchronously mount a volume */
    if (VolumeManager::Instance()->mountVolume(argv[1])) {
        cli->sendMsg(ResponseCode::OperationFailed, "Failed to mount volume.", true);
    } else {
        cli->sendMsg(ResponseCode::CommandOkay, "Volume mounted.", false);
    }

    return 0;
}

CommandListener::UnmountCmd::UnmountCmd() :
                 VoldCommand("unmount") {
}

int CommandListener::UnmountCmd::runCommand(SocketClient *cli,
                                                      int argc, char **argv) {
    /* Synchronously unmount a volume */
    if (VolumeManager::Instance()->unmountVolume(argv[1])) {
        cli->sendMsg(ResponseCode::OperationFailed, "Failed to unmount volume.", true);
    } else {
        cli->sendMsg(ResponseCode::CommandOkay, "Volume unmounted.", false);
    }

    return 0;
}

CommandListener::ShareCmd::ShareCmd() :
                 VoldCommand("share") {
}

int CommandListener::ShareCmd::runCommand(SocketClient *cli,
                                                      int argc, char **argv) {
    if (VolumeManager::Instance()->shareVolume(argv[1], argv[2])) {
        cli->sendMsg(ResponseCode::OperationFailed, "Failed to share volume.", true);
    } else {
        cli->sendMsg(ResponseCode::CommandOkay, "Volume shared.", false);
    }

    return 0;
}

CommandListener::UnshareCmd::UnshareCmd() :
                 VoldCommand("unshare") {
}

int CommandListener::UnshareCmd::runCommand(SocketClient *cli,
                                                      int argc, char **argv) {
    if (VolumeManager::Instance()->unshareVolume(argv[1], argv[2])) {
        cli->sendMsg(ResponseCode::OperationFailed, "Failed to unshare volume.", true);
    } else {
        cli->sendMsg(ResponseCode::CommandOkay, "Volume unshared.", false);
    }

    return 0;
}

CommandListener::ShareAvailableCmd::ShareAvailableCmd() :
                 VoldCommand("share_available") {
}

int CommandListener::ShareAvailableCmd::runCommand(SocketClient *cli,
                                                      int argc, char **argv) {
    bool avail = false;

    if (VolumeManager::Instance()->shareAvailable(argv[1], &avail)) {
        cli->sendMsg(ResponseCode::OperationFailed,
                     "Failed to determine share availability", true);
    } else {
        cli->sendMsg(ResponseCode::ShareAvailabilityResult,
                     (avail ? "Share available" : "Share unavailable"),
                     false);
    }
    return 0;
}

CommandListener::SimulateCmd::SimulateCmd() :
                 VoldCommand("simulate") {
}

int CommandListener::SimulateCmd::runCommand(SocketClient *cli,
                                            int argc, char **argv) {
    if (VolumeManager::Instance()->simulate(argv[1], argv[2])) {
        cli->sendMsg(ResponseCode::OperationFailed, "Failed to execute.", true);
    } else {
        cli->sendMsg(ResponseCode::CommandOkay, "Simulation executed.", false);
    }

    return 0;
}

CommandListener::FormatCmd::FormatCmd() :
                 VoldCommand("format") {
}

int CommandListener::FormatCmd::runCommand(SocketClient *cli,
                                            int argc, char **argv) {
    if (VolumeManager::Instance()->formatVolume(argv[1])) {
        cli->sendMsg(ResponseCode::OperationFailed, "Failed to format", true);
    } else {
        cli->sendMsg(ResponseCode::CommandOkay, "Volume formatted.", false);
    }

    return 0;
}

CommandListener::CreateAsecCmd::CreateAsecCmd() :
                 VoldCommand("create_asec") {
}

int CommandListener::CreateAsecCmd::runCommand(SocketClient *cli,
                                            int argc, char **argv) {
    if (argc != 6) {
        cli->sendMsg(ResponseCode::CommandSyntaxError,
                     "Usage: create_asec <namespace-id> <size_mb> <fstype> <key> <ownerUid>",
                     false);
        return 0;
    }

    if (VolumeManager::Instance()->createAsec(argv[1], atoi(argv[2]),
                                              argv[3], argv[4],
                                              atoi(argv[5]))) {
        cli->sendMsg(ResponseCode::OperationFailed, "Cache creation failed", true);
    } else {
        cli->sendMsg(ResponseCode::CommandOkay, "Cache created", false);
    }

    return 0;
}

CommandListener::FinalizeAsecCmd::FinalizeAsecCmd() :
                 VoldCommand("finalize_asec") {
}

int CommandListener::FinalizeAsecCmd::runCommand(SocketClient *cli,
                                            int argc, char **argv) {
    if (argc != 2) {
        cli->sendMsg(ResponseCode::CommandSyntaxError,
                     "Usage: finalize_asec <namespace-id>", false);
        return 0;
    }

    if (VolumeManager::Instance()->finalizeAsec(argv[1])) {
        cli->sendMsg(ResponseCode::OperationFailed, "Cache finalize failed", true);
    } else {
        cli->sendMsg(ResponseCode::CommandOkay, "Cache finalized", false);
    }
    return 0;
}

CommandListener::DestroyAsecCmd::DestroyAsecCmd() :
                 VoldCommand("destroy_asec") {
}

int CommandListener::DestroyAsecCmd::runCommand(SocketClient *cli,
                                            int argc, char **argv) {
    if (argc != 2) {
        cli->sendMsg(ResponseCode::CommandSyntaxError,
                     "Usage: destroy_asec <namespace-id>", false);
        return 0;
    }

    if (VolumeManager::Instance()->destroyAsec(argv[1])) {
        cli->sendMsg(ResponseCode::OperationFailed, "Destroy failed", true);
    } else {
        cli->sendMsg(ResponseCode::CommandOkay, "Cache Destroyed", false);
    }
    return 0;
}

CommandListener::MountAsecCmd::MountAsecCmd() :
                 VoldCommand("mount_asec") {
}

int CommandListener::MountAsecCmd::runCommand(SocketClient *cli,
                                            int argc, char **argv) {
    if (argc != 4) {
        cli->sendMsg(ResponseCode::CommandSyntaxError,
                     "Usage: mount_asec <namespace-id> <key> <ownerUid>", false);
        return 0;
    }

    if (VolumeManager::Instance()->mountAsec(argv[1], argv[2], atoi(argv[3]))) {
        cli->sendMsg(ResponseCode::OperationFailed, "Mount failed", true);
    } else {
        cli->sendMsg(ResponseCode::CommandOkay, "Mount succeeded", false);
    }
    return 0;
}

CommandListener::ListAsecCmd::ListAsecCmd() :
                 VoldCommand("list_asec") {

}

int CommandListener::ListAsecCmd::runCommand(SocketClient *cli,
                                            int argc, char **argv) {
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

    return 0;
}

CommandListener::AsecPathCmd::AsecPathCmd() :
                 VoldCommand("asec_path") {
}

int CommandListener::AsecPathCmd::runCommand(SocketClient *cli,
                                            int argc, char **argv) {
    if (argc != 2) {
        cli->sendMsg(ResponseCode::CommandSyntaxError,
                     "Usage: asec_path <namespace-id>", false);
        return 0;
    }

    char mountPath[255];

    if (VolumeManager::Instance()->getAsecMountPath(argv[1], mountPath,
                                                    sizeof(mountPath))) {
        cli->sendMsg(ResponseCode::OperationFailed, "Failed to get mount path", true);
    } else {
        cli->sendMsg(ResponseCode::AsecPathResult, mountPath, false);
    }

    return 0;
}
