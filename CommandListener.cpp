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
#include <netinet/in.h>
#include <arpa/inet.h>
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
