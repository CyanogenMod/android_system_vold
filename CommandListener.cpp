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
#include "ErrorCode.h"

CommandListener::CommandListener() :
                 FrameworkListener("vold") {
    registerCmd(new ListVolumesCmd());
    registerCmd(new MountVolumeCmd());
    registerCmd(new UnmountVolumeCmd());
    registerCmd(new ShareVolumeCmd());
    registerCmd(new UnshareVolumeCmd());
}

CommandListener::ListVolumesCmd::ListVolumesCmd() :
                 VoldCommand("list_volumes") {
}

int CommandListener::ListVolumesCmd::runCommand(SocketClient *cli,
                                                      int argc, char **argv) {
    return VolumeManager::Instance()->listVolumes(cli);
}

CommandListener::MountVolumeCmd::MountVolumeCmd() :
                 VoldCommand("mount_volume") {
}

int CommandListener::MountVolumeCmd::runCommand(SocketClient *cli,
                                                      int argc, char **argv) {
    /* Synchronously mount a volume */
    if (VolumeManager::Instance()->mountVolume(argv[1])) {
        cli->sendMsg(ErrorCode::OperationFailed, "Failed to mount volume.", true);
    } else {
        cli->sendMsg(ErrorCode::CommandOkay, "Volume mounted.", false);
    }

    return 0;
}

CommandListener::UnmountVolumeCmd::UnmountVolumeCmd() :
                 VoldCommand("unmount_volume") {
}

int CommandListener::UnmountVolumeCmd::runCommand(SocketClient *cli,
                                                      int argc, char **argv) {
    /* Synchronously unmount a volume */
    if (VolumeManager::Instance()->mountVolume(argv[1])) {
        cli->sendMsg(ErrorCode::OperationFailed, "Failed to unmount volume.", true);
    } else {
        cli->sendMsg(ErrorCode::CommandOkay, "Volume unmounted.", false);
    }

    return 0;
}

CommandListener::ShareVolumeCmd::ShareVolumeCmd() :
                 VoldCommand("share_volume") {
}

int CommandListener::ShareVolumeCmd::runCommand(SocketClient *cli,
                                                      int argc, char **argv) {
    VolumeManager *nm = VolumeManager::Instance();
    errno = ENOSYS;
    cli->sendMsg(ErrorCode::OperationFailed, "Failed to share volume", true);
    return 0;
}

CommandListener::UnshareVolumeCmd::UnshareVolumeCmd() :
                 VoldCommand("unshare_volume") {
}

int CommandListener::UnshareVolumeCmd::runCommand(SocketClient *cli,
                                                      int argc, char **argv) {
    VolumeManager *nm = VolumeManager::Instance();
    errno = ENOSYS;
    cli->sendMsg(ErrorCode::OperationFailed, "Failed to unshare volume", true);
    return 0;
}
