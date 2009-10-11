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

#ifndef _COMMANDLISTENER_H__
#define _COMMANDLISTENER_H__

#include <sysutils/FrameworkListener.h>
#include "VoldCommand.h"

class CommandListener : public FrameworkListener {
public:
    CommandListener();
    virtual ~CommandListener() {}

private:

    class ListVolumesCmd : public VoldCommand {
    public:
        ListVolumesCmd();
        virtual ~ListVolumesCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };

    class MountVolumeCmd : public VoldCommand {
    public:
        MountVolumeCmd();
        virtual ~MountVolumeCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };

    class UnmountVolumeCmd : public VoldCommand {
    public:
        UnmountVolumeCmd();
        virtual ~UnmountVolumeCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };

    class ShareVolumeCmd : public VoldCommand {
    public:
        ShareVolumeCmd();
        virtual ~ShareVolumeCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };

    class UnshareVolumeCmd : public VoldCommand {
    public:
        UnshareVolumeCmd();
        virtual ~UnshareVolumeCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };

};

#endif
