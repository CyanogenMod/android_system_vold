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

    class MountCmd : public VoldCommand {
    public:
        MountCmd();
        virtual ~MountCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };

    class UnmountCmd : public VoldCommand {
    public:
        UnmountCmd();
        virtual ~UnmountCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };

    class ShareCmd : public VoldCommand {
    public:
        ShareCmd();
        virtual ~ShareCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };

    class UnshareCmd : public VoldCommand {
    public:
        UnshareCmd();
        virtual ~UnshareCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };

    class ShareAvailableCmd : public VoldCommand {
    public:
        ShareAvailableCmd();
        virtual ~ShareAvailableCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };

    class SimulateCmd : public VoldCommand {
    public:
        SimulateCmd();
        virtual ~SimulateCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };

    class FormatCmd : public VoldCommand {
    public:
        FormatCmd();
        virtual ~FormatCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };

};

#endif
