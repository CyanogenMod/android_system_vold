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

#ifndef _RESPONSECODE_H
#define _RESPONSECODE_H

#ifdef __cplusplus
class ResponseCode {
public:
#endif
    // 100 series - Requestion action was initiated; expect another reply
    // before proceeding with a new command.
    static const int ActionInitiated  = 100;

    static const int VolumeListResult         = 110;
    static const int AsecListResult           = 111;
    static const int StorageUsersListResult   = 112;

    // 200 series - Requested action has been successfully completed
    static const int CommandOkay              = 200;
    static const int ShareStatusResult        = 210;
    static const int AsecPathResult           = 211;
    static const int ShareEnabledResult       = 212;
    static const int XwarpStatusResult        = 213;

    // 400 series - The command was accepted but the requested action
    // did not take place.
    static const int OperationFailed          = 400;
    static const int OpFailedNoMedia          = 401;
    static const int OpFailedMediaBlank       = 402;
    static const int OpFailedMediaCorrupt     = 403;
    static const int OpFailedVolNotMounted    = 404;
    static const int OpFailedStorageBusy      = 405;
    static const int OpFailedStorageNotFound  = 406;

    // 500 series - The command was not accepted and the requested
    // action did not take place.
    static const int CommandSyntaxError = 500;
    static const int CommandParameterError = 501;
    static const int CommandNoPermission = 502;

    // 600 series - Unsolicited broadcasts
    static const int UnsolicitedInformational       = 600;
    static const int VolumeStateChange              = 605;
    static const int VolumeMountFailedBlank         = 610;
    static const int VolumeMountFailedDamaged       = 611;
    static const int VolumeMountFailedNoMedia       = 612;

    static const int ShareAvailabilityChange        = 620;

    static const int VolumeDiskInserted            = 630;
    static const int VolumeDiskRemoved             = 631;
    static const int VolumeBadRemoval              = 632;
#ifdef __cplusplus
    static int convertFromErrno();
};
#endif
#endif
