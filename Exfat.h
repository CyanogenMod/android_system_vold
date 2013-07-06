/*
 * Copyright (C) 2013 The CyanogenMod Project
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

#ifndef _EXFAT_H
#define _EXFAT_H

#include <unistd.h>

class Exfat {
public:
    static int doMount(const char *fsPath, const char *mountPoint, bool ro, bool remount,
            bool executable, int ownerUid, int ownerGid, int permMask);
    static int check(const char *fsPath);
    static int format(const char *fsPath);
};

#endif
