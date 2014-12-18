/*
 * Copyright (C) 2014 The Android Open Source Project
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

#define LOG_TAG "VoldCheckBattery"
#include <cutils/log.h>

#include <binder/IServiceManager.h>
#include <batteryservice/IBatteryPropertiesRegistrar.h>

using namespace android;

extern "C"
{
    int is_battery_ok_to_start()
    {
      // Bug 16868177 exists to purge this code completely
      return true; //is_battery_ok(START_THRESHOLD);
    }

    int is_battery_ok_to_continue()
    {
      // Bug 16868177 exists to purge this code completely
      return true; //is_battery_ok(CONTINUE_THRESHOLD);
    }
}
