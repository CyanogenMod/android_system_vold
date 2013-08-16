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

#ifndef _VOLD_LOG_H
#define _VOLD_LOG_H

#ifndef MINIVOLD
#include <cutils/log.h>
#else
#include <stdio.h>
#include <unistd.h>
#include <cutils/klog.h>

#ifndef LOG_TAG
#define LOG_TAG "minivold"
#endif

#define SLOGI(...) fprintf(stdout, __VA_ARGS__)
#define SLOGD(...) fprintf(stdout, __VA_ARGS__)
#define SLOGV(...) fprintf(stdout, __VA_ARGS__)

#define SLOGE(...) fprintf(stderr, __VA_ARGS__)
#define SLOGW(...) fprintf(stderr, __VA_ARGS__)

#endif 

#endif // _VOLD_LOG_H
