/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include <string>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <android-base/logging.h>

// File descriptor which is automatically closed when this object is destroyed.
// Cannot be copied, since that would cause double-closes.
class AutoCloseFD {
public:
    AutoCloseFD(const char *path, int flags = O_RDONLY, int mode = 0):
        fd{TEMP_FAILURE_RETRY(open(path, flags | O_CLOEXEC, mode))} {}
    AutoCloseFD(const std::string &path, int flags = O_RDONLY, int mode = 0):
        AutoCloseFD(path.c_str(), flags, mode) {}
    ~AutoCloseFD() {
        if (fd != -1) {
            int preserve_errno = errno;
            if (close(fd) == -1) {
                PLOG(ERROR) << "close(2) failed";
            };
            errno = preserve_errno;
        }
    }
    AutoCloseFD(const AutoCloseFD&) = delete;
    AutoCloseFD& operator=(const AutoCloseFD&) = delete;
    explicit operator bool() {return fd != -1;}
    int get() const {return fd;}
private:
    const int fd;
};

