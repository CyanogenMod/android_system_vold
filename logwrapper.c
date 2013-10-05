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

#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "private/android_filesystem_config.h"
#include "cutils/log.h"
#include "cutils/sched_policy.h"

int parent(const char *tag, int parent_read) {
    int status;
    char buffer[4096];

    int a = 0;  // start index of unprocessed data
    int b = 0;  // end index of unprocessed data
    int sz;
    while ((sz = read(parent_read, &buffer[b], sizeof(buffer) - 1 - b)) > 0) {

        sz += b;
        // Log one line at a time
        for (b = 0; b < sz; b++) {
            if (buffer[b] == '\r') {
                buffer[b] = '\0';
            } else if (buffer[b] == '\n') {
                buffer[b] = '\0';

                ALOG(LOG_INFO, tag, "%s", &buffer[a]);
                a = b + 1;
            }
        }

        if (a == 0 && b == sizeof(buffer) - 1) {
            // buffer is full, flush
            buffer[b] = '\0';
            ALOG(LOG_INFO, tag, "%s", &buffer[a]);
            b = 0;
        } else if (a != b) {
            // Keep left-overs
            b -= a;
            memmove(buffer, &buffer[a], b);
            a = 0;
        } else {
            a = 0;
            b = 0;
        }

    }
    // Flush remaining data
    if (a != b) {
        buffer[b] = '\0';
        ALOG(LOG_INFO, tag, "%s", &buffer[a]);
    }
    status = 0xAAAA;
    if (wait(&status) != -1) {  // Wait for child
        if (WIFEXITED(status)) {
            if (WEXITSTATUS(status) != 0) {
                ALOG(LOG_INFO, "logwrapper", "%s terminated by exit(%d)", tag,
                        WEXITSTATUS(status));
            }
            return WEXITSTATUS(status);
        } else if (WIFSIGNALED(status))
            ALOG(LOG_INFO, "logwrapper", "%s terminated by signal %d", tag,
                    WTERMSIG(status));
        else if (WIFSTOPPED(status))
            ALOG(LOG_INFO, "logwrapper", "%s stopped by signal %d", tag,
                    WSTOPSIG(status));
    } else
        ALOG(LOG_INFO, "logwrapper", "%s wait() failed: %s (%d)", tag,
                strerror(errno), errno);
    return -EAGAIN;
}

void child(int argc, const char**argv) {
    // create null terminated argv_child array
    char* argv_child[argc + 1];
    memcpy(argv_child, argv, argc * sizeof(char *));
    argv_child[argc] = NULL;

    // XXX: PROTECT FROM VIKING KILLER
    if (execv(argv_child[0], argv_child)) {
        ALOG(LOG_ERROR, "logwrapper",
            "executing %s failed: %s", argv_child[0], strerror(errno));
        _exit(-1);
    }
}

int logwrap(int argc, const char* argv[], int background)
{
    pid_t pid;

    int parent_ptty;
    int child_ptty;
    char *child_devname = NULL;

    /* Use ptty instead of socketpair so that STDOUT is not buffered */
    parent_ptty = open("/dev/ptmx", O_RDWR);
    if (parent_ptty < 0) {
        ALOG(LOG_ERROR, "logwrapper", "Cannot create parent ptty");
        return -errno;
    }

    if (grantpt(parent_ptty) || unlockpt(parent_ptty) ||
            ((child_devname = (char*)ptsname(parent_ptty)) == 0)) {
        close(parent_ptty);
        ALOG(LOG_ERROR, "logwrapper", "Problem with /dev/ptmx");
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        close(parent_ptty);
        ALOG(LOG_ERROR, "logwrapper", "Failed to fork");
        return -errno;
    } else if (pid == 0) {
        /*
         * Child
         */
        child_ptty = open(child_devname, O_RDWR);
        if (child_ptty < 0) {
            close(parent_ptty);
            ALOG(LOG_ERROR, "logwrapper", "Problem with child ptty");
            _exit(-errno);
        }

        // redirect stdout and stderr
        close(parent_ptty);
        dup2(child_ptty, 1);
        dup2(child_ptty, 2);
        close(child_ptty);

        if (background) {
            int err = set_sched_policy(getpid(), SP_BACKGROUND);
            if (err < 0) {
                ALOG(LOG_WARN, "logwrapper",
                    "Unable to background process (%s)", strerror(-err));
            }
        }

        child(argc, argv);
    } else {
        /*
         * Parent
         */
        int rc = parent(argv[0], parent_ptty);
        close(parent_ptty);
        return rc;
    }

    return 0;
}
