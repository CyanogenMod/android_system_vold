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
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>

#include "private/android_filesystem_config.h"
#include "cutils/log.h"
#include "cutils/sched_policy.h"

struct monitor_data {
    const char *tag;
    int fd;
};

static int parent(const char *tag, int parent_read, int monitor_read) {
    int status;
    char buffer[4096];
    fd_set fds;
    int maxfd;
    int rc = -EAGAIN;

    int a = 0;  // start index of unprocessed data
    int b = 0;  // end index of unprocessed data
    int sz;

    maxfd = 1 + (parent_read > monitor_read ? parent_read : monitor_read);

    do {
        FD_ZERO(&fds);
        FD_SET(parent_read, &fds);
        FD_SET(monitor_read, &fds);

        if (select(maxfd, &fds, NULL, NULL, NULL) <= 0) {
            ALOG(LOG_INFO, "logwrapper", "select failed");
            break;
        }

        if (FD_ISSET(parent_read, &fds)) {
            sz = read(parent_read, &buffer[b], sizeof(buffer) - 1 - b);

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

        // Child exited, get return status and exit loop
        if (FD_ISSET(monitor_read, &fds)) {
            if (read(monitor_read, &rc, sizeof(rc)) != sizeof(rc)) {
                ALOG(LOG_ERROR, "logwrapper", "Unable to read child return "
                        "status");
                rc = -ECHILD;
            }
            break;
        }
    } while (1);

    // Flush remaining data
    if (a != b) {
        buffer[b] = '\0';
        ALOG(LOG_INFO, tag, "%s", &buffer[a]);
    }

    return rc;
}

static void child(int argc, const char**argv) {
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

static void *monitor(void *arg)
{
    struct monitor_data *data = arg;
    int status;
    int rc = -EAGAIN;

    if (wait(&status) != -1) {  // Wait for child
        if (WIFEXITED(status)) {
            if (WEXITSTATUS(status) != 0) {
                ALOG(LOG_INFO, "logwrapper", "%s terminated by exit(%d)",
                        data->tag, WEXITSTATUS(status));
            }
            rc = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status))
            ALOG(LOG_INFO, "logwrapper", "%s terminated by signal %d",
                    data->tag, WTERMSIG(status));
        else if (WIFSTOPPED(status))
            ALOG(LOG_INFO, "logwrapper", "%s stopped by signal %d", data->tag,
                    WSTOPSIG(status));
    } else
        ALOG(LOG_INFO, "logwrapper", "%s wait() failed: %s (%d)", data->tag,
                strerror(errno), errno);

    write(data->fd, &rc, sizeof(rc));
    return NULL;
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
        close(parent_ptty);
        child_ptty = open(child_devname, O_RDWR);
        if (child_ptty < 0) {
            ALOG(LOG_ERROR, "logwrapper", "Problem with child ptty");
            _exit(-errno);
        }

        // redirect stdout and stderr
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
        int rc, err;
        int sockets[2];
        pthread_t thread_id;
        struct monitor_data data;

        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets)) {
            err = errno;
            ALOG(LOG_ERROR, "logwrapper", "Unable to create monitoring "
                    "socket: %s (%d)", strerror(err), err);
            exit(-err);
        }
        data.tag = argv[0];
        data.fd = sockets[1];
        err = pthread_create(&thread_id, NULL, monitor, &data);
        if (err != 0) {
            ALOG(LOG_ERROR, "logwrapper", "Unable to create monitoring "
                    "thread: %s (%d)", strerror(err), err);
            exit(-err);
        }
        rc = parent(argv[0], parent_ptty, sockets[0]);
        close(parent_ptty);
        close(sockets[0]);
        close(sockets[1]);
        return rc;
    }

    return 0;
}
