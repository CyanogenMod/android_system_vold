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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <poll.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>

#include <android-base/stringprintf.h>

#include <cutils/sockets.h>
#include <private/android_filesystem_config.h>

static void usage(char *progname);
static int do_monitor(int sock, int stop_after_cmd);
static int do_cmd(int sock, int argc, char **argv);

static constexpr int kCommandTimeoutMs = 20 * 1000;

int vdc_main(int argc, char **argv) {
    int sock;
    int wait_for_socket;
    char *progname;

    progname = argv[0];

    wait_for_socket = argc > 1 && strcmp(argv[1], "--wait") == 0;
    if (wait_for_socket) {
        argv++;
        argc--;
    }

    if (argc < 2) {
        usage(progname);
        exit(5);
    }

    const char* sockname = "vold";
    if (!strcmp(argv[1], "cryptfs")) {
        sockname = "cryptd";
    }

    while ((sock = socket_local_client(sockname,
                                 ANDROID_SOCKET_NAMESPACE_RESERVED,
                                 SOCK_STREAM)) < 0) {
        if (!wait_for_socket) {
            fprintf(stdout, "Error connecting to %s: %s\n", sockname, strerror(errno));
            exit(4);
        } else {
            usleep(10000);
        }
    }

    if (!strcmp(argv[1], "monitor")) {
        exit(do_monitor(sock, 0));
    } else {
        exit(do_cmd(sock, argc, argv));
    }
}

static int do_cmd(int sock, int argc, char **argv) {
    int seq = getpid();

    std::string cmd(android::base::StringPrintf("%d ", seq));
    for (int i = 1; i < argc; i++) {
        if (!strchr(argv[i], ' ')) {
            cmd.append(argv[i]);
        } else {
            cmd.push_back('\"');
            cmd.append(argv[i]);
            cmd.push_back('\"');
        }

        if (i < argc - 1) {
            cmd.push_back(' ');
        }
    }

    if (TEMP_FAILURE_RETRY(write(sock, cmd.c_str(), cmd.length() + 1)) < 0) {
        fprintf(stderr, "Failed to write command: %s\n", strerror(errno));
        return errno;
    }

    return do_monitor(sock, seq);
}

static int do_monitor(int sock, int stop_after_seq) {
    char buffer[4096];
    int timeout = kCommandTimeoutMs;

    if (stop_after_seq == 0) {
        fprintf(stderr, "Connected to vold\n");
        timeout = -1;
    }

    while (1) {
        struct pollfd poll_sock = { sock, POLLIN, 0 };
        int rc = TEMP_FAILURE_RETRY(poll(&poll_sock, 1, timeout));
        if (rc == 0) {
            fprintf(stderr, "Timeout waiting for %d\n", stop_after_seq);
            return ETIMEDOUT;
        } else if (rc < 0) {
            fprintf(stderr, "Failed during poll: %s\n", strerror(errno));
            return errno;
        }

        if (!(poll_sock.revents & POLLIN)) {
            fprintf(stderr, "No data; trying again\n");
            continue;
        }

        memset(buffer, 0, sizeof(buffer));
        rc = TEMP_FAILURE_RETRY(read(sock, buffer, sizeof(buffer)));
        if (rc == 0) {
            fprintf(stderr, "Lost connection, did vold crash?\n");
            return ECONNRESET;
        } else if (rc < 0) {
            fprintf(stderr, "Error reading data: %s\n", strerror(errno));
            return errno;
        }

        int offset = 0;
        for (int i = 0; i < rc; i++) {
            if (buffer[i] == '\0') {
                char* res = buffer + offset;
                fprintf(stdout, "%s\n", res);

                int code = atoi(strtok(res, " "));
                if (code >= 200 && code < 600) {
                    int seq = atoi(strtok(nullptr, " "));
                    if (seq == stop_after_seq) {
                        if (code == 200) {
                            return 0;
                        } else {
                            return code;
                        }
                    }
                }

                offset = i + 1;
            }
        }
    }
    return EIO;
}

static void usage(char *progname) {
    fprintf(stderr,
            "Usage: %s [--wait] <monitor>|<cmd> [arg1] [arg2...]\n", progname);
}

#ifndef MINIVOLD
int main(int argc, char **argv) {
    return vdc_main(argc, argv);
}
#endif

