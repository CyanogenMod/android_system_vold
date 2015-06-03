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

#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fs_mgr.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#define LOG_TAG "VoldCryptCmdListener"

#include <base/stringprintf.h>
#include <cutils/fs.h>
#include <cutils/log.h>
#include <cutils/sockets.h>

#include <sysutils/SocketClient.h>
#include <private/android_filesystem_config.h>

#include "CryptCommandListener.h"
#include "Process.h"
#include "ResponseCode.h"
#include "cryptfs.h"

#define DUMP_ARGS 0

CryptCommandListener::CryptCommandListener() :
FrameworkListener("cryptd", true) {
    registerCmd(new CryptfsCmd());
}

#if DUMP_ARGS
void CryptCommandListener::dumpArgs(int argc, char **argv, int argObscure) {
    char buffer[4096];
    char *p = buffer;

    memset(buffer, 0, sizeof(buffer));
    int i;
    for (i = 0; i < argc; i++) {
        unsigned int len = strlen(argv[i]) + 1; // Account for space
        if (i == argObscure) {
            len += 2; // Account for {}
        }
        if (((p - buffer) + len) < (sizeof(buffer)-1)) {
            if (i == argObscure) {
                *p++ = '{';
                *p++ = '}';
                *p++ = ' ';
                continue;
            }
            strcpy(p, argv[i]);
            p+= strlen(argv[i]);
            if (i != (argc -1)) {
                *p++ = ' ';
            }
        }
    }
    SLOGD("%s", buffer);
}
#else
void CryptCommandListener::dumpArgs(int /*argc*/, char ** /*argv*/, int /*argObscure*/) { }
#endif

int CryptCommandListener::sendGenericOkFail(SocketClient *cli, int cond) {
    if (!cond) {
        return cli->sendMsg(ResponseCode::CommandOkay, "Command succeeded", false);
    } else {
        return cli->sendMsg(ResponseCode::OperationFailed, "Command failed", false);
    }
}

CryptCommandListener::CryptfsCmd::CryptfsCmd() :
                 VoldCommand("cryptfs") {
}

static int getType(const char* type)
{
    if (!strcmp(type, "default")) {
        return CRYPT_TYPE_DEFAULT;
    } else if (!strcmp(type, "password")) {
        return CRYPT_TYPE_PASSWORD;
    } else if (!strcmp(type, "pin")) {
        return CRYPT_TYPE_PIN;
    } else if (!strcmp(type, "pattern")) {
        return CRYPT_TYPE_PATTERN;
    } else {
        return -1;
    }
}

int CryptCommandListener::CryptfsCmd::runCommand(SocketClient *cli,
                                                 int argc, char **argv) {
    if ((cli->getUid() != 0) && (cli->getUid() != AID_SYSTEM)) {
        cli->sendMsg(ResponseCode::CommandNoPermission, "No permission to run cryptfs commands", false);
        return 0;
    }

    if (argc < 2) {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing Argument", false);
        return 0;
    }

    int rc = 0;

    if (!strcmp(argv[1], "checkpw")) {
        if (argc != 3) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Usage: cryptfs checkpw <passwd>", false);
            return 0;
        }
        dumpArgs(argc, argv, 2);
        rc = cryptfs_check_passwd(argv[2]);
    } else if (!strcmp(argv[1], "restart")) {
        if (argc != 2) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Usage: cryptfs restart", false);
            return 0;
        }
        dumpArgs(argc, argv, -1);
        rc = cryptfs_restart();
    } else if (!strcmp(argv[1], "cryptocomplete")) {
        if (argc != 2) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Usage: cryptfs cryptocomplete", false);
            return 0;
        }
        dumpArgs(argc, argv, -1);
        rc = cryptfs_crypto_complete();
    } else if (!strcmp(argv[1], "enablecrypto")) {
        const char* syntax = "Usage: cryptfs enablecrypto <wipe|inplace> "
                             "default|password|pin|pattern [passwd]";
        if ( (argc != 4 && argc != 5)
             || (strcmp(argv[2], "wipe") && strcmp(argv[2], "inplace")) ) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, syntax, false);
            return 0;
        }
        dumpArgs(argc, argv, 4);

        int tries;
        for (tries = 0; tries < 2; ++tries) {
            int type = getType(argv[3]);
            if (type == -1) {
                cli->sendMsg(ResponseCode::CommandSyntaxError, syntax,
                             false);
                return 0;
            } else if (type == CRYPT_TYPE_DEFAULT) {
              rc = cryptfs_enable_default(argv[2], /*allow_reboot*/false);
            } else {
                rc = cryptfs_enable(argv[2], type, argv[4],
                                    /*allow_reboot*/false);
            }

            if (rc == 0) {
                break;
            } else if (tries == 0) {
                Process::killProcessesWithOpenFiles(DATA_MNT_POINT, SIGKILL);
            }
        }
    } else if (!strcmp(argv[1], "enablefilecrypto")) {
        const char* syntax = "Usage: cryptfs enablefilecrypto";
        if (argc != 2) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, syntax, false);
            return 0;
        }
        dumpArgs(argc, argv, -1);
        rc = cryptfs_enable_file();
    } else if (!strcmp(argv[1], "changepw")) {
        const char* syntax = "Usage: cryptfs changepw "
                             "default|password|pin|pattern [newpasswd]";
        const char* password;
        if (argc == 3) {
            password = "";
        } else if (argc == 4) {
            password = argv[3];
        } else {
            cli->sendMsg(ResponseCode::CommandSyntaxError, syntax, false);
            return 0;
        }
        int type = getType(argv[2]);
        if (type == -1) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, syntax, false);
            return 0;
        }
        SLOGD("cryptfs changepw %s {}", argv[2]);
        rc = cryptfs_changepw(type, password);
    } else if (!strcmp(argv[1], "verifypw")) {
        if (argc != 3) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Usage: cryptfs verifypw <passwd>", false);
            return 0;
        }
        SLOGD("cryptfs verifypw {}");
        rc = cryptfs_verify_passwd(argv[2]);
    } else if (!strcmp(argv[1], "getfield")) {
        char *valbuf;
        int valbuf_len = PROPERTY_VALUE_MAX;

        if (argc != 3) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Usage: cryptfs getfield <fieldname>", false);
            return 0;
        }
        dumpArgs(argc, argv, -1);

        // Increase the buffer size until it is big enough for the field value stored.
        while (1) {
            valbuf = (char*)malloc(valbuf_len);
            if (valbuf == NULL) {
                cli->sendMsg(ResponseCode::OperationFailed, "Failed to allocate memory", false);
                return 0;
            }
            rc = cryptfs_getfield(argv[2], valbuf, valbuf_len);
            if (rc != CRYPTO_GETFIELD_ERROR_BUF_TOO_SMALL) {
                break;
            }
            free(valbuf);
            valbuf_len *= 2;
        }
        if (rc == CRYPTO_GETFIELD_OK) {
            cli->sendMsg(ResponseCode::CryptfsGetfieldResult, valbuf, false);
        }
        free(valbuf);
    } else if (!strcmp(argv[1], "setfield")) {
        if (argc != 4) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, "Usage: cryptfs setfield <fieldname> <value>", false);
            return 0;
        }
        dumpArgs(argc, argv, -1);
        rc = cryptfs_setfield(argv[2], argv[3]);
    } else if (!strcmp(argv[1], "mountdefaultencrypted")) {
        SLOGD("cryptfs mountdefaultencrypted");
        dumpArgs(argc, argv, -1);
        rc = cryptfs_mount_default_encrypted();
    } else if (!strcmp(argv[1], "getpwtype")) {
        SLOGD("cryptfs getpwtype");
        dumpArgs(argc, argv, -1);
        switch(cryptfs_get_password_type()) {
        case CRYPT_TYPE_PASSWORD:
            cli->sendMsg(ResponseCode::PasswordTypeResult, "password", false);
            return 0;
        case CRYPT_TYPE_PATTERN:
            cli->sendMsg(ResponseCode::PasswordTypeResult, "pattern", false);
            return 0;
        case CRYPT_TYPE_PIN:
            cli->sendMsg(ResponseCode::PasswordTypeResult, "pin", false);
            return 0;
        case CRYPT_TYPE_DEFAULT:
            cli->sendMsg(ResponseCode::PasswordTypeResult, "default", false);
            return 0;
        default:
          /** @TODO better error and make sure handled by callers */
            cli->sendMsg(ResponseCode::OpFailedStorageNotFound, "Error", false);
            return 0;
        }
    } else if (!strcmp(argv[1], "getpw")) {
        SLOGD("cryptfs getpw");
        dumpArgs(argc, argv, -1);
        const char* password = cryptfs_get_password();
        if (password) {
            char* message = 0;
            int size = asprintf(&message, "{{sensitive}} %s", password);
            if (size != -1) {
                cli->sendMsg(ResponseCode::CommandOkay, message, false);
                memset(message, 0, size);
                free (message);
                return 0;
            }
        }
        rc = -1;
    } else if (!strcmp(argv[1], "clearpw")) {
        SLOGD("cryptfs clearpw");
        dumpArgs(argc, argv, -1);
        cryptfs_clear_password();
        rc = 0;
    } else {
        dumpArgs(argc, argv, -1);
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Unknown cryptfs cmd", false);
        return 0;
    }

    // Always report that the command succeeded and return the error code.
    // The caller will check the return value to see what the error was.
    char msg[255];
    snprintf(msg, sizeof(msg), "%d", rc);
    cli->sendMsg(ResponseCode::CommandOkay, msg, false);

    return 0;
}
