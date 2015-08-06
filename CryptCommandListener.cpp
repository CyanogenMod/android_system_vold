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
#include <sys/stat.h>
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

#include <algorithm>
#include <thread>

#define LOG_TAG "VoldCryptCmdListener"

#include <android-base/logging.h>
#include <android-base/stringprintf.h>

#include <cutils/fs.h>
#include <cutils/log.h>
#include <cutils/sockets.h>

#include <sysutils/SocketClient.h>
#include <private/android_filesystem_config.h>

#include "CryptCommandListener.h"
#include "Process.h"
#include "ResponseCode.h"
#include "cryptfs.h"
#include "Ext4Crypt.h"
#include "Utils.h"

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

int CryptCommandListener::sendGenericOkFailOnBool(SocketClient *cli, bool success) {
    if (success) {
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

static char* parseNull(char* arg) {
    if (strcmp(arg, "!") == 0) {
        return nullptr;
    } else {
        return arg;
    }
}

static bool check_argc(SocketClient *cli, const std::string &subcommand, int argc,
        int expected, std::string usage) {
    assert(expected >= 2);
    if (expected == 2) {
        assert(usage.empty());
    } else {
        assert(!usage.empty());
        assert(std::count(usage.begin(), usage.end(), ' ') + 3 == expected);
    }
    if (argc == expected) {
        return true;
    }
    auto message = std::string() + "Usage: cryptfs " + subcommand;
    if (!usage.empty()) {
        message += " " + usage;
    }
    cli->sendMsg(ResponseCode::CommandSyntaxError, message.c_str(), false);
    return false;
}

static int do_enablecrypto(char* arg2, char* arg4, int type, bool no_ui) {
    int rc;
    int tries;
    for (tries = 0; tries < 2; ++tries) {
        if (type == CRYPT_TYPE_DEFAULT) {
            rc = cryptfs_enable_default(arg2, no_ui);
        } else {
            rc = cryptfs_enable(arg2, type, arg4, no_ui);
        }

        if (rc == 0) {
            free(arg2);
            free(arg4);
            return 0;
        } else if (tries == 0) {
            Process::killProcessesWithOpenFiles(DATA_MNT_POINT, SIGKILL);
        }
    }

    free(arg2);
    free(arg4);
    return -1;
}

int CryptCommandListener::CryptfsCmd::runCommand(SocketClient *cli,
                                                 int argc, char **argv) {
    if ((cli->getUid() != 0) && (cli->getUid() != AID_SYSTEM)) {
        cli->sendMsg(ResponseCode::CommandNoPermission, "No permission to run cryptfs commands", false);
        return 0;
    }

    if (argc < 2) {
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Missing subcommand", false);
        return 0;
    }

    int rc = 0;

    std::string subcommand(argv[1]);
    if (subcommand == "checkpw") {
        if (!check_argc(cli, subcommand, argc, 3, "<passwd>")) return 0;
        dumpArgs(argc, argv, 2);
        rc = cryptfs_check_passwd(argv[2]);
    } else if (subcommand == "restart") {
        if (!check_argc(cli, subcommand, argc, 2, "")) return 0;
        dumpArgs(argc, argv, -1);

        // Spawn as thread so init can issue commands back to vold without
        // causing deadlock, usually as a result of prep_data_fs.
        std::thread(&cryptfs_restart).detach();
    } else if (subcommand == "cryptocomplete") {
        if (!check_argc(cli, subcommand, argc, 2, "")) return 0;
        dumpArgs(argc, argv, -1);
        rc = cryptfs_crypto_complete();
    } else if (subcommand == "enablecrypto") {
        const char* syntax = "Usage: cryptfs enablecrypto <wipe|inplace> "
                             "default|password|pin|pattern [passwd] [noui]";

        // This should be replaced with a command line parser if more options
        // are added
        bool valid = true;
        bool no_ui = false;
        int type = CRYPT_TYPE_DEFAULT;
        int options = 4; // Optional parameters are at this offset
        if (argc < 4) {
            // Minimum 4 parameters
            valid = false;
        } else if (strcmp(argv[2], "wipe") && strcmp(argv[2], "inplace") ) {
            // Second parameter must be wipe or inplace
            valid = false;
        } else {
            // Third parameter must be valid type
            type = getType(argv[3]);
            if (type == -1) {
                valid = false;
            } else if (type != CRYPT_TYPE_DEFAULT) {
                options++;
            }
        }

        if (valid) {
            if(argc < options) {
                // Too few parameters
                valid = false;
            } else if (argc == options) {
                // No more, done
            } else if (argc == options + 1) {
                // One option, must be noui
                if (!strcmp(argv[options], "noui")) {
                    no_ui = true;
                } else {
                    valid = false;
                }
            } else {
                // Too many options
                valid = false;
            }
        }

        if (!valid) {
            cli->sendMsg(ResponseCode::CommandSyntaxError, syntax, false);
            return 0;
        }

        dumpArgs(argc, argv, 4);

        // Spawn as thread so init can issue commands back to vold without
        // causing deadlock, usually as a result of prep_data_fs.
        char* arg2 = argc > 2 ? strdup(argv[2]) : NULL;
        char* arg4 = argc > 4 ? strdup(argv[4]) : NULL;
        std::thread(&do_enablecrypto, arg2, arg4, type, no_ui).detach();
    } else if (subcommand == "enablefilecrypto") {
        if (!check_argc(cli, subcommand, argc, 2, "")) return 0;
        dumpArgs(argc, argv, -1);
        rc = cryptfs_enable_file();
    } else if (subcommand == "changepw") {
        const char* syntax = "Usage: cryptfs changepw "
                             "default|password|pin|pattern [currentpasswd] "
                             "default|password|pin|pattern [newpasswd]";
        const char* password;
        const char* currentpassword;
        if (argc == 4) {
            currentpassword = "";
            password = "";
        } else if (argc == 5) {
            currentpassword = argv[3];
            password = argv[4];
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
        rc = cryptfs_changepw(type, currentpassword, password);
    } else if (subcommand == "verifypw") {
        if (!check_argc(cli, subcommand, argc, 3, "<passwd>")) return 0;
        SLOGD("cryptfs verifypw {}");
        rc = cryptfs_verify_passwd(argv[2]);
    } else if (subcommand == "getfield") {
        if (!check_argc(cli, subcommand, argc, 3, "<fieldname>")) return 0;
        char *valbuf;
        int valbuf_len = PROPERTY_VALUE_MAX;

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
    } else if (subcommand == "setfield") {
        if (!check_argc(cli, subcommand, argc, 4, "<fieldname> <value>")) return 0;
        dumpArgs(argc, argv, -1);
        rc = cryptfs_setfield(argv[2], argv[3]);
    } else if (subcommand == "mountdefaultencrypted") {
        if (!check_argc(cli, subcommand, argc, 2, "")) return 0;
        SLOGD("cryptfs mountdefaultencrypted");
        dumpArgs(argc, argv, -1);

        // Spawn as thread so init can issue commands back to vold without
        // causing deadlock, usually as a result of prep_data_fs.
        std::thread(&cryptfs_mount_default_encrypted).detach();
    } else if (subcommand == "getpwtype") {
        if (!check_argc(cli, subcommand, argc, 2, "")) return 0;
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
    } else if (subcommand == "getpw") {
        if (!check_argc(cli, subcommand, argc, 2, "")) return 0;
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
    } else if (subcommand == "clearpw") {
        if (!check_argc(cli, subcommand, argc, 2, "")) return 0;
        SLOGD("cryptfs clearpw");
        dumpArgs(argc, argv, -1);
        cryptfs_clear_password();
        rc = 0;

    } else if (subcommand == "isConvertibleToFBE") {
        if (!check_argc(cli, subcommand, argc, 2, "")) return 0;
        // ext4enc:TODO: send a CommandSyntaxError if argv[2] not an integer
        SLOGD("cryptfs isConvertibleToFBE");
        dumpArgs(argc, argv, -1);
        rc = cryptfs_isConvertibleToFBE();

    } else if (subcommand == "init_user0") {
        if (!check_argc(cli, subcommand, argc, 2, "")) return 0;
        return sendGenericOkFailOnBool(cli, e4crypt_init_user0());

    } else if (subcommand == "create_user_key") {
        if (!check_argc(cli, subcommand, argc, 5, "<user> <serial> <ephemeral>")) return 0;
        return sendGenericOkFailOnBool(cli, e4crypt_vold_create_user_key(
            atoi(argv[2]), atoi(argv[3]), atoi(argv[4]) != 0));

    } else if (subcommand == "destroy_user_key") {
        if (!check_argc(cli, subcommand, argc, 3, "<user>")) return 0;
        return sendGenericOkFailOnBool(cli, e4crypt_destroy_user_key(atoi(argv[2])));

    } else if (subcommand == "add_user_key_auth") {
        if (!check_argc(cli, subcommand, argc, 6, "<user> <serial> <token> <secret>")) return 0;
        return sendGenericOkFailOnBool(cli, e4crypt_add_user_key_auth(
            atoi(argv[2]), atoi(argv[3]), argv[4], argv[5]));

    } else if (subcommand == "fixate_newest_user_key_auth") {
        if (!check_argc(cli, subcommand, argc, 3, "<user>")) return 0;
        return sendGenericOkFailOnBool(cli, e4crypt_fixate_newest_user_key_auth(atoi(argv[2])));

    } else if (subcommand == "unlock_user_key") {
        if (!check_argc(cli, subcommand, argc, 6, "<user> <serial> <token> <secret>")) return 0;
        return sendGenericOkFailOnBool(cli, e4crypt_unlock_user_key(
            atoi(argv[2]), atoi(argv[3]), argv[4], argv[5]));

    } else if (subcommand == "lock_user_key") {
        if (!check_argc(cli, subcommand, argc, 3, "<user>")) return 0;
        return sendGenericOkFailOnBool(cli, e4crypt_lock_user_key(atoi(argv[2])));

    } else if (subcommand == "prepare_user_storage") {
        if (!check_argc(cli, subcommand, argc, 6, "<uuid> <user> <serial> <flags>")) return 0;
        return sendGenericOkFailOnBool(cli, e4crypt_prepare_user_storage(
            parseNull(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5])));

    } else if (subcommand == "destroy_user_storage") {
        if (!check_argc(cli, subcommand, argc, 5, "<uuid> <user> <flags>")) return 0;
        return sendGenericOkFailOnBool(cli,
                e4crypt_destroy_user_storage(parseNull(argv[2]), atoi(argv[3]), atoi(argv[4])));

    } else {
        dumpArgs(argc, argv, -1);
        cli->sendMsg(ResponseCode::CommandSyntaxError, "Unknown cryptfs subcommand", false);
        return 0;
    }

    // Always report that the command succeeded and return the error code.
    // The caller will check the return value to see what the error was.
    char msg[255];
    snprintf(msg, sizeof(msg), "%d", rc);
    cli->sendMsg(ResponseCode::CommandOkay, msg, false);

    return 0;
}
