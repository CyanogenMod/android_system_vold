/*
 * Copyright (C) 2010 The Android Open Source Project
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

/* TO DO:
 *   1.  Perhaps keep several copies of the encrypted key, in case something
 *       goes horribly wrong?
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <linux/dm-ioctl.h>
#include <libgen.h>
#include <stdlib.h>
#include <sys/param.h>
#include <string.h>
#include <sys/mount.h>
#include <openssl/evp.h>
#include <errno.h>
#include <sys/reboot.h>
#include "cryptfs.h"
#define LOG_TAG "Cryptfs"
#include "cutils/log.h"
#include "cutils/properties.h"

#define DM_CRYPT_BUF_SIZE 4096

char *me = "cryptfs";

static void ioctl_init(struct dm_ioctl *io, size_t dataSize, const char *name, unsigned flags)
{
    memset(io, 0, dataSize);
    io->data_size = dataSize;
    io->data_start = sizeof(struct dm_ioctl);
    io->version[0] = 4;
    io->version[1] = 0;
    io->version[2] = 0;
    io->flags = flags;
    if (name) {
        strncpy(io->name, name, sizeof(io->name));
    }
}

static unsigned int get_blkdev_size(int fd)
{
  unsigned int nr_sec;

  if ( (ioctl(fd, BLKGETSIZE, &nr_sec)) == -1) {
    nr_sec = 0;
  }

  return nr_sec;
}

/* key can be NULL, in which case just write out the footer.  Useful to
 * update the failed mount count but not change the key.
 */
static int put_crypt_ftr_and_key(char *real_blk_name, struct crypt_mnt_ftr *crypt_ftr,
                                  unsigned char *key)
{
  int fd;
  unsigned int nr_sec, cnt;
  off64_t off;
  int rc = -1;

  if ( (fd = open(real_blk_name, O_RDWR)) < 0) {
    SLOGE("Cannot open real block device %s\n", real_blk_name);
    return -1;
  }

  if ( (nr_sec = get_blkdev_size(fd)) == 0) {
    SLOGE("Cannot get size of block device %s\n", real_blk_name);
    goto errout;
  }

  /* If it's an encrypted Android partition, the last 16 Kbytes contain the
   * encryption info footer and key, and plenty of bytes to spare for future
   * growth.
   */
  off = ((off64_t)nr_sec * 512) - CRYPT_FOOTER_OFFSET;

  if (lseek64(fd, off, SEEK_SET) == -1) {
    SLOGE("Cannot seek to real block device footer\n");
    goto errout;
  }

  if ((cnt = write(fd, crypt_ftr, sizeof(struct crypt_mnt_ftr))) != sizeof(struct crypt_mnt_ftr)) {
    SLOGE("Cannot write real block device footer\n");
    goto errout;
  }

  if (key) {
    if (crypt_ftr->keysize != 16) {
      SLOGE("Keysize of %d bits not supported for real block device %s\n",
            crypt_ftr->keysize * 8, real_blk_name);
      goto errout; 
    }

    if ( (cnt = write(fd, key, crypt_ftr->keysize)) != crypt_ftr->keysize) {
      SLOGE("Cannot write key for real block device %s\n", real_blk_name);
      goto errout;
    }
  }

  /* Success! */
  rc = 0;

errout:
  close(fd);
  return rc;

}

static int get_crypt_ftr_and_key(char *real_blk_name, struct crypt_mnt_ftr *crypt_ftr,
                                  unsigned char *key)
{
  int fd;
  unsigned int nr_sec, cnt;
  off64_t off;
  int rc = -1;

  if ( (fd = open(real_blk_name, O_RDWR)) < 0) {
    SLOGE("Cannot open real block device %s\n", real_blk_name);
    return -1;
  }

  if ( (nr_sec = get_blkdev_size(fd)) == 0) {
    SLOGE("Cannot get size of block device %s\n", real_blk_name);
    goto errout;
  }

  /* If it's an encrypted Android partition, the last 16 Kbytes contain the
   * encryption info footer and key, and plenty of bytes to spare for future
   * growth.
   */
#if 1 /* The real location, use when the enable code works */
  off = ((off64_t)nr_sec * 512) - CRYPT_FOOTER_OFFSET;
#else
  /* For testing, I'm slapping a handbuild header after my 200 megabyte
   * /data partition.  So my offset if 200 megabytes */
  off = 200*1024*1024;
#endif

  if (lseek64(fd, off, SEEK_SET) == -1) {
    SLOGE("Cannot seek to real block device footer\n");
    goto errout;
  }

  if ( (cnt = read(fd, crypt_ftr, sizeof(struct crypt_mnt_ftr))) != sizeof(struct crypt_mnt_ftr)) {
    SLOGE("Cannot read real block device footer\n");
    goto errout;
  }

  if (crypt_ftr->magic != CRYPT_MNT_MAGIC) {
    SLOGE("Bad magic for real block device %s\n", real_blk_name);
    goto errout;
  }

  if (crypt_ftr->major_version != 1) {
    SLOGE("Cannot understand major version %d real block device footer\n",
          crypt_ftr->major_version);
    goto errout;
  }

  if (crypt_ftr->minor_version != 0) {
    SLOGW("Warning: crypto footer minor version %d, expected 0, continuing...\n",
          crypt_ftr->minor_version);
  }

  if (crypt_ftr->ftr_size > sizeof(struct crypt_mnt_ftr)) {
    /* the footer size is bigger than we expected.
     * Skip to it's stated end so we can read the key.
     */
    if (lseek(fd, crypt_ftr->ftr_size - sizeof(struct crypt_mnt_ftr),  SEEK_CUR) == -1) {
      SLOGE("Cannot seek to start of key\n");
      goto errout;
    }
  }

  if (crypt_ftr->keysize != 16) {
    SLOGE("Keysize of %d bits not supported for real block device %s\n",
          crypt_ftr->keysize * 8, real_blk_name);
    goto errout;
  }

  if ( (cnt = read(fd, key, crypt_ftr->keysize)) != crypt_ftr->keysize) {
    SLOGE("Cannot read key for real block device %s\n", real_blk_name);
    goto errout;
  }

  /* Success! */
  rc = 0;

errout:
  close(fd);
  return rc;
}

/* Convert a binary key of specified length into an ascii hex string equivalent,
 * without the leading 0x and with null termination
 */
void convert_key_to_hex_ascii(unsigned char *master_key, unsigned int keysize,
                              char *master_key_ascii)
{
  unsigned int i, a;
  unsigned char nibble;

  for (i=0, a=0; i<keysize; i++, a+=2) {
    /* For each byte, write out two ascii hex digits */
    nibble = (master_key[i] >> 4) & 0xf;
    master_key_ascii[a] = nibble + (nibble > 9 ? 0x37 : 0x30);

    nibble = master_key[i] & 0xf;
    master_key_ascii[a+1] = nibble + (nibble > 9 ? 0x37 : 0x30);
  }

  /* Add the null termination */
  master_key_ascii[a] = '\0';

}

static int create_crypto_blk_dev(struct crypt_mnt_ftr *crypt_ftr, unsigned char *master_key,
                                    char *real_blk_name, char *crypto_blk_name)
{
  char buffer[DM_CRYPT_BUF_SIZE];
  char master_key_ascii[129]; /* Large enough to hold 512 bit key and null */
  char *crypt_params;
  struct dm_ioctl *io;
  struct dm_target_spec *tgt;
  unsigned int minor;
  int fd;
  int retval = -1;
  char *name ="datadev"; /* FIX ME: Make me a parameter */

  if ((fd = open("/dev/device-mapper", O_RDWR)) < 0 ) {
    SLOGE("Cannot open device-mapper\n");
    goto errout;
  }

  io = (struct dm_ioctl *) buffer;

  ioctl_init(io, DM_CRYPT_BUF_SIZE, name, 0);
  if (ioctl(fd, DM_DEV_CREATE, io)) {
    SLOGE("Cannot create dm-crypt device\n");
    goto errout;
  }

  /* Get the device status, in particular, the name of it's device file */
  ioctl_init(io, DM_CRYPT_BUF_SIZE, name, 0);
  if (ioctl(fd, DM_DEV_STATUS, io)) {
    SLOGE("Cannot retrieve dm-crypt device status\n");
    goto errout;
  }
  minor = (io->dev & 0xff) | ((io->dev >> 12) & 0xfff00);
  snprintf(crypto_blk_name, MAXPATHLEN, "/dev/block/dm-%u", minor);

  /* Load the mapping table for this device */
  tgt = (struct dm_target_spec *) &buffer[sizeof(struct dm_ioctl)];

  ioctl_init(io, 4096, name, 0);
  io->target_count = 1;
  tgt->status = 0;
  tgt->sector_start = 0;
  tgt->length = crypt_ftr->fs_size;
  strcpy(tgt->target_type, "crypt");

  crypt_params = buffer + sizeof(struct dm_ioctl) + sizeof(struct dm_target_spec);
  convert_key_to_hex_ascii(master_key, crypt_ftr->keysize, master_key_ascii);
  sprintf(crypt_params, "%s %s 0 %s 0", crypt_ftr->crypto_type_name,
          master_key_ascii, real_blk_name);
  //SLOGD("crypt_params = %s\n", crypt_params);  // Only for debugging, prints the master key!
  crypt_params += strlen(crypt_params) + 1;
  crypt_params = (char *) (((unsigned long)crypt_params + 7) & ~8); /* Align to an 8 byte boundary */
  tgt->next = crypt_params - buffer;

  if (ioctl(fd, DM_TABLE_LOAD, io)) {
      SLOGE("Cannot load dm-crypt mapping table.\n");
      goto errout;
  }

  /* Resume this device to activate it */
  ioctl_init(io, 4096, name, 0);

  if (ioctl(fd, DM_DEV_SUSPEND, io)) {
    SLOGE("Cannot resume the dm-crypt device\n");
    goto errout;
  }

  /* We made it here with no errors.  Woot! */
  retval = 0;

errout:
  close(fd);   /* If fd is <0 from a failed open call, it's safe to just ignore the close error */

  return retval;
}

static int delete_crypto_blk_dev(char *crypto_blkdev)
{
  int fd;
  char buffer[DM_CRYPT_BUF_SIZE];
  struct dm_ioctl *io;
  char *name ="datadev"; /* FIX ME: Make me a paraameter */
  int retval = -1;

  if ((fd = open("/dev/device-mapper", O_RDWR)) < 0 ) {
    SLOGE("Cannot open device-mapper\n");
    goto errout;
  }

  io = (struct dm_ioctl *) buffer;

  ioctl_init(io, DM_CRYPT_BUF_SIZE, name, 0);
  if (ioctl(fd, DM_DEV_REMOVE, io)) {
    SLOGE("Cannot remove dm-crypt device\n");
    goto errout;
  }

  /* We made it here with no errors.  Woot! */
  retval = 0;

errout:
  close(fd);    /* If fd is <0 from a failed open call, it's safe to just ignore the close error */

  return retval;

}

/* If we need to debug this, look at Devmapper.cpp:dumpState(),
 * It does DM_LIST_DEVICES, then iterates on each device and
 * calls DM_DEV_STATUS.
 */

#define HASH_COUNT 2000
#define KEY_LEN_BYTES 16
#define IV_LEN_BYTES 16

static int create_encrypted_random_key(char *passwd, unsigned char *master_key)
{
    int fd;
    unsigned char buf[KEY_LEN_BYTES];
    unsigned char ikey[32+32] = { 0 }; /* Big enough to hold a 256 bit key and 256 bit IV */
    unsigned char salt[32] = { 0 };
    EVP_CIPHER_CTX e_ctx;
    int encrypted_len, final_len;

    /* Get some random bits for a key */
    fd = open("/dev/urandom", O_RDONLY);
    read(fd, buf, sizeof(buf));
    close(fd);

    /* Now encrypt it with the password */
    /* To Do: Make a salt based on some immutable data about this device.
     * IMEI, or MEID, or CPU serial number, or whatever we can find
     */
    /* Turn the password into a key and IV that can decrypt the master key */
    PKCS5_PBKDF2_HMAC_SHA1(passwd, strlen(passwd), salt, sizeof(salt),
                           HASH_COUNT, KEY_LEN_BYTES+IV_LEN_BYTES, ikey);
  
    /* Initialize the decryption engine */
    if (! EVP_EncryptInit(&e_ctx, EVP_aes_128_cbc(), ikey, ikey+KEY_LEN_BYTES)) {
        SLOGE("EVP_EncryptInit failed\n");
        return -1;
    }
    EVP_CIPHER_CTX_set_padding(&e_ctx, 0); /* Turn off padding as our data is block aligned */
    /* Encrypt the master key */
    if (! EVP_EncryptUpdate(&e_ctx, master_key, &encrypted_len,
                              buf, KEY_LEN_BYTES)) {
        SLOGE("EVP_EncryptUpdate failed\n");
        return -1;
    }
    if (! EVP_EncryptFinal(&e_ctx, master_key + encrypted_len, &final_len)) {
        SLOGE("EVP_EncryptFinal failed\n");
        return -1;
    }

    if (encrypted_len + final_len != KEY_LEN_BYTES) {
        SLOGE("EVP_Encryption length check failed with %d, %d bytes\n", encrypted_len, final_len);
        return -1;
    } else {
        return 0;
    }
}

static int decrypt_master_key(char *passwd, unsigned char *encrypted_master_key,
                              unsigned char *decrypted_master_key)
{
  unsigned char ikey[32+32] = { 0 }; /* Big enough to hold a 256 bit key and 256 bit IV */
  unsigned char salt[32] = { 0 };
  EVP_CIPHER_CTX d_ctx;
  int decrypted_len, final_len;

  /* To Do: Make a salt based on some immutable data about this device.
   * IMEI, or MEID, or CPU serial number, or whatever we can find
   */
  /* Turn the password into a key and IV that can decrypt the master key */
  PKCS5_PBKDF2_HMAC_SHA1(passwd, strlen(passwd), salt, sizeof(salt),
                         HASH_COUNT, KEY_LEN_BYTES+IV_LEN_BYTES, ikey);

  /* Initialize the decryption engine */
  if (! EVP_DecryptInit(&d_ctx, EVP_aes_128_cbc(), ikey, ikey+KEY_LEN_BYTES)) {
    return -1;
  }
  EVP_CIPHER_CTX_set_padding(&d_ctx, 0); /* Turn off padding as our data is block aligned */
  /* Decrypt the master key */
  if (! EVP_DecryptUpdate(&d_ctx, decrypted_master_key, &decrypted_len,
                            encrypted_master_key, KEY_LEN_BYTES)) {
    return -1;
  }
  if (! EVP_DecryptFinal(&d_ctx, decrypted_master_key + decrypted_len, &final_len)) {
    return -1;
  }

  if (decrypted_len + final_len != KEY_LEN_BYTES) {
    return -1;
  } else {
    return 0;
  }
}

static int get_orig_mount_parms(char *mount_point, char *fs_type, char *real_blkdev,
                                unsigned long *mnt_flags, char *fs_options)
{
  char mount_point2[32];
  char fs_flags[32];

  property_get("ro.crypto.fs_type", fs_type, "");
  property_get("ro.crypto.fs_real_blkdev", real_blkdev, "");
  property_get("ro.crypto.fs_mnt_point", mount_point2, "");
  property_get("ro.crypto.fs_options", fs_options, "");
  property_get("ro.crypto.fs_flags", fs_flags, "");
  *mnt_flags = strtol(fs_flags, 0, 0);

  if (strcmp(mount_point, mount_point2)) {
    /* Consistency check.  These should match. If not, something odd happened. */
    return -1;
  }

  return 0;
}

static int wait_and_unmount(char *mountpoint)
{
    int i, rc;
#define WAIT_UNMOUNT_COUNT 20

    /*  Now umount the tmpfs filesystem */
    for (i=0; i<WAIT_UNMOUNT_COUNT; i++) {
        if (umount(mountpoint)) {
            sleep(1);
            i++;
        } else {
          break;
        }
    }

    if (i < WAIT_UNMOUNT_COUNT) {
      SLOGD("unmounting %s succeeded\n", mountpoint);
      rc = 0;
    } else {
      SLOGE("unmounting %s failed\n", mountpoint);
      rc = -1;
    }

    return rc;
}

int cryptfs_restart(void)
{
    char fs_type[32];
    char real_blkdev[MAXPATHLEN];
    char crypto_blkdev[MAXPATHLEN];
    char fs_options[256];
    unsigned long mnt_flags;
    struct stat statbuf;
    int rc = -1, i;
#define DATA_PREP_TIMEOUT 100

    /* Here is where we shut down the framework.  The init scripts
     * start all services in one of three classes: core, main or late_start.
     * On boot, we start core and main.  Now, we stop main, but not core,
     * as core includes vold and a few other really important things that
     * we need to keep running.  Once main has stopped, we should be able
     * to umount the tmpfs /data, then mount the encrypted /data.
     * We then restart the class main, and also the class late_start.
     * At the moment, I've only put a few things in late_start that I know
     * are not needed to bring up the framework, and that also cause problems
     * with unmounting the tmpfs /data, but I hope to add add more services
     * to the late_start class as we optimize this to decrease the delay
     * till the user is asked for the password to the filesystem.
     */

    /* The init files are setup to stop the class main when vold.decrypt is
     * set to trigger_reset_main.
     */
    property_set("vold.decrypt", "trigger_reset_main");
    SLOGD("Just asked init to shut down class main\n");

    /* Now that the framework is shutdown, we should be able to umount()
     * the tmpfs filesystem, and mount the real one.
     */

    property_get("ro.crypto.fs_crypto_blkdev", crypto_blkdev, "");
    if (strlen(crypto_blkdev) == 0) {
        SLOGE("fs_crypto_blkdev not set\n");
        return -1;
    }

    if (! get_orig_mount_parms("/data", fs_type, real_blkdev, &mnt_flags, fs_options)) {
        SLOGD("Just got orig mount parms\n");

        if (! (rc = wait_and_unmount("/data")) ) {
            /* If that succeeded, then mount the decrypted filesystem */
            mount(crypto_blkdev, "/data", fs_type, mnt_flags, fs_options);

            /* Do the prep of the /data filesystem */
            property_set("vold.post_fs_data_done", "0");
            property_set("vold.decrypt", "trigger_post_fs_data");
            SLOGD("Just triggered post_fs_data\n");

            /* Wait a max of 25 seconds, hopefully it takes much less */
            for (i=0; i<DATA_PREP_TIMEOUT; i++) {
                char p[16];;

                property_get("vold.post_fs_data_done", p, "0");
                if (*p == '1') {
                    break;
                } else {
                    usleep(250000);
                }
            }
            if (i == DATA_PREP_TIMEOUT) {
                /* Ugh, we failed to prep /data in time.  Bail. */
                return -1;
            }

            /* startup service classes main and late_start */
            property_set("vold.decrypt", "trigger_restart_framework");
            SLOGD("Just triggered restart_framework\n");

            /* Give it a few moments to get started */
            sleep(1);
        }
    }

    return rc;
}

static int test_mount_encrypted_fs(char *passwd, char *mount_point)
{
  struct crypt_mnt_ftr crypt_ftr;
  /* Allocate enough space for a 256 bit key, but we may use less */
  unsigned char encrypted_master_key[32], decrypted_master_key[32];
  char crypto_blkdev[MAXPATHLEN];
  char real_blkdev[MAXPATHLEN];
  char fs_type[32];
  char fs_options[256];
  char tmp_mount_point[64];
  unsigned long mnt_flags;
  unsigned int orig_failed_decrypt_count;
  int rc;

  if (get_orig_mount_parms(mount_point, fs_type, real_blkdev, &mnt_flags, fs_options)) {
    SLOGE("Error reading original mount parms for mount point %s\n", mount_point);
    return -1;
  }

  if (get_crypt_ftr_and_key(real_blkdev, &crypt_ftr, encrypted_master_key)) {
    SLOGE("Error getting crypt footer and key\n");
    return -1;
  }
  SLOGD("crypt_ftr->fs_size = %lld\n", crypt_ftr.fs_size);
  orig_failed_decrypt_count = crypt_ftr.failed_decrypt_count;

  if (! (crypt_ftr.flags & CRYPT_MNT_KEY_UNENCRYPTED) ) {
    decrypt_master_key(passwd, encrypted_master_key, decrypted_master_key);
  }

  if (create_crypto_blk_dev(&crypt_ftr, decrypted_master_key,
                               real_blkdev, crypto_blkdev)) {
    SLOGE("Error creating decrypted block device\n");
    return -1;
  }

  /* If init detects an encrypted filesystme, it writes a file for each such
   * encrypted fs into the tmpfs /data filesystem, and then the framework finds those
   * files and passes that data to me */
  /* Create a tmp mount point to try mounting the decryptd fs
   * Since we're here, the mount_point should be a tmpfs filesystem, so make
   * a directory in it to test mount the decrypted filesystem.
   */
  sprintf(tmp_mount_point, "%s/tmp_mnt", mount_point);
  mkdir(tmp_mount_point, 0755);
  if ( mount(crypto_blkdev, tmp_mount_point, "ext4", MS_RDONLY, "") ) {
    SLOGE("Error temp mounting decrypted block device\n");
    delete_crypto_blk_dev(crypto_blkdev);
    crypt_ftr.failed_decrypt_count++;
  } else {
    /* Success, so just umount and we'll mount it properly when we restart
     * the framework.
     */
    umount(tmp_mount_point);
    crypt_ftr.failed_decrypt_count  = 0;
  }

  if (orig_failed_decrypt_count != crypt_ftr.failed_decrypt_count) {
    put_crypt_ftr_and_key(real_blkdev, &crypt_ftr, 0);
  }

  if (crypt_ftr.failed_decrypt_count) {
    /* We failed to mount the device, so return an error */
    rc = crypt_ftr.failed_decrypt_count;

  } else {
    /* Woot!  Success!  Save the name of the crypto block device
     * so we can mount it when restarting the framework.
     */
    property_set("ro.crypto.fs_crypto_blkdev", crypto_blkdev);
    rc = 0;
  }

  return rc;
}

int cryptfs_check_passwd(char *passwd)
{
    int rc = -1;

    rc = test_mount_encrypted_fs(passwd, "/data");

    return rc;
}

/* Initialize a crypt_mnt_ftr structure.  The keysize is
 * defaulted to 16 bytes, and the filesystem size to 0.
 * Presumably, at a minimum, the caller will update the
 * filesystem size and crypto_type_name after calling this function.
 */
static void cryptfs_init_crypt_mnt_ftr(struct crypt_mnt_ftr *ftr)
{
    ftr->magic = CRYPT_MNT_MAGIC;
    ftr->major_version = 1;
    ftr->minor_version = 0;
    ftr->ftr_size = sizeof(struct crypt_mnt_ftr);
    ftr->flags = 0;
    ftr->keysize = 16;
    ftr->spare1 = 0;
    ftr->fs_size = 0;
    ftr->failed_decrypt_count = 0;
    ftr->crypto_type_name[0] = '\0';
}

static int cryptfs_enable_wipe(char *crypto_blkdev, off64_t size)
{
    char cmdline[256];
    int rc = -1;

    snprintf(cmdline, sizeof(cmdline), "/system/bin/make_ext4fs -a /data -l %lld %s",
             size * 512, crypto_blkdev);
    SLOGI("Making empty filesystem with command %s\n", cmdline);
    if (system(cmdline)) {
      SLOGE("Error creating empty filesystem on %s\n", crypto_blkdev);
    } else {
      SLOGD("Successfully created empty filesystem on %s\n", crypto_blkdev);
      rc = 0;
    }

    return rc;
}

static inline int unix_read(int  fd, void*  buff, int  len)
{
    int  ret;
    do { ret = read(fd, buff, len); } while (ret < 0 && errno == EINTR);
    return ret;
}

static inline int unix_write(int  fd, const void*  buff, int  len)
{
    int  ret;
    do { ret = write(fd, buff, len); } while (ret < 0 && errno == EINTR);
    return ret;
}

#define CRYPT_INPLACE_BUFSIZE 4096
#define CRYPT_SECTORS_PER_BUFSIZE (CRYPT_INPLACE_BUFSIZE / 512)
static int cryptfs_enable_inplace(char *crypto_blkdev, char *real_blkdev, off64_t size)
{
    int realfd, cryptofd;
    char *buf[CRYPT_INPLACE_BUFSIZE];
    int rc = -1;
    off64_t numblocks, i, remainder;
   
    if ( (realfd = open(real_blkdev, O_RDONLY)) < 0) { 
        SLOGE("Error opening real_blkdev %s for inplace encrypt\n", real_blkdev);
        return -1;
    }

    if ( (cryptofd = open(crypto_blkdev, O_WRONLY)) < 0) { 
        SLOGE("Error opening crypto_blkdev %s for inplace encrypt\n", crypto_blkdev);
        close(realfd);
        return -1;
    }

    /* This is pretty much a simple loop of reading 4K, and writing 4K.
     * The size passed in is the number of 512 byte sectors in the filesystem.
     * So compute the number of whole 4K blocks we should read/write,
     * and the remainder.
     */
    numblocks = size / CRYPT_SECTORS_PER_BUFSIZE;
    remainder = size % CRYPT_SECTORS_PER_BUFSIZE;

    SLOGE("Encrypting filesystem in place...");

    /* process the majority of the filesystem in blocks */
    for (i=0; i<numblocks; i++) {
        if ( ! (i % 65536)) { //KEN
            SLOGE("|"); //KEN
        } //KEN
        if (unix_read(realfd, buf, CRYPT_INPLACE_BUFSIZE) <= 0) {
            SLOGE("Error reading real_blkdev %s for inplace encrypt\n", crypto_blkdev);
            goto errout;
        }
        if (unix_write(cryptofd, buf, CRYPT_INPLACE_BUFSIZE) <= 0) {
            SLOGE("Error writing crypto_blkdev %s for inplace encrypt\n", crypto_blkdev);
            goto errout;
        }
    }

    /* Do any remaining sectors */
    for (i=0; i<remainder; i++) {
        if (unix_read(realfd, buf, 512) <= 0) {
            SLOGE("Error reading rival sectors from real_blkdev %s for inplace encrypt\n", crypto_blkdev);
            goto errout;
        }
        if (unix_write(cryptofd, buf, 512) <= 0) {
            SLOGE("Error writing final sectors to crypto_blkdev %s for inplace encrypt\n", crypto_blkdev);
            goto errout;
        }
    }

    rc = 0;

errout:
    close(realfd);
    close(cryptofd);

    return rc;
}

#define CRYPTO_ENABLE_WIPE 1
#define CRYPTO_ENABLE_INPLACE 2
int cryptfs_enable(char *howarg, char *passwd)
{
    int how = 0;
    char crypto_blkdev[MAXPATHLEN], real_blkdev[MAXPATHLEN];
    char fs_type[32], fs_options[256], mount_point[32];
    unsigned long mnt_flags, nr_sec;
    unsigned char master_key[16], decrypted_master_key[16];
    int rc, fd;
    struct crypt_mnt_ftr crypt_ftr;

    if (!strcmp(howarg, "wipe")) {
      how = CRYPTO_ENABLE_WIPE;
    } else if (! strcmp(howarg, "inplace")) {
      how = CRYPTO_ENABLE_INPLACE;
    } else {
      /* Shouldn't happen, as CommandListener vets the args */
      return -1;
    }

    get_orig_mount_parms(mount_point, fs_type, real_blkdev, &mnt_flags, fs_options);

    /* The init files are setup to stop the class main and late start when
     * set to 4.  They also unmount the fuse filesystem /mnt/sdcard on stingray.
     */
    property_set("vold.decrypt", "trigger_shutdown_framework");
    SLOGD("Just asked init to shut down class main\n");

    if (wait_and_unmount("/mnt/sdcard")) {
        return -1;
    }

    /* Now unmount the /data partition. */
    if (! (rc = wait_and_unmount("/data")) ) {
        /* OK, we've unmounted /data, time to setup an encrypted
         * mapping, and either write a new filesystem or encrypt
         * in place.
         */

        fd = open(real_blkdev, O_RDONLY);
        if ( (nr_sec = get_blkdev_size(fd)) == 0) {
            SLOGE("Cannot get size of block device %s\n", real_blkdev);
            return -1;
        }
        close(fd);

        /* Initialize a crypt_mnt_ftr for the partition */
        cryptfs_init_crypt_mnt_ftr(&crypt_ftr);
        crypt_ftr.fs_size = nr_sec - (CRYPT_FOOTER_OFFSET / 512);
        strcpy((char *)crypt_ftr.crypto_type_name, "aes-cbc-essiv:sha256");

        /* Make an encrypted master key */
        if (create_encrypted_random_key(passwd, master_key)) {
            SLOGE("Cannot create encrypted master key\n");
            return -1;
        }

        /* Write the key to the end of the partition */
        put_crypt_ftr_and_key(real_blkdev, &crypt_ftr, master_key);

        decrypt_master_key(passwd, master_key, decrypted_master_key);
        create_crypto_blk_dev(&crypt_ftr, decrypted_master_key, real_blkdev, crypto_blkdev);

        if (how == CRYPTO_ENABLE_WIPE) {
            rc = cryptfs_enable_wipe(crypto_blkdev, crypt_ftr.fs_size);
        } else if (how == CRYPTO_ENABLE_INPLACE) {
            rc = cryptfs_enable_inplace(crypto_blkdev, real_blkdev, crypt_ftr.fs_size);
        } else {
            /* Shouldn't happen */
            SLOGE("cryptfs_enable: internal error, unknown option\n");
            return -1;
        }

        if (! rc) {
            delete_crypto_blk_dev(crypto_blkdev);
            sync();
            reboot(LINUX_REBOOT_CMD_RESTART);
        }
    } else {
        return -1;
    }

    return 0;
}

