LOCAL_PATH:= $(call my-dir)

common_src_files := \
	VolumeManager.cpp \
	CommandListener.cpp \
	VoldCommand.cpp \
	NetlinkManager.cpp \
	NetlinkHandler.cpp \
	Volume.cpp \
	DirectVolume.cpp \
	Process.cpp \
	Ext4.cpp \
	Fat.cpp \
	Ntfs.cpp \
	Loop.cpp \
	Devmapper.cpp \
	ResponseCode.cpp \
	Xwarp.cpp \
	VoldUtil.c \
	fstrim.c \
	cryptfs.c

common_c_includes := \
	$(KERNEL_HEADERS) \
	system/extras/ext4_utils \
	external/openssl/include \
	external/scrypt/lib/crypto \
	external/e2fsprogs/lib

common_shared_libraries := \
	libsysutils \
	libcutils \
	liblog \
	libdiskconfig \
	libhardware_legacy \
	liblogwrap \
	libext4_utils \
	libcrypto \
	libext2_blkid

common_static_libraries := \
	libfs_mgr \
	libscrypt_static \
	libmincrypt

include $(CLEAR_VARS)

ifneq ($(BOARD_VOLD_MAX_PARTITIONS),)
LOCAL_CFLAGS += -DVOLD_MAX_PARTITIONS=$(BOARD_VOLD_MAX_PARTITIONS)
endif

ifeq ($(BOARD_VOLD_EMMC_SHARES_DEV_MAJOR), true)
LOCAL_CFLAGS += -DVOLD_EMMC_SHARES_DEV_MAJOR
endif

ifeq ($(BOARD_VOLD_DISC_HAS_MULTIPLE_MAJORS), true)
LOCAL_CFLAGS += -DVOLD_DISC_HAS_MULTIPLE_MAJORS
endif

ifneq ($(TARGET_FUSE_SDCARD_UID),)
LOCAL_CFLAGS += -DFUSE_SDCARD_UID=$(TARGET_FUSE_SDCARD_UID)
endif

ifneq ($(TARGET_FUSE_SDCARD_GID),)
LOCAL_CFLAGS += -DFUSE_SDCARD_GID=$(TARGET_FUSE_SDCARD_GID)
endif

LOCAL_MODULE := libvold

LOCAL_SRC_FILES := $(common_src_files)

LOCAL_C_INCLUDES := $(common_c_includes)

LOCAL_SHARED_LIBRARIES := $(common_shared_libraries)

LOCAL_STATIC_LIBRARIES := $(common_static_libraries)

LOCAL_MODULE_TAGS := eng tests

include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)

LOCAL_MODULE:= vold

LOCAL_SRC_FILES := \
	main.cpp \
	$(common_src_files)

LOCAL_C_INCLUDES := $(common_c_includes)

LOCAL_CFLAGS := -Werror=format

ifneq ($(BOARD_VOLD_MAX_PARTITIONS),)
LOCAL_CFLAGS += -DVOLD_MAX_PARTITIONS=$(BOARD_VOLD_MAX_PARTITIONS)
endif

ifeq ($(BOARD_VOLD_EMMC_SHARES_DEV_MAJOR), true)
LOCAL_CFLAGS += -DVOLD_EMMC_SHARES_DEV_MAJOR
endif

ifeq ($(BOARD_VOLD_DISC_HAS_MULTIPLE_MAJORS), true)
LOCAL_CFLAGS += -DVOLD_DISC_HAS_MULTIPLE_MAJORS
endif

ifneq ($(TARGET_FUSE_SDCARD_UID),)
LOCAL_CFLAGS += -DFUSE_SDCARD_UID=$(TARGET_FUSE_SDCARD_UID)
endif

ifneq ($(TARGET_FUSE_SDCARD_GID),)
LOCAL_CFLAGS += -DFUSE_SDCARD_GID=$(TARGET_FUSE_SDCARD_GID)
endif

LOCAL_SHARED_LIBRARIES := $(common_shared_libraries)

LOCAL_STATIC_LIBRARIES := $(common_static_libraries)

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:= vdc.c

LOCAL_MODULE:= vdc

LOCAL_C_INCLUDES := $(KERNEL_HEADERS)

LOCAL_CFLAGS := 

LOCAL_SHARED_LIBRARIES := libcutils

include $(BUILD_EXECUTABLE)
