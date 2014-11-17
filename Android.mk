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
	Exfat.cpp \
	Loop.cpp \
	Devmapper.cpp \
	ResponseCode.cpp \
	CheckBattery.cpp \
	VoldUtil.c \
	fstrim.c \
	cryptfs.c

common_c_includes := \
	system/extras/ext4_utils \
	system/extras/f2fs_utils \
	external/openssl/include \
	external/stlport/stlport \
	bionic \
	external/scrypt/lib/crypto \
	frameworks/native/include \
	system/security/keystore \
	hardware/libhardware/include/hardware \
	system/security/softkeymaster/include/keymaster \
	external/e2fsprogs/lib

common_libraries := \
	libsysutils \
	libbinder \
	libcutils \
	liblog \
	libdiskconfig \
	liblogwrap \
	libf2fs_sparseblock \
	libselinux \
	libutils \

common_shared_libraries := \
	$(common_libraries) \
	libhardware_legacy \
	libcrypto \
	libhardware \
	libstlport \
	libsoftkeymaster \
	libext2_blkid

common_static_libraries := \
	libfs_mgr \
	libext4_utils_static \
	libscrypt_static \
	libminshacrypt \
	libbatteryservice

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

ifeq ($(TARGET_HW_DISK_ENCRYPTION),true)
LOCAL_C_INCLUDES += device/qcom/common/cryptfs_hw
common_shared_libraries += libcryptfs_hw
LOCAL_CFLAGS += -DCONFIG_HW_DISK_ENCRYPTION
endif

ifneq ($(BOARD_VOLD_MAX_PARTITIONS),)
LOCAL_CFLAGS += -DVOLD_MAX_PARTITIONS=$(BOARD_VOLD_MAX_PARTITIONS)
endif

ifeq ($(BOARD_VOLD_DISC_HAS_MULTIPLE_MAJORS), true)
LOCAL_CFLAGS += -DVOLD_DISC_HAS_MULTIPLE_MAJORS
endif

ifeq ($(BOARD_VOLD_EMMC_SHARES_DEV_MAJOR), true)
LOCAL_CFLAGS += -DVOLD_EMMC_SHARES_DEV_MAJOR
endif

LOCAL_SHARED_LIBRARIES := $(common_shared_libraries)

LOCAL_STATIC_LIBRARIES := $(common_static_libraries)

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:= vdc.c

LOCAL_MODULE:= vdc

LOCAL_C_INCLUDES :=

LOCAL_CFLAGS := 

LOCAL_SHARED_LIBRARIES := libcutils

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE:= libminivold
LOCAL_SRC_FILES := $(common_src_files)
LOCAL_C_INCLUDES := $(common_c_includes) system/core/fs_mgr/include system/core/logwrapper/include
LOCAL_CFLAGS := $(common_cflags) -DMINIVOLD -DHELPER_PATH=\"/sbin/\"
LOCAL_MODULE_TAGS := optional
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE:= minivold
LOCAL_SRC_FILES := main.cpp
LOCAL_C_INCLUDES := $(common_c_includes)
LOCAL_CFLAGS := $(common_cflags) -DMINIVOLD
LOCAL_STATIC_LIBRARIES := libminivold
LOCAL_STATIC_LIBRARIES += libc libstdc++ libstlport_static
LOCAL_STATIC_LIBRARIES += $(common_static_libraries) $(common_libraries)
LOCAL_STATIC_LIBRARIES += libcrypto_static libext2_uuid libvold
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_CLASS := RECOVERY_EXECUTABLES
LOCAL_MODULE_PATH := $(TARGET_RECOVERY_ROOT_OUT)/sbin
LOCAL_MODULE_TAGS := optional
include $(BUILD_EXECUTABLE)
