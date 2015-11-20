LOCAL_PATH:= $(call my-dir)

common_src_files := \
	VolumeManager.cpp \
	CommandListener.cpp \
	CryptCommandListener.cpp \
	VoldCommand.cpp \
	NetlinkManager.cpp \
	NetlinkHandler.cpp \
	Process.cpp \
	fs/Exfat.cpp \
	fs/Ext4.cpp \
	fs/F2fs.cpp \
	fs/Ntfs.cpp \
	fs/Vfat.cpp \
	Loop.cpp \
	Devmapper.cpp \
	ResponseCode.cpp \
	CheckBattery.cpp \
	Ext4Crypt.cpp \
	VoldUtil.c \
	cryptfs.c \
	Disk.cpp \
	DiskPartition.cpp \
	VolumeBase.cpp \
	PublicVolume.cpp \
	PrivateVolume.cpp \
	EmulatedVolume.cpp \
	Utils.cpp \
	MoveTask.cpp \
	Benchmark.cpp \
	TrimTask.cpp \
	main.cpp

common_c_includes := \
	system/extras/ext4_utils \
	system/extras/f2fs_utils \
	external/scrypt/lib/crypto \
	frameworks/native/include \
	system/security/keystore \
	hardware/libhardware/include/hardware \
	system/security/softkeymaster/include/keymaster

common_libraries := \
	libsysutils \
	libbinder \
	libcutils \
	liblog \
	libdiskconfig \
	liblogwrap \
	libf2fs_sparseblock \
	libselinux \
	libutils

common_shared_libraries := \
	$(common_libraries) \
	libhardware_legacy \
	libext4_utils \
	libcrypto \
	libhardware \
	libsoftkeymaster \
	libbase \
	libext2_blkid

common_static_libraries := \
	libfs_mgr \
	libext4_utils_static \
	libsparse_static \
	libsquashfs_utils \
	libscrypt_static \
	libmincrypt \
	libbatteryservice \
	libext2_blkid \
	libext2_uuid_static \
	libz

vold_conlyflags := -std=c11
vold_cflags := -Werror -Wall -Wno-missing-field-initializers -Wno-unused-variable -Wno-unused-parameter

include $(CLEAR_VARS)

LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_MODULE := libvold
LOCAL_CLANG := true
LOCAL_SRC_FILES := $(common_src_files)
LOCAL_C_INCLUDES := $(common_c_includes)
LOCAL_SHARED_LIBRARIES := $(common_shared_libraries)
LOCAL_STATIC_LIBRARIES := $(common_static_libraries)
LOCAL_MODULE_TAGS := eng tests
LOCAL_CFLAGS := $(vold_cflags)
LOCAL_CONLYFLAGS := $(vold_conlyflags)

include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)

LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_MODULE:= vold
LOCAL_CLANG := true
LOCAL_SRC_FILES := \
	vold.c

LOCAL_C_INCLUDES := $(common_c_includes)
LOCAL_CFLAGS := $(vold_cflags)
LOCAL_CONLYFLAGS := $(vold_conlyflags)

ifeq ($(TARGET_HW_DISK_ENCRYPTION),true)
TARGET_CRYPTFS_HW_PATH ?= device/qcom/common/cryptfs_hw
LOCAL_C_INCLUDES += $(TARGET_CRYPTFS_HW_PATH)
common_shared_libraries += libcryptfs_hw
LOCAL_CFLAGS += -DCONFIG_HW_DISK_ENCRYPTION
endif

LOCAL_SHARED_LIBRARIES := $(common_shared_libraries)
LOCAL_STATIC_LIBRARIES := libvold $(common_static_libraries)

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_CLANG := true
LOCAL_SRC_FILES:= vdc.c
LOCAL_MODULE:= vdc
LOCAL_SHARED_LIBRARIES := libcutils
LOCAL_CFLAGS := $(vold_cflags)
LOCAL_CONLYFLAGS := $(vold_conlyflags)

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_CLANG := true
LOCAL_SRC_FILES:= secdiscard.cpp
LOCAL_MODULE:= secdiscard
LOCAL_SHARED_LIBRARIES := libcutils
LOCAL_CFLAGS := $(vold_cflags)
LOCAL_CONLYFLAGS := $(vold_conlyflags)

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_MODULE := libminivold
LOCAL_CLANG := true
LOCAL_SRC_FILES := $(common_src_files)
LOCAL_C_INCLUDES := $(common_c_includes) system/core/fs_mgr/include system/core/logwrapper/include
LOCAL_SHARED_LIBRARIES := $(common_shared_libraries)
LOCAL_STATIC_LIBRARIES := $(common_static_libraries)
LOCAL_MODULE_TAGS := eng tests
LOCAL_CFLAGS := $(vold_cflags) -DMINIVOLD -DHELPER_PATH=\"/sbin/\"
LOCAL_CONLYFLAGS := $(vold_conlyflags)
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_MODULE := minivold
LOCAL_CLANG := true
LOCAL_SRC_FILES := vold.c
LOCAL_C_INCLUDES := $(common_c_includes)
LOCAL_CFLAGS := $(vold_cflags) -DMINIVOLD
LOCAL_CONLYFLAGS := $(vold_conlyflags)
LOCAL_STATIC_LIBRARIES := libminivold
LOCAL_STATIC_LIBRARIES += libc libc++_static libm
LOCAL_STATIC_LIBRARIES += libbase
LOCAL_STATIC_LIBRARIES += $(common_static_libraries) $(common_libraries)
LOCAL_STATIC_LIBRARIES += libcrypto_static libext2_uuid libvold
LOCAL_STATIC_LIBRARIES += libnl
LOCAL_SHARED_LIBRARIES := $(common_shared_libraries)
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_PACK_MODULE_RELOCATIONS := false
LOCAL_MODULE_CLASS := RECOVERY_EXECUTABLES
LOCAL_MODULE_PATH := $(TARGET_RECOVERY_ROOT_OUT)/sbin
LOCAL_MODULE_TAGS := optional
include $(BUILD_EXECUTABLE)
