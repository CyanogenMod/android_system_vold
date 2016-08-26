LOCAL_PATH:= $(call my-dir)

common_src_files := \
	VolumeManager.cpp \
	CommandListener.cpp \
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
	secontext.cpp \
	main.cpp

crypto_src_files := \
	CryptCommandListener.cpp \
	Ext4Crypt.cpp \
	cryptfs.c \
	Keymaster.cpp \
	KeyStorage.cpp \
	ScryptParameters.cpp

common_c_includes := \
	system/extras/ext4_utils \
	system/extras/f2fs_utils \
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
	libutils

common_shared_libraries := \
	$(common_libraries) \
	libhardware_legacy \
	libext4_utils \
	libcrypto \
	libhardware \
	libsoftkeymaster \
	libbase \
	libkeymaster_messages \
	libext2_blkid

common_static_libraries := \
	libbootloader_message_writer \
	libfs_mgr \
	libfec \
	libfec_rs \
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

ifeq ($(TARGET_KERNEL_HAVE_EXFAT),true)
vold_cflags += -DCONFIG_KERNEL_HAVE_EXFAT
endif

ifeq ($(TARGET_KERNEL_HAVE_NTFS),true)
vold_cflags += -DCONFIG_KERNEL_HAVE_NTFS
endif

include $(CLEAR_VARS)

LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_MODULE := libvold
LOCAL_CLANG := true
LOCAL_SRC_FILES := $(common_src_files) $(crypto_src_files)
LOCAL_C_INCLUDES := $(common_c_includes)
LOCAL_SHARED_LIBRARIES := $(common_shared_libraries)
LOCAL_STATIC_LIBRARIES := $(common_static_libraries)
LOCAL_MODULE_TAGS := eng tests
LOCAL_CFLAGS := $(vold_cflags)
LOCAL_CONLYFLAGS := $(vold_conlyflags)

ifeq ($(TARGET_HW_DISK_ENCRYPTION),true)
TARGET_CRYPTFS_HW_PATH ?= device/qcom/common/cryptfs_hw
LOCAL_C_INCLUDES += $(TARGET_CRYPTFS_HW_PATH)
LOCAL_CFLAGS += -DCONFIG_HW_DISK_ENCRYPTION
endif

include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)

LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_MODULE := vold
LOCAL_CLANG := true
LOCAL_SRC_FILES := \
	vold.c

LOCAL_INIT_RC := vold.rc

LOCAL_C_INCLUDES := $(common_c_includes)
LOCAL_CFLAGS := $(vold_cflags)
LOCAL_CONLYFLAGS := $(vold_conlyflags)

LOCAL_SHARED_LIBRARIES := $(common_shared_libraries)
LOCAL_STATIC_LIBRARIES := libvold $(common_static_libraries)

ifeq ($(TARGET_HW_DISK_ENCRYPTION),true)
LOCAL_SHARED_LIBRARIES += libcryptfs_hw
endif

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_CLANG := true
LOCAL_SRC_FILES := vdc.cpp
LOCAL_MODULE := vdc
LOCAL_SHARED_LIBRARIES := libcutils libbase
LOCAL_CFLAGS := $(vold_cflags)
LOCAL_CONLYFLAGS := $(vold_conlyflags)
LOCAL_INIT_RC := vdc.rc

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_CLANG := true
LOCAL_SRC_FILES:= secdiscard.cpp
LOCAL_MODULE:= secdiscard
LOCAL_SHARED_LIBRARIES := libbase
LOCAL_CFLAGS := $(vold_cflags)
LOCAL_CONLYFLAGS := $(vold_conlyflags)

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_MODULE := libminivold_static
LOCAL_CLANG := true
LOCAL_SRC_FILES := $(common_src_files)
LOCAL_C_INCLUDES := $(common_c_includes) system/core/fs_mgr/include system/core/logwrapper/include
LOCAL_SHARED_LIBRARIES := $(common_shared_libraries)
LOCAL_STATIC_LIBRARIES := $(common_static_libraries)
LOCAL_MODULE_TAGS := eng tests
LOCAL_CFLAGS := $(vold_cflags) -DMINIVOLD
LOCAL_CONLYFLAGS := $(vold_conlyflags)
include $(BUILD_STATIC_LIBRARY)
