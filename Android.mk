LOCAL_PATH:= $(call my-dir)

common_src_files := \
	VolumeManager.cpp \
	CommandListener.cpp \
	CryptCommandListener.cpp \
	VoldCommand.cpp \
	NetlinkManager.cpp \
	NetlinkHandler.cpp \
	Process.cpp \
	fs/Ext4.cpp \
	fs/F2fs.cpp \
	fs/Vfat.cpp \
	Loop.cpp \
	Devmapper.cpp \
	ResponseCode.cpp \
	CheckBattery.cpp \
	Ext4Crypt.cpp \
	VoldUtil.c \
	cryptfs.c \
	Disk.cpp \
	VolumeBase.cpp \
	PublicVolume.cpp \
	PrivateVolume.cpp \
	EmulatedVolume.cpp \
	Utils.cpp \
	MoveTask.cpp \
	Benchmark.cpp \
	TrimTask.cpp \
	Keymaster.cpp \
	KeyStorage.cpp \
	ScryptParameters.cpp \
	secontext.cpp \

common_c_includes := \
	system/extras/ext4_utils \
	system/extras/f2fs_utils \
	external/scrypt/lib/crypto \
	frameworks/native/include \
	system/security/keystore \
	hardware/libhardware/include/hardware \
	system/security/softkeymaster/include/keymaster

common_shared_libraries := \
	libsysutils \
	libbinder \
	libcutils \
	liblog \
	libdiskconfig \
	libhardware_legacy \
	liblogwrap \
	libext4_utils \
	libf2fs_sparseblock \
	libcrypto \
	libselinux \
	libutils \
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
	libsquashfs_utils \
	libscrypt_static \
	libmincrypt \
	libbatteryservice \
	libext2_blkid \
	libext2_uuid_static

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
LOCAL_MODULE := vold
LOCAL_CLANG := true
LOCAL_SRC_FILES := \
	main.cpp \
	$(common_src_files)

LOCAL_INIT_RC := vold.rc

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
LOCAL_STATIC_LIBRARIES := $(common_static_libraries)

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
