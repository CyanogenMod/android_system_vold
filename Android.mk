LOCAL_PATH:= $(call my-dir)

ifneq ($(BOARD_VOLD_MAX_PARTITIONS),)
common_cflags += -DVOLD_MAX_PARTITIONS=$(BOARD_VOLD_MAX_PARTITIONS)
endif

ifeq ($(BOARD_VOLD_EMMC_SHARES_DEV_MAJOR), true)
common_cflags += -DVOLD_EMMC_SHARES_DEV_MAJOR
endif

ifeq ($(BOARD_VOLD_DISC_HAS_MULTIPLE_MAJORS), true)
common_cflags += -DVOLD_DISC_HAS_MULTIPLE_MAJORS
endif

ifneq ($(TARGET_USE_CUSTOM_LUN_FILE_PATH),)
common_cflags += -DCUSTOM_LUN_FILE=\"$(TARGET_USE_CUSTOM_LUN_FILE_PATH)\"
endif

common_cflags += -Werror

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
	cryptfs.c \
	main.cpp

extra_src_files := \
	Xwarp.cpp \
	VoldUtil.c \
	fstrim.c \

common_c_includes := \
	$(KERNEL_HEADERS) \
	system/extras/ext4_utils \
	external/openssl/include \
	external/stlport/stlport \
	bionic \
	external/scrypt/lib/crypto \
	external/e2fsprogs/lib \
	system/core/fs_mgr/include \
	system/core/logwrapper/include

common_libraries := \
	libsysutils \
	libcutils \
	liblog \
	libdiskconfig \
	libext2_blkid \
	liblogwrap

common_static_libraries := \
	libfs_mgr \
	libext4_utils_static \
	libstlport_static \
	libscrypt_static \
	libminshacrypt \
	libpower

include $(CLEAR_VARS)
LOCAL_MODULE := libvold
LOCAL_SRC_FILES := $(common_src_files) $(extra_src_files)
LOCAL_C_INCLUDES := $(common_c_includes)
LOCAL_SHARED_LIBRARIES := $(common_libraries) libcrypto
LOCAL_CFLAGS := $(common_cflags)
LOCAL_MODULE_TAGS := eng tests
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE:= vold
LOCAL_SRC_FILES := vold.c
LOCAL_C_INCLUDES := $(common_c_includes)
LOCAL_CFLAGS := $(common_cflags)
LOCAL_SHARED_LIBRARIES := $(common_libraries) libcrypto
LOCAL_STATIC_LIBRARIES := libvold $(common_static_libraries)
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_SRC_FILES:= vdc.c
LOCAL_MODULE:= vdc
LOCAL_C_INCLUDES := $(KERNEL_HEADERS)
LOCAL_CFLAGS := 
LOCAL_SHARED_LIBRARIES := libcutils
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE:= libminivold
LOCAL_SRC_FILES := $(common_src_files)
LOCAL_C_INCLUDES := $(common_c_includes)
LOCAL_CFLAGS := $(common_cflags) -DMINIVOLD -DHELPER_PATH=\"/sbin/\"
LOCAL_MODULE_TAGS := optional
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE:= minivold
LOCAL_SRC_FILES := vold.c
LOCAL_C_INCLUDES := $(common_c_includes)
LOCAL_CFLAGS := $(common_cflags) -DMINIVOLD
LOCAL_STATIC_LIBRARIES := libminivold
LOCAL_STATIC_LIBRARIES += libc libstdc++
LOCAL_STATIC_LIBRARIES += $(common_libraries) $(common_static_libraries)
LOCAL_STATIC_LIBRARIES += libcrypto_static libext2_uuid libvold
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_CLASS := RECOVERY_EXECUTABLES
LOCAL_MODULE_PATH := $(TARGET_RECOVERY_ROOT_OUT)/sbin
LOCAL_MODULE_TAGS := optional
include $(BUILD_EXECUTABLE)
