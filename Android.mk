LOCAL_PATH:= $(call my-dir)

common_src_files := \
	VolumeManager.cpp \
	CommandListener.cpp \
	VoldCommand.cpp \
	NetlinkManager.cpp \
	NetlinkHandler.cpp \
	Volume.cpp \
	DirectVolume.cpp \
	AutoVolume.cpp \
	logwrapper.c \
	Process.cpp \
	Ext4.cpp \
	Fat.cpp \
	Ntfs.cpp \
	Loop.cpp \
	Devmapper.cpp \
	ResponseCode.cpp \
	Xwarp.cpp \
	cryptfs.c

common_c_includes := \
	$(KERNEL_HEADERS) \
	system/extras/ext4_utils \
	external/openssl/include

common_shared_libraries := \
	libsysutils \
	libcutils \
	libdiskconfig \
	libhardware_legacy \
	libcrypto

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

LOCAL_STATIC_LIBRARIES := libfs_mgr

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

ifneq ($(TARGET_USE_CUSTOM_LUN_FILE_PATH),)
LOCAL_CFLAGS += -DCUSTOM_LUN_FILE=\"$(TARGET_USE_CUSTOM_LUN_FILE_PATH)\"
endif

ifneq ($(TARGET_USE_CUSTOM_SECOND_LUN_NUM),)
LOCAL_CFLAGS += -DCUSTOM_SECOND_LUN_NUM=$(TARGET_USE_CUSTOM_SECOND_LUN_NUM)
endif

LOCAL_SHARED_LIBRARIES := $(common_shared_libraries)

LOCAL_STATIC_LIBRARIES := libfs_mgr

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:= vdc.c

LOCAL_MODULE:= vdc

LOCAL_C_INCLUDES := $(KERNEL_HEADERS)

LOCAL_CFLAGS := 

LOCAL_SHARED_LIBRARIES := libcutils

include $(BUILD_EXECUTABLE)
