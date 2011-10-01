BUILD_VOLD2 := false
ifneq ($(TARGET_SIMULATOR),true)
    BUILD_VOLD2 := true
endif

ifeq ($(BUILD_VOLD2),true)

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
	Fat.cpp \
	Ntfs.cpp \
	Loop.cpp \
	Devmapper.cpp \
	ResponseCode.cpp \
	Xwarp.cpp

common_c_includes := \
	$(KERNEL_HEADERS) \
	external/openssl/include

common_shared_libraries := \
	libsysutils \
	libcutils \
	libdiskconfig \
	libcrypto

include $(CLEAR_VARS)

LOCAL_MODULE := libvold
ifeq ($(BOARD_USE_USB_MASS_STORAGE_SWITCH), true)
LOCAL_CFLAGS += -DUSE_USB_MASS_STORAGE_SWITCH
endif
LOCAL_SRC_FILES := $(common_src_files)

LOCAL_C_INCLUDES := $(common_c_includes)

LOCAL_SHARED_LIBRARIES := $(common_shared_libraries)

LOCAL_MODULE_TAGS := eng tests

include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)

ifneq ($(BOARD_VOLD_MAX_PARTITIONS),)
LOCAL_CFLAGS += -DVOLD_MAX_PARTITIONS=$(BOARD_VOLD_MAX_PARTITIONS)
endif

ifeq ($(BOARD_VOLD_EMMC_SHARES_DEV_MAJOR), true)
LOCAL_CFLAGS += -DVOLD_EMMC_SHARES_DEV_MAJOR
endif

ifneq ($(TARGET_USE_CUSTOM_LUN_FILE_PATH),)
LOCAL_CFLAGS += -DCUSTOM_LUN_FILE=\"$(TARGET_USE_CUSTOM_LUN_FILE_PATH)\"
endif

ifneq ($(TARGET_USE_CUSTOM_SECOND_LUN_NUM),)
LOCAL_CFLAGS += -DCUSTOM_SECOND_LUN_NUM=$(TARGET_USE_CUSTOM_SECOND_LUN_NUM)
endif

LOCAL_MODULE:= vold

ifeq ($(BOARD_USE_USB_MASS_STORAGE_SWITCH), true)
LOCAL_CFLAGS += -DUSE_USB_MASS_STORAGE_SWITCH
endif

LOCAL_SRC_FILES := \
	main.cpp \
	$(common_src_files)

LOCAL_C_INCLUDES := $(common_c_includes)

LOCAL_SHARED_LIBRARIES := $(common_shared_libraries)

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:= vdc.c

LOCAL_MODULE:= vdc

LOCAL_C_INCLUDES := $(KERNEL_HEADERS)

LOCAL_SHARED_LIBRARIES := libcutils

include $(BUILD_EXECUTABLE)

endif # ifeq ($(BUILD_VOLD,true)
