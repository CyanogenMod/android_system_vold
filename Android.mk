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
	logwrapper.c \
	Process.cpp \
	Fat.cpp \
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

LOCAL_SRC_FILES := $(common_src_files)

LOCAL_C_INCLUDES := $(common_c_includes)

LOCAL_SHARED_LIBRARIES := $(common_shared_libraries)

LOCAL_MODULE_TAGS := eng tests

include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)

LOCAL_MODULE:= vold

LOCAL_SRC_FILES := \
	main.cpp \
	$(common_src_files)

LOCAL_C_INCLUDES := $(common_c_includes)

LOCAL_CFLAGS := 

LOCAL_SHARED_LIBRARIES := $(common_shared_libraries)

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:= vdc.c

LOCAL_MODULE:= vdc

LOCAL_C_INCLUDES := $(KERNEL_HEADERS)

LOCAL_CFLAGS := 

LOCAL_SHARED_LIBRARIES := libcutils

include $(BUILD_EXECUTABLE)

endif # ifeq ($(BUILD_VOLD,true)
