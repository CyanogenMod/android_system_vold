BUILD_VOLD2 := false
ifneq ($(TARGET_SIMULATOR),true)
    BUILD_VOLD2 := true
endif

ifeq ($(BUILD_VOLD2),true)

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:=                                      \
                  main.cpp                             \
		  VolumeManager.cpp                    \
		  CommandListener.cpp                  \
                  VoldCommand.cpp                      \
                  NetlinkManager.cpp                   \
                  NetlinkHandler.cpp                   \
                  BlockDevice.cpp                      \
                  Volume.cpp                           \
                  DirectVolume.cpp                     \
                  logwrapper.c                         \
                  Process.cpp                          \
                  geom_mbr_enc.c                       \
                  Fat.cpp                              \
                  Loop.cpp                             \
                  Devmapper.cpp                        \
                  ResponseCode.cpp                     \
                  Xwarp.cpp

LOCAL_MODULE:= vold

LOCAL_C_INCLUDES := $(KERNEL_HEADERS) -I../../frameworks/base/include/

LOCAL_CFLAGS := 

LOCAL_SHARED_LIBRARIES := libsysutils libcutils

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_SRC_FILES:=          \
                  vdc.c \

LOCAL_MODULE:= vdc

LOCAL_C_INCLUDES := $(KERNEL_HEADERS)

LOCAL_CFLAGS := 

LOCAL_SHARED_LIBRARIES := libcutils

include $(BUILD_EXECUTABLE)

endif # ifeq ($(BUILD_VOLD,true)
