# Build the unit tests.
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk

LOCAL_C_INCLUDES := \
    system/core/fs_mgr/include

LOCAL_SHARED_LIBRARIES := \
    liblog \
    libcrypto \

LOCAL_STATIC_LIBRARIES := libvold
LOCAL_SRC_FILES := VolumeManager_test.cpp
LOCAL_MODULE := vold_tests
LOCAL_MODULE_TAGS := eng tests

include $(BUILD_NATIVE_TEST)
