LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
ROOT_PATH := $(LOCAL_PATH)
LOCAL_MODULE := hookzzdemo
LOCAL_C_INCLUDES := $(ROOT_PATH)
LOCAL_SRC_FILES := 	native-lib.cpp
LOCAL_LDLIBS := -llog
LOCAL_STATIC_LIBRARIES := hookzz
include $(BUILD_SHARED_LIBRARY)

include D:\CodeDocument\project\HookZz\Android.mk