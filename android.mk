#
# ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./android.mk APP_ABI=armeabi(armeabi-v7a/arm64-v8a)
#

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE    := capstone.armv7
LOCAL_SRC_FILES := $(LOCAL_PATH)/deps/capstone/libcapstone.android.armv7.a
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/deps/capstone/include
include $(PREBUILT_STATIC_LIBRARY)


include $(CLEAR_VARS)
LOCAL_MODULE    := capstone.armv64
LOCAL_SRC_FILES := $(LOCAL_PATH)/deps/capstone/libcapstone.android.arm64.a
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/deps/capstone/include
include $(PREBUILT_STATIC_LIBRARY)


include $(CLEAR_VARS)

ZZ_INCLUDE := $(LOCAL_PATH)/include \
			$(LOCAL_PATH)/src \
			$(LOCAL_PATH)/deps/capstone/include

ZZ_SRC := $(wildcard $(LOCAL_PATH)/src/*.c) \
			$(wildcard $(LOCAL_PATH)/src/zzdeps/common/*.c) \
			$(wildcard $(LOCAL_PATH)/src/zzdeps/posix/*.c) \
			$(wildcard $(LOCAL_PATH)/src/platforms/backend-linux/*.c) \
			$(wildcard $(LOCAL_PATH)/src/platforms/backend-posix/*.c)

ifeq ($(TARGET_ARCH), arm)

	ZZ_SRC += $(wildcard $(LOCAL_PATH)/src/platforms/arch-arm/*.c) \
			$(wildcard $(LOCAL_PATH)/src/platforms/backend-arm/*.c)
	ZZ_STATIC_LIB := capstone.armv7
else ifeq ($(TARGET_ARCH), arm64)
	ZZ_SRC += $(wildcard $(LOCAL_PATH)/src/platforms/arch-arm64/*.c) \
			$(wildcard $(LOCAL_PATH)/src/platforms/backend-arm64/*.c)
	ZZ_STATIC_LIB := capstone.arm64
endif

LOCAL_MODULE := hookzz
LOCAL_C_INCLUDES := $(ZZ_INCLUDE)
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_SRC_FILES := 	$(ZZ_SRC)
# LOCAL_CFLAGS := 
LOCAL_STATIC_LIBRARIES := $(ZZ_STATIC_LIB)

include $(BUILD_STATIC_LIBRARY)
# include $(BUILD_SHARED_LIBRARY)
