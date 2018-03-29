#
# ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./android.mk APP_ABI=armeabi(armeabi-v7a/arm64-v8a)
#

LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

# ------------ zkit make env ---------------

zkit_PATH := $(LOCAL_PATH)/src/zkit

zkit_INCLUDE := $(zkit_PATH) \
			$(zkit_PATH)/include

zkit_FILES_PATH := $(zkit_PATH)/CommonKit \
			$(zkit_PATH)/LinuxKit \
			$(zkit_PATH)/ELFKit \
			$(zkit_PATH)/PosixKit

zkit_FILES_SUFFIX := %.cpp %.c

define walk
    $(wildcard $(1)) $(foreach e, $(wildcard $(1)/*), $(call walk, $(e)))
endef

zkit_ALLFILES := $(foreach src_path,$(zkit_FILES_PATH), $(call walk,$(src_path),*.*) )
# $(warning zkit_ALLFILES $(zkit_ALLFILES))
zkit_FILE_LIST  := $(filter $(zkit_FILES_SUFFIX),$(zkit_ALLFILES))
zkit_SRC_FILES := $(zkit_FILE_LIST:$(LOCAL_PATH)/%=%)
# $(warning zkit_SRC_FILES= $(zkit_SRC_FILES))

# ------------ zkit make env end ---------------


# ------------ hookzz make env ---------------
 
HOOKZZ_INCLUDE := $(LOCAL_PATH)/include \
			$(LOCAL_PATH)/src

HOOKZZ_SRC_FILES := $(wildcard $(LOCAL_PATH)/src/*.c) \
			$(wildcard $(LOCAL_PATH)/src/platforms/backend-linux/*.c) \
			$(wildcard $(LOCAL_PATH)/src/platforms/backend-posix/*.c)

ifeq ($(TARGET_ARCH), arm)
	HOOKZZ_SRC_FILES += $(wildcard $(LOCAL_PATH)/src/platforms/arch-arm/*.c) \
			$(wildcard $(LOCAL_PATH)/src/platforms/backend-arm/*.c)
else ifeq ($(TARGET_ARCH), arm64)
	HOOKZZ_SRC_FILES += $(wildcard $(LOCAL_PATH)/src/platforms/arch-arm64/*.c) \
			$(wildcard $(LOCAL_PATH)/src/platforms/backend-arm64/*.c) \
			$(wildcard $(LOCAL_PATH)/src/platforms/backend-arm64/*.S)

else ifeq ($(TARGET_ARCH), x86)
	HOOKZZ_SRC_FILES += $(wildcard $(LOCAL_PATH)/src/platforms/arch-x86/*.c) \
			$(wildcard $(LOCAL_PATH)/src/platforms/backend-x86/*.c)
endif

# ------------ hookzz make env end ---------------

HOOKZZ_SRC_FILES += $(zkit_FILE_LIST)
HOOKZZ_INCLUDE += $(zkit_INCLUDE)

LOCAL_MODULE := hookzz
LOCAL_C_INCLUDES := $(HOOKZZ_INCLUDE)
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_SRC_FILES := 	$(HOOKZZ_SRC_FILES)
LOCAL_LDLIBS += -llog

include $(BUILD_STATIC_LIBRARY)