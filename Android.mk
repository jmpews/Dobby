#
# ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./android.mk APP_ABI=armeabi(armeabi-v7a/arm64-v8a)
#

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

# ------------ kitzz make env ---------------

KITZZ_PATH := D:/CodeDocument/project/kitzz

KITZZ_INCLUDE := $(KITZZ_PATH) \
			$(KITZZ_PATH)/include

KITZZ_FILES_PATH := $(KITZZ_PATH)/CommonKit \
			$(KITZZ_PATH)/LinuxKit \
			$(KITZZ_PATH)/ELFKit \
			$(KITZZ_PATH)/PosixKit

KITZZ_FILES_SUFFIX := %.cpp %.c

define walk
    $(wildcard $(1)) $(foreach e, $(wildcard $(1)/*), $(call walk, $(e)))
endef

KITZZ_ALLFILES := $(foreach src_path,$(KITZZ_FILES_PATH), $(call walk,$(src_path),*.*) )
#$(warning KITZZ_ALLFILES $(KITZZ_ALLFILES))
KITZZ_FILE_LIST  := $(filter $(KITZZ_FILES_SUFFIX),$(KITZZ_ALLFILES))
KITZZ_SRC_FILES := $(KITZZ_FILE_LIST:$(LOCAL_PATH)/%=%)
#(warning KITZZ_SRC_FILES= $(KITZZ_SRC_FILES))

# ------------ kitzz make env end ---------------


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

HOOKZZ_SRC_FILES += $(KITZZ_SRC_FILES)
HOOKZZ_INCLUDE += $(KITZZ_INCLUDE)

LOCAL_MODULE := hookzz
LOCAL_C_INCLUDES := $(HOOKZZ_INCLUDE)
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_SRC_FILES := 	$(HOOKZZ_SRC_FILES)

include $(BUILD_STATIC_LIBRARY)