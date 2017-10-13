NO_COLOR=\x1b[0m
OK_COLOR=\x1b[32;01m
ERROR_COLOR=\x1b[31;01m
WARN_COLOR=\x1b[33;01m

HOOKZZ_NAME := hookzz
HOOKZZ_DIR := $(abspath .)
LOCAL_PATH := $(abspath .)
OUTPUT_DIR := $(abspath build)

CFLAGS ?= -O0 -g
CXXFLAGS = $(CFLAGS) -stdlib=libc++ -std=c++11 -gmodules
LDFLAGS ?=
LIBS_CFLAGS ?= -fPIC

OS ?= $(shell uname -s)

ZZ_SRCS_PATH := $(abspath $(LOCAL_PATH)/src)
ZZ_DEPS_PATH := $(abspath $(LOCAL_PATH)/src/zzdeps)
ZZ_CAPSTONE_DEPS_PATH := $(abspath $(LOCAL_PATH)/deps/capstone)
ZZ_COMMON_SRCS := $(wildcard $(ZZ_SRCS_PATH)/*.c)

ifeq ($(OS), Darwin)

endif

ifeq ($(BACKEND), ios)

	ZZ_BACKEND := ios
	ZZ_GXX_BIN := $(shell xcrun --sdk iphoneos --find clang++)
	ZZ_GCC_BIN := $(shell xcrun --sdk iphoneos --find clang)
	ZZ_SDK := $(shell xcrun --sdk iphoneos --show-sdk-path)
	ZZ_GCC_SOURCE := $(ZZ_GCC_BIN) -isysroot $(ZZ_SDK)
	ZZ_GXX_SOURCE := $(ZZ_GXX_BIN) -isysroot $(ZZ_SDK)
	ZZ_GCC_TEST := $(ZZ_GCC_BIN) -isysroot $(ZZ_SDK)
	ZZ_GXX_TEST := $(ZZ_GXX_BIN) -isysroot $(ZZ_SDK)

	# zzdeps
	ZZ_DEPS_SRCS := $(wildcard $(ZZ_DEPS_PATH)/darwin/*.c) \
			$(wildcard $(ZZ_DEPS_PATH)/common/*.c) \
			$(wildcard $(ZZ_DEPS_PATH)/posix/*.c) 
	ZZ_DEPS_OBJS := $(ZZ_DEPS_SRCS:.c=.o)

	ZZ_SRCS := $(ZZ_COMMON_SRCS) \
			$(wildcard $(ZZ_SRCS_PATH)/platforms/backend-darwin/*.c) \
			$(wildcard $(ZZ_SRCS_PATH)/platforms/backend-posix/*.c)
	
	ZZ_EXPORT_INCLUDE := -I$(LOCAL_PATH)/include

	ZZ_SRCS_INCLUDE := $(ZZ_EXPORT_INCLUDE) \
			-I$(ZZ_CAPSTONE_DEPS_PATH)/include \
			-I$(ZZ_SRCS_PATH)
	
	ifeq ($(ARCH), arm)
		ZZ_ARCH := armv7

		ZZ_SRCS += $(wildcard $(ZZ_SRCS_PATH)/platforms/arch-$(ARCH)/*.c) \
			$(wildcard $(ZZ_SRCS_PATH)/platforms/backend-$(ARCH)/*.c)
		ZZ_CAPSTONE_LIB := -L$(ZZ_CAPSTONE_DEPS_PATH) -lcapstone.$(ZZ_BACKEND).$(ZZ_ARCH)
		OUTPUT_DIR := $(OUTPUT_DIR)/$(ZZ_BACKEND)-$(ARCH)
	else ifeq ($(ARCH), arm64)
		ZZ_ARCH := arm64

		ZZ_SRCS += $(wildcard $(ZZ_SRCS_PATH)/platforms/arch-$(ARCH)/*.c) \
			$(wildcard $(ZZ_SRCS_PATH)/platforms/backend-$(ARCH)/*.c)
		ZZ_CAPSTONE_LIB := -L$(ZZ_CAPSTONE_DEPS_PATH) -lcapstone.$(ZZ_BACKEND).$(ZZ_ARCH)
		OUTPUT_DIR := $(OUTPUT_DIR)/$(ZZ_BACKEND)-$(ARCH)
	endif

	ZZ_GCC_BIN += -arch $(ZZ_ARCH) 
	ZZ_GCC_SOURCE += $(ZZ_SRCS_INCLUDE) -arch $(ZZ_ARCH)
	ZZ_GCC_TEST += $(ZZ_INCLUDE) -arch $(ZZ_ARCH) 

	_ := $(shell rm -rf $(ZZ_CAPSTONE_DEPS_PATH)/libcapstone.$(ZZ_BACKEND).$(ZZ_ARCH).o)
	_ := $(shell mkdir -p $(ZZ_CAPSTONE_DEPS_PATH)/libcapstone.$(ZZ_BACKEND).$(ZZ_ARCH).o)
	_ := $(shell cp $(ZZ_CAPSTONE_DEPS_PATH)/libcapstone.$(ZZ_BACKEND).$(ZZ_ARCH).a $(ZZ_CAPSTONE_DEPS_PATH)/libcapstone.$(ZZ_BACKEND).$(ZZ_ARCH).o/)
	_ := $(shell cd $(ZZ_CAPSTONE_DEPS_PATH)/libcapstone.$(ZZ_BACKEND).$(ZZ_ARCH).o/; ar -x $(ZZ_CAPSTONE_DEPS_PATH)/libcapstone.$(ZZ_BACKEND).$(ZZ_ARCH).o/libcapstone.$(ZZ_BACKEND).$(ZZ_ARCH).a)

	ZZ_CAPSTONE_DEPS_OBJS := $(wildcard $(ZZ_CAPSTONE_DEPS_PATH)/libcapstone.$(ZZ_BACKEND).$(ZZ_ARCH).o/*.o)

	ZZ_LIB := $(ZZ_CAPSTONE_LIB)

	CFLAGS ?= -g
	LDFLAGS := $(ZZ_LIB)
	ZZ_SRCS_OBJS := $(ZZ_SRCS:.c=.o)
	
	ZZ_OBJS := $(ZZ_SRCS_OBJS) $(ZZ_DEPS_OBJS)

# ATTENTION !!!
# 1. simple `ar` can't make a 'static library', need `ar -x` to extract `libcapstone.ios.arm64.a` and then `ar rcs` to pack as `.a`
# 2. must `rm -rf  $(OUTPUT_DIR)/libhookzz.static.a`, very important!!!
$(HOOKZZ_NAME) : $(ZZ_OBJS)
	@mkdir -p $(OUTPUT_DIR)
	@rm -rf $(OUTPUT_DIR)/*

	@$(ZZ_GCC_SOURCE) -fPIC -shared -dynamiclib $(CFLAGS) $(LDFLAGS) $(ZZ_OBJS) -o $(OUTPUT_DIR)/lib$(HOOKZZ_NAME).dylib
	@ar -rcs $(OUTPUT_DIR)/lib$(HOOKZZ_NAME).static.a $(ZZ_OBJS) $(ZZ_CAPSTONE_DEPS_OBJS)

	@echo "$(OK_COLOR)build success for $(ARCH)-ios-hookzz! $(NO_COLOR)"

$(ZZ_SRCS_OBJS): %.o : %.c
	@$(ZZ_GCC_SOURCE) $(CFLAGS) -c $< -o $@
	@echo "$(OK_COLOR)generate [$@]! $(NO_COLOR)"

$(ZZ_DEPS_OBJS): %.o : %.c
	@$(ZZ_GCC_BIN) -isysroot $(ZZ_SDK) $(CFLAGS) -c $< -o $@
	@echo "$(OK_COLOR)generate [$@]! $(NO_COLOR)"


else ifeq ($(BACKEND), android)
endif

clean:
	@rm -rf $(shell find ./src -name "*\.o" | xargs echo)
	@rm -rf $(OUTPUT_DIR)
	@echo "$(OK_COLOR)clean all *.o success!$(NO_COLOR)"