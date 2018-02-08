#!/bin/bash

# !!! Do Not Use This

export PWD=`pwd`
export PREFIX=${PWD}/system
export NDK_HOME=/xxx/android-ndk-r10e
export CROSS_COMPILE=${NDK_HOME}/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin/arm-linux-androideabi-
export PATH=${NDK_HOME}/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin:$PATH
export SYSROOT=${NDK_HOME}/platforms/android-21/arch-arm

make distclean
rm */config.cache
./configure \
--prefix=$PREFIX \
--host=arm-linux-androideabi \
--target=arm-linux-androideabi \
--disable-option-checking \
CC=${CROSS_COMPILE}gcc \
CXX=${CROSS_COMPILE}g++ \
CFLAGS="-g -I -O2 -mandroid -mbionic -I${NDK_HOME}/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/lib/gcc/arm-linux-androideabi/4.9/include -I${SYSROOT}/usr/include/ --sysroot=${SYSROOT} -Wno-error -fPIE" \
LDFLAGS="-L${NDK_HOME}/platforms/android-21/arch-arm/usr/lib -pie" \
CPP=${CROSS_COMPILE}cpp \
CPPFLAGS="-I${NDK_HOME}/platforms/android-21/arch-arm/usr/include/" \
AR=${CROSS_COMPILE}ar

make -j4
mkdir -p $PREFIX
make install