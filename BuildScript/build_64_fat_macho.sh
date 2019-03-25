#!/bin/sh

# if error, exit
set -

BuildPath=$(dirname "$0")

# build aarch64
mkdir -p ${BuildPath}/temp_build_aarch64

cd temp_build_aarch64

cmake ../.. \
-DCMAKE_TOOLCHAIN_FILE=cmake/ios.toolchain.cmake \
-DIOS_PLATFORM=OS64 \
-DIOS_ARCH=arm64 \
-DENABLE_BITCODE=0 \
-DENABLE_ARC=0 \
-DENABLE_VISIBILITY=0 \
-DIOS_DEPLOYMENT_TARGET=9.3 \
-DCMAKE_SYSTEM_PROCESSOR=aarch64 \
-DSHARED=ON \
-DZ_DEBUG=ON

make -j4
cd ..

# build ios simulator
mkdir -p ${BuildPath}/temp_build_simulator_x86_64

cd temp_build_simulator_x86_64

cmake ../.. \
-DCMAKE_TOOLCHAIN_FILE=cmake/ios.toolchain.cmake \
-DIOS_PLATFORM=SIMULATOR64 \
-DIOS_ARCH=x86_64 \
-DENABLE_BITCODE=0 \
-DENABLE_ARC=0 \
-DENABLE_VISIBILITY=0 \
-DIOS_DEPLOYMENT_TARGET=9.3 \
-DCMAKE_SYSTEM_PROCESSOR=x86_64 \
-DSHARED=ON \
-DZ_DEBUG=ON

make -j4
cd ..

# build x86_64
mkdir -p ${BuildPath}/temp_build_x86_64

cd temp_build_x86_64

cmake ../.. \
-DSHARED=ON \
-DZ_DEBUG=ON

make -j4

cd ..

# lipo combine 2 dylib
lipo -create ${BuildPath}/temp_build_aarch64/libhookzz.dylib ${BuildPath}/temp_build_simulator_x86_64/libhookzz.dylib -output ${BuildPath}/libhookzz.dylib