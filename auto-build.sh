#!/bin/sh

# if error, exit
set -

CURRENT_DIR=$(dirname "$0")

compress_dir_array=""

summary_output_dir_name=build-output

rm -rf ${summary_output_dir_name}

# build macos x86_64
output_dir_name=darwin-x64-build
echo "prepare build ${output_dir_name}"

mkdir -p ${CURRENT_DIR}/${output_dir_name}
cmake -S . -B ${output_dir_name} -DCMAKE_BUILD_TYPE=Release \
  -DDOBBY_GENERATE_SHARED=OFF -DDarwin.GenerateFramework=ON -DDOBBY_DEBUG=OFF
cmake --build ${output_dir_name} --target Dobby

mkdir -p ${summary_output_dir_name}/darwin/x86_64
cp -r ${output_dir_name}/Dobby.framework ${summary_output_dir_name}/darwin/x86_64


# build iphone aarch64
output_dir_name=darwin-arm64-build
compress_dir_array="$compress_dir_array $output_dir_name"
echo "prepare build ${output_dir_name}"

mkdir -p ${CURRENT_DIR}/${output_dir_name}
cmake -S . -B ${output_dir_name} -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE=cmake/ios.toolchain.cmake \
  -DPLATFORM=OS64 -DARCHS="arm64" -DCMAKE_SYSTEM_PROCESSOR=arm64 \
  -DENABLE_BITCODE=0 -DENABLE_ARC=0 -DENABLE_VISIBILITY=1 -DDEPLOYMENT_TARGET=9.3 \
  -DDOBBY_GENERATE_SHARED=OFF -DDarwin.GenerateFramework=ON -DDOBBY_DEBUG=OFF
cmake --build ${output_dir_name} --target Dobby

mkdir -p ${summary_output_dir_name}/darwin/arm64
cp -r ${output_dir_name}/Dobby.framework ${summary_output_dir_name}/darwin/arm64


# build darwin universal
output_dir_name=darwin-universal-build
echo "prepare build ${output_dir_name}"

mkdir -p ${CURRENT_DIR}/${output_dir_name}

cp -r ${summary_output_dir_name}/darwin/arm64/Dobby.framework ${output_dir_name}
lipo -create ${summary_output_dir_name}/darwin/arm64/Dobby.framework/Dobby ${summary_output_dir_name}/darwin/x86_64/Dobby.framework/Dobby -output ${output_dir_name}/Dobby.framework/Dobby

mkdir -p ${summary_output_dir_name}/darwin/universal
cp -r ${output_dir_name}/Dobby.framework ${summary_output_dir_name}/darwin/universal

# build android aarch64
output_dir_name=android-arm64-build
compress_dir_array="$compress_dir_array $output_dir_name"
echo "prepare build ${output_dir_name}"

cmake -S . -B ${output_dir_name} -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_SYSTEM_NAME=Android -DCMAKE_ANDROID_ARCH_ABI="arm64-v8a" -DCMAKE_ANDROID_NDK=$ANDROID_NDK_DIR -DCMAKE_SYSTEM_VERSION=21 -DCMAKE_ANDROID_NDK_TOOLCHAIN_VERSION=clang \
  -DDOBBY_GENERATE_SHARED=OFF -DDOBBY_DEBUG=OFF
cmake --build ${output_dir_name} --target dobby

mkdir -p ${summary_output_dir_name}/android/arm64
mv ${output_dir_name}/libdobby.a ${summary_output_dir_name}/android/arm64/libdobby.a


# build android armv7
output_dir_name=android-armv7-build
compress_dir_array="$compress_dir_array $output_dir_name"
echo "prepare build ${output_dir_name}"

cmake -S . -B ${output_dir_name} -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_SYSTEM_NAME=Android -DCMAKE_ANDROID_ARCH_ABI="armeabi-v7a" -DCMAKE_ANDROID_NDK=$ANDROID_NDK_DIR -DCMAKE_SYSTEM_VERSION=16 -DCMAKE_ANDROID_NDK_TOOLCHAIN_VERSION=clang \
  -DDOBBY_GENERATE_SHARED=OFF -DDOBBY_DEBUG=OFF
cmake --build ${output_dir_name} --target dobby

mkdir -p ${summary_output_dir_name}/android/armv7
mv ${output_dir_name}/libdobby.a ${summary_output_dir_name}/android/armv7/libdobby.a


current_date_time="`date +%Y%m%d%H%M%S`";
tar czvf Dobby_${current_date_time}.tar.gz ${summary_output_dir_name}
