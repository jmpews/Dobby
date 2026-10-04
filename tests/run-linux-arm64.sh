#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DPlugin.SymbolResolver=OFF -DDOBBY_DEBUG=OFF
cmake --build build --target dobby_static dobby -j2
c++ -O2 -mbranch-protection=pac-ret+bti -I include tests/linux-arm64-hook-smoke.cpp build/libdobby.a -ldl -o build/hook-smoke
build/hook-smoke
c++ -O2 -mbranch-protection=pac-ret+bti -I include tests/linux-arm64-hook-smoke.cpp -L build -ldobby -Wl,-rpath,"$PWD/build" -o build/hook-smoke-shared
build/hook-smoke-shared
c++ -std=c++17 -O2 -I include -I source -I . -I common -I external -I external/logging tests/linux-process-map-smoke.cpp build/libdobby.a -ldl -o build/process-map-smoke
build/process-map-smoke
