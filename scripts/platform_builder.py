import os
import shutil
import subprocess
import sys
import logging
import argparse
from pathlib import Path

platforms = {
    "macos": ["x86_64", "arm64", "arm64e"],
    "iphoneos": ["arm64", "arm64e"],
    "linux": ["x86", "x86_64", "arm", "arm64"],
    "android": ["x86", "x86_64", "armeabi-v7a", "arm64-v8a"]
}

class PlatformBuilder:
    cmake_args = []
    cmake_build_type = "Release"
    cmake_dir = None
    llvm_dir = None
    
    def __init__(self, project_dir: Path, library_build_type, platform, arch):
        self.project_dir = project_dir
        self.library_build_type = library_build_type
        self.platform = platform
        self.arch = arch

        self.cmake_build_dir = project_dir / "build" / f"cmake-build-{platform}-{arch}"
        self.output_dir = project_dir / "build" / platform / arch

        self.cmake = "cmake" if not self.cmake_dir else str(Path(self.cmake_dir) / "bin" / "cmake")
        llvm_bin = Path(self.llvm_dir) / "bin" if self.llvm_dir else None
        self.clang = str(llvm_bin / "clang") if llvm_bin else "clang"
        self.clangxx = str(llvm_bin / "clang++") if llvm_bin else "clang++"

        self.shared_output_name = ""
        self.static_output_name = ""
        self.setup_common_args()

    def setup_common_args(self):
        self.cmake_args = [
            f"-DCMAKE_C_COMPILER={self.clang}",
            f"-DCMAKE_CXX_COMPILER={self.clangxx}",
            f"-DCMAKE_BUILD_TYPE={self.cmake_build_type}"
        ]

    def cmake_generate_build_system(self):
        self.cmake_build_dir.mkdir(parents=True, exist_ok=True)
        
        cmd = [
            self.cmake,
            "-S", str(self.project_dir),
            "-B", str(self.cmake_build_dir)
        ] + self.cmake_args
        
        logging.info(f"Executing: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)

    def build(self):
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.cmake_generate_build_system()

        build_cmd = [
            self.cmake, "--build", str(self.cmake_build_dir),
            "--clean-first",
            "--target", "dobby",
            "--target", "dobby_static",
            "--", "-j8"
        ]
        subprocess.run(build_cmd, check=True)

        for out_name in [self.shared_output_name, self.static_output_name]:
            if out_name:
                src = self.cmake_build_dir / out_name
                if src.exists():
                    shutil.copy(src, self.output_dir / out_name)
                    logging.info(f"Copied {out_name} to {self.output_dir}")

class LinuxPlatformBuilder(PlatformBuilder):
    def __init__(self, project_dir, library_build_type, arch):
        super().__init__(project_dir, library_build_type, "linux", arch)
        self.shared_output_name = "libdobby.so"
        self.static_output_name = "libdobby.a"
        self.cmake_args += [
            "-DCMAKE_SYSTEM_NAME=Linux",
            f"-DCMAKE_SYSTEM_PROCESSOR={arch}",
        ]

class AndroidPlatformBuilder(PlatformBuilder):
    def __init__(self, android_ndk_dir, project_dir, library_build_type, arch):
        super().__init__(project_dir, library_build_type, "android", arch)
        self.shared_output_name = "libdobby.so"
        self.static_output_name = "libdobby.a"

        api_level = 19 if arch in ["armeabi-v7a", "x86"] else 21
        self.cmake_args += [
            "-DCMAKE_SYSTEM_NAME=Android",
            f"-DCMAKE_ANDROID_NDK={android_ndk_dir}",
            f"-DCMAKE_ANDROID_ARCH_ABI={arch}",
            f"-DCMAKE_SYSTEM_VERSION={api_level}"
        ]

class DarwinPlatformBuilder(PlatformBuilder):
    def __init__(self, project_dir, library_build_type, platform, arch):
        super().__init__(project_dir, library_build_type, platform, arch)
        self.shared_output_name = "libdobby.dylib"
        self.static_output_name = "libdobby.a"

        self.cmake_args += [
            f"-DCMAKE_OSX_ARCHITECTURES={arch}",
            f"-DCMAKE_SYSTEM_PROCESSOR={arch}",
        ]

        if platform == "macos":
            self.cmake_args += ["-DCMAKE_SYSTEM_NAME=Darwin"]
            sdk_name = "macosx"
        else:
            self.cmake_args += ["-DCMAKE_SYSTEM_NAME=iOS", "-DCMAKE_OSX_DEPLOYMENT_TARGET=9.3"]
            sdk_name = "iphoneos"

        sdk_path = subprocess.check_output(["xcrun", "--sdk", sdk_name, "--show-sdk-path"], text=True).strip()
        self.cmake_args += [f"-DCMAKE_OSX_SYSROOT={sdk_path}"]

    @classmethod
    def lipo_create_fat(cls, project_dir: Path, platform, output_name):
        archs = platforms[platform]
        files = [str(project_dir / "build" / platform / a / output_name) for a in archs]
        
        fat_output_dir = project_dir / "build" / platform / "universal"
        fat_output_dir.mkdir(parents=True, exist_ok=True)
        
        cmd = ["lipo", "-create"] + files + ["-output", str(fat_output_dir / output_name)]
        subprocess.run(cmd, check=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", type=str, required=True)
    parser.add_argument("--arch", type=str, required=True)
    parser.add_argument("--library_build_type", type=str, default="static")
    parser.add_argument("--android_ndk_dir", type=str)
    parser.add_argument("--cmake_dir", type=str)
    parser.add_argument("--llvm_dir", type=str)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    project_root = Path(__file__).resolve().parent.parent
    PlatformBuilder.cmake_dir = args.cmake_dir
    PlatformBuilder.llvm_dir = args.llvm_dir

    if not (project_root / "CMakeLists.txt").exists():
        logging.error("Please run this script in Dobby project root directory")
        sys.exit(1)

    if args.platform not in platforms:
        logging.error(f"Invalid platform {args.platform}")
        sys.exit(-1)

    target_archs = platforms[args.platform] if args.arch == "all" else [args.arch]
    
    last_builder = None
    for arch in target_archs:
        if args.platform in ["macos", "iphoneos"]:
            builder = DarwinPlatformBuilder(project_root, args.library_build_type, args.platform, arch)
        elif args.platform == "android":
            if not args.android_ndk_dir:
                logging.error("NDK dir is required for android")
                sys.exit(-1)
            builder = AndroidPlatformBuilder(args.android_ndk_dir, project_root, args.library_build_type, arch)
        elif args.platform == "linux":
            builder = LinuxPlatformBuilder(project_root, args.library_build_type, arch)
        else:
            continue
        
        logging.info(f"Building for {args.platform} ({arch})...")
        builder.build()
        last_builder = builder

    if args.platform in ["iphoneos", "macos"] and args.arch == "all" and last_builder:
        for out in [last_builder.shared_output_name, last_builder.static_output_name]:
            DarwinPlatformBuilder.lipo_create_fat(project_root, args.platform, out)