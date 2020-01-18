# Getting Started With iOS

available build option within iOS:

```
Plugin.HideLibrary=ON, enable the hidden library plugin

Plugin.ObjectiveC=ON, enable the objective-c toolkit
```

## Add Dobby.framework to your project

```
cmake .. -G Xcode \
-DCMAKE_BUILD_TYPE=Release \
-DCMAKE_TOOLCHAIN_FILE=cmake/ios.toolchain.cmake \
-DPLATFORM=OS64 \
-DARCHS=arm64 \
-DENABLE_BITCODE=1 \
-DENABLE_ARC=0 \
-DENABLE_VISIBILITY=1 \
-DDEPLOYMENT_TARGET=9.3 \
-DCMAKE_SYSTEM_PROCESSOR=aarch64 \
-DDynamicBinaryInstrument=ON -DNearBranchTrampoline=ON \
-DPlugin.FindSymbol=ON -DPlugin.HideLibrary=ON -DPlugin.ObjectiveC=ON
```

**drag the `Dobby.xcodeproj` to your project**

## Hide your library

invoke `DobbyHideLibrary("Dobby");` will delete the image record in the `dyld::allimageinfos`

## Objective-C Toolkit

invoke `DobbyOCReturnConstant("XXClass", "isVip", true);` will hook the objective-c instance/class method, and return the constant 1 automatically.
