#!/bin/sh

AppPath=/Users/jmpews/Library/Developer/Xcode/DerivedData/MachOStaitcPatcherExample-dvodqyfyhehjjfczhvfngijycnew/Build/Products/Debug-iphoneos/MachOStaitcPatcherExample.app

security cms -D -i ${AppPath}/embedded.mobileprovision > profile.plist

/usr/libexec/PlistBuddy -x -c "Print :Entitlements" profile.plist > entitlements.plist

codesign --verify --verbose=3 ${AppPath}

codesign --remove-signature ${AppPath}

/Users/jmpews/project/HookZz/Plugins/MachOStaticPatcher/build/Debug/MachOStaticPatcher ${AppPath}/MachOStaitcPatcherExample 0x100006a98

chmod 755 ${AppPath}/MachOStaitcPatcherExample_modified

mv ${AppPath}/MachOStaitcPatcherExample_modified ${AppPath}/MachOStaitcPatcherExample

codesign -f -s "iPhone Developer: Haolin Huang (xxxxx)" --entitlements entitlements.plist ${AppPath}