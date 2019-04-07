## Prologue

MachOSaticPatcher is a static hook tool which is based on HookZz.

## Usage

#### 0. Check the origin code signature

```
codesign --verify --verbose=3 /YourBinaryApp
```

#### 1. Remove the origin code signature.

```
codesign --remove-signature /YourBinaryApp
```

#### 2. Static initialize the app

insert the hook routing and stub placeholder.

```
./MachOStaticPatcher /YourBinaryApp/binary 0x100001000
```

#### 3. Resign the App

```
# dump the entitlements.plist
security cms -D -i /YourBinaryApp/embedded.mobileprovision > profile.plist
/usr/libexec/PlistBuddy -x -c 'Print :Entitlements' profile.plist > entitlements.plist

# force resign the app
codesign -f -s "iPhone Developer: Haolin Huang (5JBQ9SJ278)" --entitlements entitlements.plist /YourBinaryApp
```


#### 4. Add Runtime initialization library

the origin placeholder need to do rebase.


#### 5. install the App

drop the app to `Devices` -> `INSTALLED APPS` window.

## Epilogue

have fun.