/*
`xcrun --sdk iphoneos --find clang` \
-fPIC -shared -dynamiclib \
-arch arm64 \
-isysroot `xcrun --sdk iphoneos --show-sdk-path` \
solidifytrampoline.c \
-o  solidifytrampoline.dylib
*/
