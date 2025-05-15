
#include <stdio.h>
#include <syslog.h>

// # 编译ARM版本
// clang -target arm64-apple-macos11 -dynamiclib -o inject_arm.dylib inject.c

// # 编译x86_64版本
// clang -target x86_64-apple-macos11 -dynamiclib -o inject_x86.dylib inject.c

// # 使用lipo创建通用二进制
// lipo -create inject_arm.dylib inject_x86.dylib -output inject.dylib

__attribute__((constructor))
static void customConstructor(int argc, const char **argv)
 {
     printf(">>>>>>>> Hello from dylib!\n");
     syslog(LOG_ERR, ">>>>>>>> Dylib injection successful in %s\n", argv[0]);

}
