// # 编译ARM版本
// clang -target arm64-apple-macos11 -dynamiclib -o inject_arm.dylib inject.m -framework Foundation

// # 编译x86_64版本
// clang -target x86_64-apple-macos11 -dynamiclib -o inject_x86.dylib inject.m -framework Foundation

// # 使用lipo创建通用二进制
// lipo -create inject_arm.dylib inject_x86.dylib -output inject.dylib -framework Foundation

#import <Foundation/Foundation.h>
#import <stdio.h>
#import <syslog.h>
#import <Cocoa/Cocoa.h>
#import <objc/runtime.h>




__attribute__((constructor))
static void customConstructor(void) {
    NSLog(@">>>>>> OC dylib loaded");
}

@implementation dylib_dobby_hook
@end
