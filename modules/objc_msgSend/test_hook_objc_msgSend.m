/**
 *    Copyright 2017 jmpews
 * 
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 * 
 *        http://www.apache.org/licenses/LICENSE-2.0
 * 
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#import <Foundation/Foundation.h>
#import <objc/message.h>
@interface TestClass : NSObject
- (void)test_msgSend:(int)a: (int)b: (int)c: (int)d: (int)e: (int)f: (int)g: (int)h: (int)k;
@end

@implementation TestClass
- (void)test_msgSend:(int)a :(int)b :(int)c :(int)d :(int)e :(int)f :(int)g :(int)h :(int)k {
    printf("%d, %d, %d, %d, %d, %d, %d, %d, %d", a, b, c, d, e, f, g, h, k);
}
@end

int main(int argc, const char * argv[])
{
  @autoreleasepool
  {
    TestClass *t = [TestClass new];
    SEL sel = @selector(test_msgSend:::::::::);
    ((void (*)(id, SEL, int, int, int, int, int, int, int, int, int))objc_msgSend)(t, sel, 1, 2, 3, 4, 5, 6, 7, 8, 9);
    [t test_msgSend:1 :2 :3 :4 :5 :6 :7 :8 :9];
  }
  return 0;
}