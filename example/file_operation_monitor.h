//
//  YourHackL1b.hpp
//  HookExample
//
//  Created by jmpews on 2019/3/25.
//  Copyright © 2019 jmpews. All rights reserved.
//

#ifndef YourHackL1b_hpp
#define YourHackL1b_hpp

#include <stdio.h>

extern "C" {
extern int DobbyHook(void *function_address, void *replace_call, void **origin_call);
}

#endif /* YourHackL1b_hpp */
