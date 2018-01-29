//    Copyright 2017 jmpews
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

#include "MachoFD.h"
using namespace std;
int main(int argc, const char **argv)
{
    string target_file_path = "/Users/jmpews/Desktop/test/test.dylib";
    MachoFD *machofd = new MachoFD(target_file_path.c_str());
    machofd->parse_macho();
}