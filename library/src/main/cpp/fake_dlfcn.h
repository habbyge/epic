// Copyright (c) 2016 avs333
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
//		of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
//		to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//		copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
//		The above copyright notice and this permission notice shall be included in all
//		copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// 		AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

/**
 * Java中的System.loadLibrary(libName)，会调用到 binoc/linker.cc 中的 linker.cc 的 do_dlopen()，
 * 本质上是 #include <fcntl.h> 中的 dlopen()等系列函数，这里实际上给我的启示是 读取so文件可以直接使用
 * fcntl.h 中的函数(android_namespace_t是在Android7.0及以后引入的命名空间机制，它把应用层的共享库与系
 * 统层的共享库区分开来，并限制对部分系统方法的访问)，do_dlopen()会调用find_library()来查找和加载so，并
 * 返回 soinfo结构体，本质是调用 <fcntl.h> 中的 dlopen(const char* soPathName, int mode)，返回void*，
 * 就是指向 struct soinfo的指针，soinfo->call_constructors() 表示在手动显式的加载so时，加载完成后系
 * 统会调用其指定的构造函数，这个调用会比JNI_OnLoad更早，其指定方式是在函数前加上属性:
 * __attribute__((constructor))。
 */
#ifndef DEXPOSED_DLFCN_H
#define DEXPOSED_DLFCN_H

#include <cstdlib>
#include <string.h>
#include <unistd.h>

extern "C" {

void* dlopen_ex(const char* filename, int flags);
void* dlsym_ex(void* handle, const char* symbol);
int dlclose_ex(void* handle);
const char* dlerror_ex();

} // extern "C"

#endif // DEXPOSED_DLFCN_H
