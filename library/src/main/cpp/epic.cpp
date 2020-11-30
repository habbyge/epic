/**
 * Original Copyright 2014-2015 Marvin Wißfeld
 * Modified work Copyright (c) 2017, weishu
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Android本身是裁减过的Linux,好些system call不能使用,另外由于没有采用glibc(用的是Bionic libc)
 * 好些函数所在的头文件位置也有变化，这都给移植工作带来困难。更为坑爹的是一些函数在头文件里能找到定义
 * 在具体库里确没有实现（比如：pthread_mutex_timedlock）. Android Native开发在编译链接阶段会遇
 * 到上述“惨痛”经历，但更为痛苦的是好不容易变成可执行文件，一运行就Crash没有任何信息。遇到这种情况，
 * 在排除了代码有低级错误的情况后，最终只能想办法做debug.
 * 
 * http://weishu.me/2017/11/23/dexposed-on-art/
 * 
 * ART有什么特别的？
 * 为什么Dexposed能够在Dalvik上为所欲为，到ART时代就不行了呢？排除其他非技术因素来讲，ART确实比
 * Dalvik复杂太多；更要命的是，从Android L到Android O，每一个Android版本中的ART变化都是天翻地
 * 覆的，大致列举一下：Android L(5.0/5.1) 上的ART是在Dalvik上的JIT编译器魔改过来的，名为quick
 * （虽然有个portable编译器，但是从未启用过）；这个编译器会做一定程度的方法内联，因此很多基于入口替
 * 换的Hook方式一上来就跪了。Android M(6.0) 上的ART编译器完全重新实现了：Optimizing。且不说之前
 * 在Android L上的Hook实现要在M上重新做一遍，这个编译器的寄存器分配比quick好太多，结果就是hook实
 * 现的时候你要是乱在栈或者寄存器上放东西，代码很容易就跑飞。Android N(7.0/7.1) N 开始采用了混合
 * 编译的方式，既有AOT也有JIT，还伴随着解释执行；混合模式对Hook影响是巨大的，以至于Xposed 直到今年
 * 才正式支持Android N。首先JIT的出现导致方法入口不固定，跑着跑着入口就变了，更麻烦的是还会有OSR
 * （栈上替换），不仅入口变了，正在运行时方法的汇编代码都可能发生变化；其次，JIT的引入带来了更深度的
 * 运行时方法内联，这些都使得虚拟机层面的Hook更为复杂。Android O(8.0) Android O的Runtime做了很
 * 多优化，传统Java VM有的一些优化手段都已经实现，比如类层次分析，循环优化，向量化等；除此之外，
 * DexCache被删除，跨dex方法内联以及Concurrent compacting GC 的引入，使得Hook技术变的扑朔迷离.
 * 可以看出，ART不仅复杂，而且还爱折腾；一言不合就魔改，甚至重写。再加上Android的碎片化，这使得实现
 * 一个稳定的虚拟机层面上运行时Java Method AOP几无可能。
 * 
 * 在ART中，每一个Java方法在虚拟机内部都由一个ArtMethod对象表示（Native层，实际上是一个C++对象）,
 * 这个native 的 ArtMethod对象包含了此Java方法的所有信息，比如名字，参数类型，方法本身代码的入口
 * 地址（entrypoint)等；暂时放下trampoline以及interpreter和jit不谈，一个Java方法的执行非常简单:
 * 1. 想办法拿到这个Java方法所代表的ArtMethod对象
 * 2. 取出其entrypoint，然后跳转到此处开始执行(所有entrypoint均指compiled_code_entry_point)
 * 
 * 从以上两点来看，一种很自然的Hook方案是: "直接替换entrypoint"，通过把原方法对应的ArtMethod对象
 * 的entrypoint替换为目标方法的entrypoint，可以使得原方法被调用过程中取entrypoint的时候拿到的是
 * 目标方法的entry，进而直接跳转到目标方法的.text段；从而达到Hook的目的。
 * 这也是 AndFix 的热补丁方案，Sophix 对这个方案做了一些改进，也即整体替换，不过原理上都一样。二者
 * 在替换方法之后把原方法直接丢弃，因此无法实现AOP。AndroidMethodHook 基于Sophix的原理，用
 * dexmaker动态生成类，将原方法保存下来，从而实现了AOP。
 * 
 * Epic基本原理:
 * 一个较为通用的Hook技术，几乎只有一条路———基于dynamic dispatch的
 * dynamic callee-side rewriting.
 * 
 * ARM汇编特点1: https://cloud.tencent.com/developer/article/1658622
 * 
 * 特点1：ARM采用RISC架构
 * CPU本身不能直接读取内存，而需要先将内存中内容加载入CPU中通用寄存器中才能被CPU
 * 处理：ldr（load register）将内存中的内容加载到通用寄存器中，str(store register)将进村器中的
 * 内容存储到内存空间中，ldr/str组合用来实现 ARM CPU和内存数据交换.
 * 
 * ARM汇编特点2：8种寻址方式。
 * 寄存器寻址    mov r1, r2 把r2寄存器的值加载到r1当中。
 * 立即寻址      mov r0, #0xFF00  将立即数的值赋给r0
 * 寄存器移位寻址 mov r0, r1, lsl #3 
 * 寄存器间接寻址 ldr r1, [r2]
 * 基址变址寻址   ldr r1, [r2, #4]
 * 多寄存器寻址  ldmia r1!, {r2-r7,r12}
 * 堆栈寻址      stmfd sp!, {r2-r7,lr}
 * 相对寻址      beqflag
 *
 * ARM汇编特点3：指令后缀。同一指令经常附带不同后缀，变成不同的指令。经常使用的后缀有：
 * B（byte）功能不变，操作长度变为8位
 * H（half word）功能不变，长度变为16位
 * S（signed）功能不变，操作数变为有符号，如 ldr ldrb ldrh ldrsb ldrsh
 * S（S标志）功能不变，影响CPSR标志位，如 mov和movs  movs r0, #0
 * 
 * ARM汇编特点4：多级指令流水线。为增加处理器指令流的速度，ARM使用多级流水线。所以要注意PC指向正被
 * 取指的指令，而非正在执行的指令。
 * 
 * cmp r0, r1  比较r0和r1寄存器值是否相等，若相等，会改变cpsr寄存器对应的零标志位
 * 跳转指令b、bl、bx
 * 
 * Arm汇编中的一些规则：https://www.jianshu.com/p/0277280d8e35
 * 栈与栈帧
 * 默认满栈降序规则，即PUSH先减后放，POP先取后加。
 * 栈帧寄存器指向函数前序期压栈保存寄存器前的栈底。一般先压LR后R11(FP),之后才申请栈上空间(即减SP)。
 * 结束时直接依据FP恢复LR以及上层FP。
 * 
 * 有必要说明一下ART中的函数的调用约定。以Thumb2为例，子函数调用的参数传递是通过寄存器r0~r3 以及sp
 * 寄存器完成的。r0 ~ r3 依次传递第一个至第4个参数，同时 sp, (sp + 4), (sp + 8), (sp + 12) 
 * 也存放着r0~r3上对应的值；多余的参数通过 sp传递，比如 *(sp + 16)放第四个参数，以此类推。同时，函
 * 数的返回值放在r0寄存器。如果一个参数不能在一个寄存器中放下，那么会占用2个或多个寄存器.
 * 
 * 在ART中，r0寄存器固定存放被调用方法的ArtMethod指针，如果是non-static 方法，r1寄存器存放方法的
 * this对象；另外，只有long/double 占用8bytes，其余所有基本类型和对象类型都占用4bytes。不过这只
 * 是基本情形，不同的ART版本对这个调用约定有不同的处理，甚至不完全遵循。
 * 
 * Arm的3个特殊寄存器: sp(r13)/lr(r14)/pc(r15)
 * sp：帧指针寄存器
 * lr: 连接寄存器 (1) 保存子程序返回地址；(2) 当异常发生时，异常模式的r14用来保存异常返回地址，将
 *     r14如栈可以处理嵌套中断
 * 程序计数器r15(pc)
 * 
 * trampoline2 蹦床函数
 */

#include <jni.h>
#include <android/log.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#include <dlfcn.h>
#include <cstdlib>
#include <sys/system_properties.h>
#include <fcntl.h>
#include "fake_dlfcn.h"
#include "art.h"

#undef NDEBUG
#ifdef NDEBUG
#define LOGV(...)  ((void)__android_log_print(ANDROID_LOG_INFO, \
        "epic.Native", __VA_ARGS__))
#else
#define LOGV(...)
#endif

#define JNIHOOK_CLASS "me/weishu/epic/art/EpicNative"

jobject (*addWeakGloablReference)(JavaVM*, void*, void*) = nullptr;

void* (*jit_load_)(bool*) = nullptr;
void* jit_compiler_handle_= nullptr;
bool (*jit_compile_method_)(void*, void*, void*, bool) = nullptr;

typedef bool (*JIT_COMPILE_METHOD1)(void*, void*, void*, bool);
// Android Q
typedef bool (*JIT_COMPILE_METHOD2)(void*, void*, void*, bool, bool); 

void (*jit_unload_)(void*) = nullptr;

class ScopedSuspendAll {
};

void (*suspendAll)(ScopedSuspendAll*, char*) = nullptr;
void (*resumeAll)(ScopedSuspendAll*) = nullptr;

class ScopedJitSuspend {
};

void (*startJit)(ScopedJitSuspend*) = nullptr;
void (*stopJit)(ScopedJitSuspend*) = nullptr;

void (*DisableMovingGc)(void*) = nullptr;

void* __self() {

#ifdef __arm__
    register uint32_t r9 asm("r9");
    return (void*) r9;
#elif defined(__aarch64__)
    register uint64_t x19 asm("x19");
    return (void*) x19;
#else
#endif

};

static int api_level;

/**
 * 核心方案：使用 linker(链接器)提供的<dlfcn.h>的函数库来打开so库文件，并索引到指定符号(函数符号)
 * 偏移处，然后直接调用改地址的函数符号，并传参即可。
 */
void init_entries(JNIEnv* env) {

    // 获取Android系统 SDK 版本：adb shell getprop ro.build.version.release 
    // 我的机器上返回: 10.
    // 获取Android系统 API 版本：adb shell getprop ro.build.version.sdk 我的机器上返回：29
    char api_level_str[5];
    __system_property_get("ro.build.version.sdk", api_level_str);

    api_level = atoi(api_level_str);
    LOGV("api level: %d", api_level);
    
    if (api_level < 23) {
        // RTLD_LAZY: 在dlopen()返回前，对于动态库中存在的未定义的变量(如外部变量extern，也可
        //  以是函数)不执行解析，就是不解析这个变量的地址。
        // RTLD_NOW：与上面不同，他需要在dlopen返回前，解析出每个未定义变量的地址，如果解析不出
        // 来，在dlopen会返回NULL，错误为: undefined symbol: xxxx.......
        // RTLD_GLOBAL: 它的含义是使得so库中的解析的定义变量在随后的其它的链接库中变得可以使用。

        // Android L: 
        // art::JavaVMExt::AddWeakGlobalReference(art::Thread*, art::mirror::Object*)
        void* handle = dlopen("libart.so", RTLD_LAZY | RTLD_GLOBAL);
        addWeakGloablReference = (jobject (*)(JavaVM*, void*, void*)) dlsym(handle, 
            "_ZN3art9JavaVMExt22AddWeakGlobalReferenceEPNS_6ThreadEPNS_6mirror6ObjectE");
    } else if (api_level < 24) {
        // Android M, art::JavaVMExt::AddWeakGlobalRef(art::Thread*, art::mirror::Object*)
        void* handle = dlopen("libart.so", RTLD_LAZY | RTLD_GLOBAL);
        addWeakGloablReference = (jobject (*)(JavaVM*, void*, void*)) dlsym(handle, 
                "_ZN3art9JavaVMExt16AddWeakGlobalRefEPNS_6ThreadEPNS_6mirror6ObjectE");
    } else {
        // Android N and O, Google disallow us use dlsym(google不允许使用dlsym()函数了)
        void* handle = dlopen_ex("libart.so", RTLD_NOW); 
        void* jit_lib = dlopen_ex("libart-compiler.so", RTLD_NOW);
        
        LOGV("fake dlopen install: %p", handle);

        const char* addWeakGloablReferenceSymbol = api_level <= 25 ? 
            "_ZN3art9JavaVMExt16AddWeakGlobalRefEPNS_6ThreadEPNS_6mirror6ObjectE" : 
            "_ZN3art9JavaVMExt16AddWeakGlobalRefEPNS_6ThreadENS_6ObjPtrINS_6mirror6ObjectEEE";

        addWeakGloablReference = (jobject (*)(JavaVM*, void*, void*)) dlsym_ex(
                handle, addWeakGloablReferenceSymbol);

        jit_compile_method_ = (bool (*)(void*, void*, void*, bool)) dlsym_ex(
                jit_lib, "jit_compile_method");

        jit_load_ = reinterpret_cast<void* (*)(bool*)>(dlsym_ex(jit_lib, "jit_load"));
        bool generate_debug_info = false;
        jit_compiler_handle_ = (jit_load_)(&generate_debug_info);
        LOGV("jit compile_method: %p", jit_compile_method_);

        suspendAll = reinterpret_cast<void(*)(ScopedSuspendAll*, char*)>(dlsym_ex(
                handle, "_ZN3art16ScopedSuspendAllC1EPKcb"));

        resumeAll = reinterpret_cast<void (*)(ScopedSuspendAll*)>(dlsym_ex(
                handle, "_ZN3art16ScopedSuspendAllD1Ev"));

        // Disable this now.
        // startJit = reinterpret_cast<void(*)(ScopedJitSuspend*)>(
        //      dlsym_ex(handle, "_ZN3art3jit16ScopedJitSuspendD1Ev"));
        // stopJit = reinterpret_cast<void(*)(ScopedJitSuspend*)>(dlsym_ex(
        //      handle, "_ZN3art3jit16ScopedJitSuspendC1Ev"));

        // DisableMovingGc = reinterpret_cast<void(*)(void*)>(dlsym_ex(handle,
        //      "_ZN3art2gc4Heap15DisableMovingGcEv"));
    }

    LOGV("addWeakGloablReference: %p", addWeakGloablReference);
}

jboolean epic_compile(JNIEnv* env, jclass, jobject method, jlong self) {
    LOGV("self from native peer: %p, from register: %p", 
        reinterpret_cast<void*>(self), __self());

    jlong art_method = (jlong) env->FromReflectedMethod(method);

    bool ret;
    if (api_level >= 29) {
        ret = ((JIT_COMPILE_METHOD2) jit_compile_method_)(jit_compiler_handle_,
                                                    reinterpret_cast<void*>(art_method),
                                                    reinterpret_cast<void*>(self), 
                                                    false, 
                                                    false);
    } else {
        ret = ((JIT_COMPILE_METHOD1) jit_compile_method_)(jit_compiler_handle_,
                                                    reinterpret_cast<void*>(art_method),
                                                    reinterpret_cast<void*>(self), 
                                                    false);
    }
    return (jboolean) ret;
}

jlong epic_suspendAll(JNIEnv*, jclass) {
    ScopedSuspendAll* scopedSuspendAll = (ScopedSuspendAll*) 
            malloc(sizeof(ScopedSuspendAll));

    suspendAll(scopedSuspendAll, "stop_jit");
    return reinterpret_cast<jlong>(scopedSuspendAll);
}

void epic_resumeAll(JNIEnv* env, jclass, jlong obj) {
    ScopedSuspendAll* scopedSuspendAll = reinterpret_cast<ScopedSuspendAll*>(obj);
    resumeAll(scopedSuspendAll);
}

jlong epic_stopJit(JNIEnv*, jclass) {
    ScopedJitSuspend* scopedJitSuspend = (ScopedJitSuspend*) 
            malloc(sizeof(ScopedJitSuspend));

    stopJit(scopedJitSuspend);
    return reinterpret_cast<jlong >(scopedJitSuspend);
}

void epic_startJit(JNIEnv*, jclass, jlong obj) {
    ScopedJitSuspend* scopedJitSuspend = reinterpret_cast<ScopedJitSuspend*>(obj);
    startJit(scopedJitSuspend);
}

void epic_disableMovingGc(JNIEnv* env, jclass, jint api) {
    void* heap = getHeap(env, api);
    DisableMovingGc(heap);
}

jboolean epic_munprotect(JNIEnv* env, jclass, jlong addr, jlong len) {
    long pagesize = sysconf(_SC_PAGESIZE); // 页大小
    unsigned alignment = (unsigned) ((unsigned long long) addr % pagesize);
    LOGV("munprotect page size: %d, alignment: %d", pagesize, alignment);

    int i = mprotect((void*) (addr - alignment), (size_t)(alignment + len),
                     PROT_READ | PROT_WRITE | PROT_EXEC); // 读/写/执行权限
    if (i == -1) {
        LOGV("mprotect failed: %s (%d)", strerror(errno), errno);
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

jboolean epic_cacheflush(JNIEnv* env, jclass, jlong addr, jlong len) {
#if defined(__arm__)
    int i = cacheflush(addr, addr + len, 0);
    LOGV("arm cacheflush for, %ul", addr);
    if (i == -1) {
        LOGV("cache flush failed: %s (%d)", strerror(errno), errno);
        return JNI_FALSE;
    }
#elif defined(__aarch64__)
    char* begin = reinterpret_cast<char*>(addr);
    __builtin___clear_cache(begin, begin + len);
    LOGV("aarch64 __builtin___clear_cache, %p", (void*)begin);
#endif
    return JNI_TRUE;
}

void epic_memcpy(JNIEnv* env, jclass, jlong src, jlong dest, jint length) {
    char* srcPnt = (char*) src;
    char* destPnt = (char*) dest;
    for (int i = 0; i < length; ++i) {
        destPnt[i] = srcPnt[i];
    }
}

void epic_memput(JNIEnv* env, jclass, jbyteArray src, jlong dest) {
    jbyte* srcPnt = env->GetByteArrayElements(src, 0);
    jsize length = env->GetArrayLength(src);
    unsigned char* destPnt = (unsigned char*) dest;
    for (int i = 0; i < length; ++i) {
        // LOGV("put %d with %d", i, *(srcPnt + i));
        destPnt[i] = (unsigned char) srcPnt[i];
    }
    env->ReleaseByteArrayElements(src, srcPnt, 0);
}

jbyteArray epic_memget(JNIEnv* env, jclass, jlong src, jint length) {
    jbyteArray dest = env->NewByteArray(length);
    if (dest == NULL) {
        return NULL;
    }
    unsigned char* destPnt = (unsigned char*) env->GetByteArrayElements(dest, 0);
    unsigned char* srcPnt = (unsigned char*) src;
    for (int i = 0; i < length; ++i) {
        destPnt[i] = srcPnt[i];
    }
    env->ReleaseByteArrayElements(dest, (jbyte*) destPnt, 0);

    return dest;
}

jlong epic_mmap(JNIEnv* env, jclass, jint length) {
    
    void* space = mmap(0, (size_t) length, 
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS, 
                       -1, 0);

    if (space == MAP_FAILED) {
        LOGV("mmap failed: %d", errno);
        return 0;
    }
    return (jlong) space;
}

void epic_munmap(JNIEnv* env, jclass, jlong addr, jint length) {
    int r = munmap((void*) addr, (size_t) length);
    if (r == -1) {
        LOGV("munmap failed: %d", errno);
    }
}

jlong epic_malloc(JNIEnv* env, jclass, jint size) {
    size_t length = sizeof(void*) * size;
    void* ptr = malloc(length);
    LOGV("malloc :%d of memory at: %p", (int) length, ptr);
    return (jlong) ptr;
}


jobject epic_getobject(JNIEnv* env, jclass clazz, jlong self, jlong address) {
    JavaVM* vm;
    env->GetJavaVM(&vm);
    LOGV("java vm: %p, self: %p, address: %p", vm, (void*) self, (void*) address);

    jobject object = addWeakGloablReference(vm, (void*) self, (void*) address);
    return object;
}

jlong epic_getMethodAddress(JNIEnv* env, jclass clazz, jobject method) {
    jlong art_method = (jlong) env->FromReflectedMethod(method);
    return art_method;
}

jboolean epic_isGetObjectAvaliable(JNIEnv*, jclass) {
    return (jboolean) (addWeakGloablReference != nullptr);
}

jlong pc, jlong sizeOfDirectJump,

jboolean epic_activate(JNIEnv* env, jclass jclazz, 
                       jlong jumpToAddress, 
                       jlong sizeOfBridgeJump, 
                       jbyteArray code) {

    // fetch the array, we can not call this when thread suspend(may lead deadlock)
    // 获取Java层的字节数组：code，转换为JNI能用的字节数组 和 长度
    jbyte* srcPnt = env->GetByteArrayElements(code, JNI_FALSE);
    jsize length = env->GetArrayLength(code);

    jlong cookie = 0;
    bool isNougat = api_level >= 24;
    if (isNougat) {
        // We do thus things:
        // 1. modify the code mprotect
        // 2. modify the code

        // Ideal, this two operation must be atomic. Below N, this is safe, 
        // because no one modify the code except ourselves;
        // But in Android N, When the jit is working, between our step 1 and step 2,
        // if we modity the mprotect of the code, and planning to write the code,
        // the jit thread may modify the mprotect of the code meanwhile
        // we must suspend all thread to ensure the atomic operation.

        LOGV("suspend all thread.");
        cookie = epic_suspendAll(env, jclazz);
    }

    jboolean result = epic_munprotect(env, jclazz, jumpToAddress, sizeOfDirectJump);
    if (result) {
        unsigned char* destPnt = (unsigned char*) jumpToAddress;

        for (int i = 0; i < length; ++i) {
            destPnt[i] = (unsigned char) srcPnt[i];
        }
        jboolean ret = epic_cacheflush(env, jclazz, pc, sizeOfBridgeJump);
        if (!ret) {
            LOGV("cache flush failed!!");
        }
    } else {
        LOGV("Writing hook failed: Unable to unprotect memory at %d", jumpToAddress);
    }

    if (cookie != 0) {
        LOGV("resume all thread.");
        epic_resumeAll(env, jclazz, cookie);
    }

    env->ReleaseByteArrayElements(code, srcPnt, 0);
    return result;
}

static JNINativeMethod dexposedMethods[] = {
    {
        "mmap",                 
        "(I)J",                           
        (void*) epic_mmap
    },
    {
        "munmap",               
        "(JI)Z",                          
        (void*) epic_munmap
    },
    {
        "memcpy",               
        "(JJI)V",                         
        (void*) epic_memcpy
    },
    {
        "memput",               
        "([BJ)V",                         
        (void*) epic_memput
    },
    {
        "memget",               
        "(JI)[B",                         
        (void*) epic_memget
    },
    {
        "munprotect",           
        "(JJ)Z",                          
        (void*) epic_munprotect
    },
    {
        "getMethodAddress",     
        "(Ljava/lang/reflect/Member;)J",  
        (void*) epic_getMethodAddress
    },
    
    {
        "cacheflush",           
        "(JJ)Z",                          
        (void*) epic_cacheflush
    },
    {
        "malloc",               
        "(I)J",                           
        (void*) epic_malloc
    },
    {
        "getObjectNative",      
        "(JJ)Ljava/lang/Object;",         
        (void*) epic_getobject
    },
    {
        "compileMethod",        
        "(Ljava/lang/reflect/Member;J)Z", 
        (void*) epic_compile
    },
    {
        "suspendAll",           
        "()J",                            
        (void*) epic_suspendAll
    },
    {
        "resumeAll",            
        "(J)V",                           
        (void*) epic_resumeAll
    },
    {
        "stopJit",              
        "()J",                            
        (void*) epic_stopJit
    },
    {
        "startJit",             
        "(J)V",                           
        (void*) epic_startJit
    },
    {
        "disableMovingGc",      
        "(I)V",                           
        (void*) epic_disableMovingGc
    },
    {
        "activateNative",       
        "(JJJJ[B)Z",                      
        (void*) epic_activate
    },
    {
        "isGetObjectAvailable", 
        "()Z",                            
        (void*) epic_isGetObjectAvaliable
    }
};

static int registerNativeMethods(JNIEnv* env, 
                                 const char* className,
                                 JNINativeMethod* gMethods, 
                                 int numMethods) {

    jclass clazz = env->FindClass(className);
    if (clazz == NULL) {
        return JNI_FALSE;
    }
    if (env->RegisterNatives(clazz, gMethods, numMethods) < 0) {
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    JNIEnv* env = NULL;

    LOGV("JNI_OnLoad");

    if (vm->GetEnv((void**) &env, JNI_VERSION_1_6) != JNI_OK) {
        return -1;
    }

    if (!registerNativeMethods(env, JNIHOOK_CLASS, dexposedMethods,
            sizeof(dexposedMethods) / sizeof(dexposedMethods[0]))) {
                
        return -1;
    }

    init_entries(env);

    return JNI_VERSION_1_6;
}
