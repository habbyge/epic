//
// Created by 葛祥林 on 2021/4/28.
//

#ifndef EPIC_EPIC_H
#define EPIC_EPIC_H

// art/compiler/jit/jit_compiler.cc
// todo ------------------------------ jit load ------------------------------
// 5.0/5.1没有提供jit编译接口
static const char* jit_load_SYM = "jit_load";
using jit_load_6 = void* (*)(void**); // extern "C" void* jit_load(CompilerCallbacks** callbacks)
using jit_load_7_8_9 = void* (*)(bool*); // xtern "C" void* jit_load(bool* generate_debug_info)
using jit_load_10_11 = void* (*)(); // 返回 JitCompiler* const jit_compiler()

static void* jit_compiler_handle_ = nullptr; // 即: JitCompiler*，也就是jit执行器对象

// todo ------------------------------ jit compile ------------------------------
// 5.0/5.1没有提供jit编译接口
static const char* CompileMethod_SYM_6_10 = "jit_compile_method";
// bool jit_compile_method(void* handle, ArtMethod* method, Thread* self)
using jit_compile_method_6 = bool (*)(void*, void*, void*);
// bool jit_compile_method(void* handle, ArtMethod* method, Thread* self, bool osr)
using jit_compile_method_7_8_9 = bool (*)(void*, void*, void*, bool);
// bool jit_compile_method(void* handle, ArtMethod* method, Thread* self, bool baseline, bool osr)
using JIT_COMPILE_METHOD_10 = bool (*)(void*, void*, void*, bool, bool); // Android 10

// bool CompileMethod(Thread* self, JitMemoryRegion* region, ArtMethod* method, bool baseline, bool osr)
static const char* CompileMethod_SYM_11 = "_ZN3art3jit11JitCompiler13CompileMethodEPNS_6ThreadEPNS0_15JitMemoryRegionEPNS_9ArtMethodEbb";
using jit_compile_method_11 = bool (*)(void*, void*, void*, void*, bool, bool); // 第1个参数是: this

// 只支持: 6.0
class CompilerCallbacks {
public:
  enum class CallbackMode {  // private
    kCompileBootImage,
    kCompileApp
  };

  virtual ~CompilerCallbacks() { }

private:
  // Whether the compiler is creating a boot image.
  const CallbackMode mode_;
};

#endif //EPIC_EPIC_H
