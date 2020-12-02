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

//fork from https://github.com/avs333/Nougat_dlfunctions
//do some modify
//support all cpu abi such as x86, x86_64
//support filename search if filename is not start with '/'

/**
 * fake_dlopen()与fake_dlsym()可以代替dlopen()与dlsym()来使用，它的原理是在当前进程的内存中，
 * 搜索符号表的方式，在内存中找到函数的内存地址。当然，它是有限制的：只能dlopen()已经加载进入内存
 * 的so，即系统或自己预先加载的动态库，并且参数flags加载标志被忽略。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <elf.h>
#include <dlfcn.h>
#include <sys/system_properties.h>
#include <android/log.h>

#define TAG_NAME    "dlfcn_ex"

#ifdef LOG_DBG
    #define log_info(fmt, args...) __android_log_print(ANDROID_LOG_INFO, \
                                                       TAG_NAME,         \
                                                       (const char*) fmt, ##args)

    #define log_err(fmt, args...) __android_log_print(ANDROID_LOG_ERROR, \
                                                      TAG_NAME,          \
                                                      (const char *) fmt, ##args)
    #define log_dbg log_info
#else
    #define log_dbg(...)
    #define log_info(fmt, args...)
    #define log_err(fmt, args...)
#endif

#ifdef __LP64__
    #define Elf_Ehdr Elf64_Ehdr
    #define Elf_Shdr Elf64_Shdr
    #define Elf_Sym  Elf64_Sym
#else
    #define Elf_Ehdr Elf32_Ehdr
    #define Elf_Shdr Elf32_Shdr
    #define Elf_Sym  Elf32_Sym
#endif


/**
 * 加载 Elf 文件到mmap后，解析后的结果
 */
typedef struct ctx {
    void* load_addr; // so库文件加载到进程中的基地址，来自 /proc/pid/maps
    
    void* dynstr;    // 名称字符串表(Section)

    void* dynsym;    // 符号表(Section)
    int nsyms;       // 符号表中的符号item条数
    
    off_t bias;      // 是节头表在进程地址空间中的基地址 TODO: 这个字段是啥?
} ctx_t;

extern "C" {

static int fake_dlclose(void* handle) {
    if (handle) {
        ctx_t* ctx = (ctx_t*) handle;
        if (ctx->dynsym) {
            free(ctx->dynsym);    /* we're saving dynsym and dynstr */
        }
        if (ctx->dynstr) {
            free(ctx->dynstr);    /* from library file just in case */
        }
        free(ctx);
    }
    return 0;
}

/** 
 * 缺点: flags are ignored
 * 
 * API>=24的Android系统，Goole限制不能使用dl库，那么可以通过 /proc/pid/maps 文件，
 * 来查找到对应so库文件，被加载到该进程中的基地址，从而把该文件使用mmap()映射到内存中，
 * 再进行解析，获取so库(ELF)中的符号表类型的节、字符串类型的节，打包成 struct ctx 返回
 */
static void* fake_dlopen_with_path(const char* libpath, int flags) {
    FILE* maps;
    char buff[256];
    ctx_t* ctx = 0;
    off_t load_addr, size;
    int i, fd = -1, found = 0;
    char* shoff;

    // ELF文件头，这里是把so库文件使用 mmap() 系统调用，映射到这个地址
    Elf_Ehdr* elf = (Elf_Ehdr*) MAP_FAILED; // reinterpret_cast<void*>(-1)

#define fatal(fmt, args...) do {    \
            log_err(fmt,##args);    \
            goto err_exit;          \
        } while(0)

    maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        fatal("failed to open maps");
    }

    // 查找到 libpath 这个so库的行
    while (!found && fgets(buff, sizeof(buff), maps)) {
        if (strstr(buff, libpath) && (strstr(buff, "r-xp") || strstr(buff, "r--p"))) {
            found = 1;
        }
    }
    fclose(maps);

    if (!found) {
        fatal("%s not found in my userspace", libpath);
    }

    if (sscanf(buff, "%lx", &load_addr) != 1) {
        fatal("failed to read load address for %s", libpath);
    }

    log_info("%s loaded in Android at 0x%08lx", libpath, load_addr);

    // Now, mmap the same library once again

    fd = open(libpath, O_RDONLY);
    if (fd < 0) {
        fatal("failed to open %s", libpath);
    }
    size = lseek(fd, 0, SEEK_END); // 索引到so库文件末尾
    if (size <= 0) {
        fatal("lseek() failed for %s", libpath);
    }

    // mmap()是Linux/Unix的系统调用，映射文件或设备到内存中，取消映射就是munmap()函数.
    // - 该函数主要用途有三个：
    // 1. 将普通文件映射到内存中，通常在需要对文件进行频繁读写时使用，用内存读写取代I/O读写，
    //    以获得较高的性能；
    // 2. 将特殊文件进行匿名内存映射，为关联进程提供共享内存空间；
    // 3. 为无关联的进程间的Posix共享内存（SystemV的共享内存操作是shmget/shmat）
    // - 参数addr：
    // 指向欲映射的内存起始地址，通常设为 NULL，代表让系统自动选定地址，映射成功后返回该地址。
    // - 参数length：
    // 代表将文件中多大的部分映射到内存。
    // - 参数prot：
    // 映射区域的保护方式。可以为以下几种方式的组合：
    // PROT_EXEC 映射区域可被执行
    // PROT_READ 映射区域可被读取
    // PROT_WRITE 映射区域可被写入
    // PROT_NONE 映射区域不能存取
    // - 参数flags：
    // 影响映射区域的各种特性。在调用mmap()时必须要指定 MAP_SHARED 或 MAP_PRIVATE。
    // MAP_FIXED 如果参数start所指的地址无法成功建立映射时，则放弃映射，不对地址做修正。
    //           通常不鼓励用此.
    // MAP_SHARED对映射区域的写入数据会复制回文件内，而且允许其他映射该文件的进程共享。
    // MAP_PRIVATE 对映射区域的写入操作会产生一个映射文件的复制，即私人的“写入时复制”
    //            （copy on write）对此区域作的任何修改都不会写回原来的文件内容。
    // MAP_ANONYMOUS 建立匿名映射。此时会忽略参数fd，不涉及文件，而且映射区域无法和其他进程共享。
    // MAP_DENYWRITE 只允许对映射区域的写入操作，其他对文件直接写入的操作将会被拒绝。
    // MAP_LOCKED 将映射区域锁定住，这表示该区域不会被置换（swap）。
    // - 参数fd：
    // 要映射到内存中的文件描述符。如果使用匿名内存映射时，即flags中设置了MAP_ANONYMOUS，fd设为-1
    // - 参数offset：
    // 文件映射的偏移量，通常设置为0，代表从文件最前方开始对应，offset必须是分页大小的整数倍
    elf = (Elf_Ehdr*) mmap(0, size, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    fd = -1; // 安全防御性编程，防止fd被滥用，导致的一些未定义行为
    if (elf == MAP_FAILED) {
        fatal("mmap() failed for %s", libpath);
    }

    ctx = (cgx_t*) calloc(1, sizeof(ctx_t));
    if (!ctx) {
        fatal("no memory for %s", libpath);
    }

    ctx->load_addr = (void*) load_addr;   // so库加载到该进程中的基地址
    shoff = ((char*) elf) + elf->e_shoff; // 节头表偏移量

    // 遍历节头表(Section Header Table)
    for (i = 0; i < elf->e_shnum; i++, shoff += elf->e_shentsize) {
        Elf_Shdr* sh = (Elf_Shdr*) shoff; // 节头
        log_dbg("%s: i=%d shdr=%p type=%x", __func__, i, sh, sh->sh_type);

        switch (sh->sh_type) {
        case SHT_DYNSYM: { // 符号表 .dynsym
            if (ctx->dynsym) {
                fatal("%s: duplicate DYNSYM sections", libpath); /* .dynsym */
            }
            ctx->dynsym = malloc(sh->sh_size);
            if (!ctx->dynsym) {
                fatal("%s: no memory for .dynsym", libpath);
            }
            memcpy(ctx->dynsym, ((char*) elf) + sh->sh_offset, sh->sh_size);
            ctx->nsyms = (sh->sh_size / sizeof(Elf_Sym));
        }
        break;

        case SHT_STRTAB: { // 字符串(名字)表 .dynstr
            if (ctx->dynstr) {
                break;    /* .dynstr is guaranteed to be the first STRTAB */
            }
            ctx->dynstr = malloc(sh->sh_size);
            if (!ctx->dynstr) {
                fatal("%s: no memory for .dynstr", libpath);
            }
            memcpy(ctx->dynstr, ((char*) elf) + sh->sh_offset, sh->sh_size);
        }
        break;

        case SHT_PROGBITS: {
            if (!ctx->dynstr || !ctx->dynsym) {
                break;
            }
            // won't even bother checking against the section name
            // - sh_addr: 该节在ELF文件被加载到进程地址空间中后的偏移量，其在进程中的真实地址是:
            // load_addr+sh->sh_addr.
            // - sh_offset 在elf文件中的偏移量
            ctx->bias = (off_t) sh->sh_addr - (off_t) sh->sh_offset;
            i = elf->e_shnum;  /* exit for */
        }
        break;

        }
    }

    munmap(elf, size); // 释放elf在mmap空间的映射
    elf = 0;

    if (!ctx->dynstr || !ctx->dynsym) {
        fatal("dynamic sections not found in %s", libpath);
    }

#undef fatal
    log_dbg("%s: ok, dynsym = %p, dynstr = %p", libpath, ctx->dynsym, ctx->dynstr);
    return ctx;

err_exit:
    if (fd >= 0) {
        close(fd);
    }
    if (elf != MAP_FAILED) {
        munmap(elf, size);
    }
    fake_dlclose(ctx);
    return 0;
}


#if defined(__LP64__)
    static const char *const kSystemLibDir = "/system/lib64/";
    static const char *const kOdmLibDir = "/odm/lib64/";
    static const char *const kVendorLibDir = "/vendor/lib64/";
    static const char *const kApexLibDir = "/apex/com.android.runtime/lib64/";
#else
    static const char* const kSystemLibDir = "/system/lib/";
    static const char* const kOdmLibDir = "/odm/lib/";
    static const char* const kVendorLibDir = "/vendor/lib/";
    static const char* const kApexLibDir = "/apex/com.android.runtime/lib/";
#endif

/**
 * 由于google限制了 api>=24 以上的Android系统使用dlfcn.h库，所以这里做特殊处理
 */
static void* fake_dlopen(const char* filename, int flags) {
    if (strlen(filename) > 0 && filename[0] == '/') { // so库的完整路径
        return fake_dlopen_with_path(filename, flags);
    } else { // so库的非完整路径
        char buf[512] = {0};
        void* handle = NULL;
        // sysmtem
        strcpy(buf, kSystemLibDir);
        strcat(buf, filename); // 生成so库完整路径
        handle = fake_dlopen_with_path(buf, flags);
        if (handle) {
            return handle;
        }

        // apex
        memset(buf, 0, sizeof(buf));
        strcpy(buf, kApexLibDir);
        strcat(buf, filename);
        handle = fake_dlopen_with_path(buf, flags);
        if (handle) {
            return handle;
        }

        // odm
        memset(buf, 0, sizeof(buf));
        strcpy(buf, kOdmLibDir);
        strcat(buf, filename);
        handle = fake_dlopen_with_path(buf, flags);
        if (handle) {
            return handle;
        }

        // vendor
        memset(buf, 0, sizeof(buf));
        strcpy(buf, kVendorLibDir);
        strcat(buf, filename);
        handle = fake_dlopen_with_path(buf, flags);
        if (handle) {
            return handle;
        }

        return fake_dlopen_with_path(filename, flags);
    }
}

/**
 * 从 符号表(节) 中获取 name 指定的符号，这里需要注意的是：
 * 1. 符号表中的 sym->st_name 字段不仅仅是一个字符串名称，还是一个index，该位置对应的就是符号名称.
 * 2. sym->st_value 字段表示的是该字符对应的地址偏移.
 */
static void* fake_dlsym(void* handle, const char* name) {
    int i;
    ctx_t* ctx = reinterpret_cast<ctx_t*>(handle);
    Elf_Sym* sym = reinterpret_cast<Elf_Sym*>(ctx->dynsym);
    char* strings = reinterpret_cast<char*>(ctx->dynstr);

    for (i = 0; i < ctx->nsyms; ++i, ++sym) { // 遍历符号表
        if (strcmp(strings + sym->st_name, name) == 0) { // 找到该符号(函数符号)
            // NB: sym->st_value is an offset into the section for relocatables,
            // but a VMA for shared libs or exe files, so we have to subtract 
            // the bias.
            // 在so库或可执行文件中，sym->st_value 表示符号的地址
            // ctx->bias = (off_t) sh->sh_addr - (off_t) sh->sh_offset
            void* ret = (char*) ctx->load_addr + sym->st_value - ctx->bias;
            log_info("%s found at %p", name, ret);
            return ret;
        }
    }
    return 0;
}


static const char* fake_dlerror() {
    return NULL;
}

// =============== implementation for compat ==========
static int SDK_INT = -1;

static int get_sdk_level() {
    if (SDK_INT > 0) {
        return SDK_INT;
    }
    char sdk[PROP_VALUE_MAX] = {0};;
    __system_property_get("ro.build.version.sdk", sdk);
    SDK_INT = atoi(sdk);
    return SDK_INT;
}

int dlclose_ex(void* handle) {
    if (get_sdk_level() >= 24) {
        return fake_dlclose(handle);
    } else {
        return dlclose(handle);
    }
}

/**
 * 返回的是 struct ctx 结构体
 */
void* dlopen_ex(const char* filename, int flags) {
    log_info("dlopen: %s", filename);
    if (get_sdk_level() >= 24) {
        return fake_dlopen(filename, flags);
    } else {
        return dlopen(filename, flags);
    }
}

void* dlsym_ex(void* handle, const char* symbol) {
    if (get_sdk_level() >= 24) {
        return fake_dlsym(handle, symbol);
    } else {
        return dlsym(handle, symbol);
    }
}

const char* dlerror_ex() {
    if (get_sdk_level() >= 24) {
        return fake_dlerror();
    } else {
        return dlerror();
    }
}

} // end of "extern "C""
