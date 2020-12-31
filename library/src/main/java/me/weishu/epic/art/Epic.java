/*
 * Copyright (c) 2017, weishu
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package me.weishu.epic.art;

import android.os.Build;

import com.taobao.android.dexposed.utility.Debug;
import com.taobao.android.dexposed.utility.Logger;
import com.taobao.android.dexposed.utility.Runtime;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import me.weishu.epic.art.arch.Arm64;
import me.weishu.epic.art.arch.ShellCode;
import me.weishu.epic.art.arch.Thumb2;
import me.weishu.epic.art.method.ArtMethod;

/**
 * Hook Center.
 * 目前的 Android 热更新基本上是采用 "底层替换" 或者是 "类加载"，Sophix 则把这两者进行了结合.
 */
public final class Epic {
    private static final String TAG = "Epic";

    private static final Map<String, ArtMethod> backupMethodsMapping
            = new ConcurrentHashMap<>();

    private static final Map<Long, MethodInfo> originSigs = new ConcurrentHashMap<>();

    private static final Map<Long, Trampoline> scripts = new HashMap<>();
    private static ShellCode ShellCode;

    static {
        boolean isArm = true;
        int apiLevel = Build.VERSION.SDK_INT;
        boolean thumb2 = true;
        if (isArm) {
            if (Runtime.is64Bit()) {
                ShellCode = new Arm64();
            } else if (Runtime.isThumb2()) {
                ShellCode = new Thumb2();
            } else {
                thumb2 = false;
                ShellCode = new Thumb2();
                Logger.w(TAG, "ARM32, not support now.");
            }
        }
        if (ShellCode == null) {
            throw new RuntimeException("Do not support this ARCH now!! API LEVEL:"
                    + apiLevel + " thumb2 ? : " + thumb2);
        }
        Logger.i(TAG, "Using: " + ShellCode.getName());
    }

    public static void hookMethod(Constructor<?> origin) {
        hookMethod(ArtMethod.of(origin));
    }

    public static void hookMethod(Method origin) {
        ArtMethod artOrigin = ArtMethod.of(origin);
        hookMethod(artOrigin);
    }

    /**
     * 找到需要hook的java方法对应的C/C++层Art虚拟机中额方法对象：ArtMethod.
     */
    private static void hookMethod(ArtMethod artOrigin) {
        MethodInfo methodInfo = new MethodInfo();
        methodInfo.isStatic = Modifier.isStatic(artOrigin.getModifiers());
        final Class<?>[] parameterTypes = artOrigin.getParameterTypes();
        if (parameterTypes != null) {
            methodInfo.paramNumber = parameterTypes.length;
            methodInfo.paramTypes = parameterTypes;
        } else {
            methodInfo.paramNumber = 0;
            methodInfo.paramTypes = new Class<?>[0];
        }
        methodInfo.returnType = artOrigin.getReturnType();
        methodInfo.method = artOrigin;
        originSigs.put(artOrigin.getAddress(), methodInfo);

        if (!artOrigin.isAccessible()) {
            artOrigin.setAccessible(true);
        }

        // (3) 如果是静态方法，需要主动调用一下.
        // 因为静态方法是延迟解析的，主动调用可以保证ART完成静态方法的解析.
        // 在LinkCode时，静态方法的compiled_code入口点被设置为:art_quick_resolution_trampoline.
        // 这相当于  native inline hook.
        // 所以，如果静态方法的 compiled_code 入口点不对，那肯定 Hook 不成功.
        artOrigin.ensureResolved();

        // 如果要Hook的方法还未编译，则调用ArtMethod.compile主动进行编译
        // 和上面的原因一样，因为epic是 "dynamic callee-side rewriting"
        // 在Android N及以上系统中，APK安装时默认不会进行AOT编译.
        // 对于还未编译的方法，在LinkCode函数中会将其compile_code入口点设置为
        // GetQuickToInterpreterBridge, 这也是 art_quick_interpreter_bridge.
        // 如果要hook的目标方法还未编译，则调用 ArtMethod.compile()主动触发编译
        long originEntry = artOrigin.getEntryPointFromQuickCompiledCode();
        if (originEntry == ArtMethod.getQuickToInterpreterBridge()) {
            // compilePoint地址 与 interpretBridge 地址相同，说明还没有通过 jit 热编译.
            Logger.i(TAG, "this method is not compiled, compile it now " +
                    "current entry: 0x" + Long.toHexString(originEntry));

            // 如果要Hook的方法还未编译，则调 用ArtMethod.compile 主动进行编译，这么做也是因为 epic  是
            // “dynamic callee-side rewriting”。
            // ArtMethod.compile() 是通过调用JIT的jit_compile_method来完成方法编译的
            boolean ret = artOrigin.compile();
            if (ret) {
                originEntry = artOrigin.getEntryPointFromQuickCompiledCode();
                Logger.i(TAG, "compile method success, new entry: 0x" + Long.toHexString(originEntry));
            } else {
                Logger.e(TAG, "compile method failed...");
                return;
                // return hookInterpreterBridge(artOrigin);
            }
        }

        // 为原Method创建个备份，保存到 Epic.backupMethodsMapping中。
        // 这里原Method和备份得到的Method都是由ArtMethod对象表示
        // 之说以
        ArtMethod backupMethod = artOrigin.backup(); // TODO: ING

        Logger.i(TAG, "backup method address:" + Debug.addrHex(backupMethod.getAddress()));

        Logger.i(TAG, "backup method entry :" + Debug.addrHex(
                backupMethod.getEntryPointFromQuickCompiledCode()));

        ArtMethod backupList = getBackMethod(artOrigin);
        if (backupList == null) {
            setBackMethod(artOrigin, backupMethod);
        }

        final long key = originEntry;
        final EntryLock lock = EntryLock.obtain(originEntry);
        // noinspection SynchronizationOnLocalVariableOrMethodParameter
        synchronized (lock) {
            if (!scripts.containsKey(key)) {
                scripts.put(key, new Trampoline(ShellCode, originEntry));
            }
            Trampoline trampoline = scripts.get(key);
            // 安装跳板代码：完成hook
            boolean ret = trampoline.install(artOrigin);
            Logger.d(TAG, "hook Method result:" + ret);
            return;
        }
    }

    /*
    private static boolean hookInterpreterBridge(ArtMethod artOrigin) {
        String identifier = artOrigin.getIdentifier();
        ArtMethod backupMethod = artOrigin.backup();

        Logger.d(TAG, "backup method address:" +
                Debug.addrHex(backupMethod.getAddress()));
        Logger.d(TAG, "backup method entry :" +
                Debug.addrHex(backupMethod.getEntryPointFromQuickCompiledCode()));

        List<ArtMethod> backupList = backupMethodsMapping.get(identifier);
        if (backupList == null) {
            backupList = new LinkedList<ArtMethod>();
            backupMethodsMapping.put(identifier, backupList);
        }
        backupList.add(backupMethod);

        long originalEntryPoint = ShellCode.toMem(
                artOrigin.getEntryPointFromQuickCompiledCode());
        Logger.d(TAG, "originEntry Point(bridge):" + Debug.addrHex(originalEntryPoint));

        originalEntryPoint += 16;
        Logger.d(TAG, "originEntry Point(offset8):" + Debug.addrHex(originalEntryPoint));

        if (!scripts.containsKey(originalEntryPoint)) {
            scripts.put(originalEntryPoint, new Trampoline(ShellCode, artOrigin));
        }
        Trampoline trampoline = scripts.get(originalEntryPoint);

        boolean ret = trampoline.install();
        Logger.i(TAG, "hook Method result:" + ret);
        return ret;

    }*/

    public synchronized static ArtMethod getBackMethod(ArtMethod origin) {
        String identifier = origin.getIdentifier();
        return backupMethodsMapping.get(identifier);
    }

    public static synchronized void setBackMethod(ArtMethod origin, ArtMethod backup) {
        String identifier = origin.getIdentifier();
        backupMethodsMapping.put(identifier, backup);
    }

    public static MethodInfo getMethodInfo(long address) {
        return originSigs.get(address);
    }

    public static int getQuickCompiledCodeSize(ArtMethod method) {
        long entryPoint = ShellCode.toMem(method.getEntryPointFromQuickCompiledCode());
        long sizeInfo1 = entryPoint - 4;
        byte[] bytes = EpicNative.get(sizeInfo1, 4);
        int size = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
        Logger.d(TAG, "getQuickCompiledCodeSize: " + size);
        return size;
    }


    public static class MethodInfo {
        public boolean isStatic;
        public int paramNumber;
        public Class<?>[] paramTypes;
        public Class<?> returnType;
        public ArtMethod method;

        @Override
        public String toString() {
            return method.toGenericString();
        }
    }

    private static class EntryLock {
        static Map<Long, EntryLock> sLockPool = new HashMap<>();

        static synchronized EntryLock obtain(long entry) {
            if (sLockPool.containsKey(entry)) {
                return sLockPool.get(entry);
            } else {
                EntryLock entryLock = new EntryLock();
                sLockPool.put(entry, entryLock);
                return entryLock;
            }
        }
    }
}
