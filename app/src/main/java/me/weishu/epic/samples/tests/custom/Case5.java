package me.weishu.epic.samples.tests.custom;

import android.util.Log;
import android.widget.TextView;

import com.taobao.android.dexposed.utility.Unsafe;

import de.robv.android.xposed.DexposedBridge;
import de.robv.android.xposed.XC_MethodHook;
import me.weishu.epic.art.EpicNative;

/**
 * Created by weishu on 17/11/6.
 */
public class Case5 implements Case {
    private static final String TAG = "Case5";

    @Override
    public void hook() {
        DexposedBridge.findAndHookMethod(TextView.class, "setPadding",
                                         int.class, int.class, int.class, int.class,
                                         new XC_MethodHook() {

            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                if (param.thisObject != null) {
                    Log.i(TAG, "this:" + Long.toHexString(Unsafe.getObjectAddress(param.thisObject)));
                }
                if (param.method != null) {
                    Log.i(TAG, "mehod:" + Long.toHexString(EpicNative.getMethodAddress(param.method)));
                }
                if (param.args != null) {
                    for (Object arg : param.args) {
                        Log.i(TAG, "param:" + arg);
                        if (arg != null) {
                            Log.i(TAG, "<" + arg.getClass() + "> : 0x" + Long.toHexString(
                                    Unsafe.getObjectAddress(arg)) + ", value: " + arg);
                        } else {
                            Log.i(TAG, "param: null");
                        }
                    }
                }
            }

            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                super.afterHookedMethod(param);
                Log.i(TAG, "after");
            }
        });
    }

    @Override
    public boolean validate(Object... args) {
        return true;
    }
}
