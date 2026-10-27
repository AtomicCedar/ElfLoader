/*
 * Copyright (C) 2024 Eirv
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

package io.github.eirv.elfloader;

import android.annotation.SuppressLint;
import android.os.Build;
import android.system.ErrnoException;
import android.system.Os;

import sun.misc.Unsafe;

import java.io.FileDescriptor;
import java.io.InterruptedIOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.io.BufferedReader;
import java.io.FileReader;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public class ElfLoader {
    private static final int JNI_ERR = -1;
    private static final int JNI_VERSION_1_2 = 0x00010002;
    private static final int JNI_VERSION_1_4 = 0x00010004;
    private static final int JNI_VERSION_1_6 = 0x00010006;
    private static final int SHELLCODE_SIZE = 0x200;
    private static final int ANDROID_DLEXT_USE_LIBRARY_FD = 0x10;

    private static final Unsafe theUnsafe;
    private static final Field artMethodField;
    private static final Method nativeMethod;
    private static ElfLoader instance;

    static {
        Field field = null;
        try {
            var executableClass = Method.class.getSuperclass();
            assert executableClass != null;
            field = executableClass.getDeclaredField("artMethod");
            field.setAccessible(true);
        } catch (ReflectiveOperationException ignored) {
        }
        artMethodField = field;

        try {
            nativeMethod = ElfLoader.class.getDeclaredMethod("a");

            @SuppressLint("DiscouragedPrivateApi")
            var theUnsafeField = Unsafe.class.getDeclaredField("theUnsafe");
            theUnsafeField.setAccessible(true);
            var u = (Unsafe) theUnsafeField.get(null);
            assert u != null;
            theUnsafe = u;
        } catch (ReflectiveOperationException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private long mmapAddress;
    private int extinfoFdOffset;
    private int extinfoFlagsOffset;
    private int entrySlotOffset;
    private int entryNameOffset;
    private int libraryNameOffset;
    private boolean libraryFd;
    private final HashMap<String, LoadedLibrary> loadedLibraries = new HashMap<>();

    private ElfLoader() {}

    public static ElfLoader getLoader() {
        var loader = instance;
        if (loader != null) return loader;
        return instance = new ElfLoader();
    }

    private static void registerNative(Method method, long function) {
        var u = theUnsafe;
        var addressSize = u.addressSize();
        var stubs = Compiler.class.getDeclaredMethods();
        var artMethodSize = getArtMethod(stubs[1]) - getArtMethod(stubs[0]);
        var address = getArtMethod(method) + artMethodSize - addressSize * 2L;
        if (addressSize == 8) {
            u.putLong(address, function);
        } else {
            u.putInt(address, (int) function);
        }
    }

    private static long getArtMethod(Method method) {
        var field = artMethodField;
        if (field != null) {
            try {
                return field.getLong(method);
            } catch (IllegalAccessException ignored) {
            }
        }
        // sdk >= 28
        return theUnsafe.getLong(method, 24);
    }

    private static void putString(long addr, String str) {
        var bytes = str.getBytes();
        var len = bytes.length;
        copyMemory(bytes, addr, len);
        theUnsafe.putByte(addr + len, (byte) 0);
    }

    private static void copyMemory(Object srcArray, long dstAddr, int len) {
        var u = theUnsafe;
        try {
            u.copyMemoryFromPrimitiveArray(srcArray, 0, dstAddr, len);
            return;
        } catch (NoSuchMethodError ignored) {
        }
        Object[] arr = {srcArray};
        int srcAddr = u.getInt(arr, u.arrayBaseOffset(Object[].class))
                + u.arrayBaseOffset(srcArray.getClass());
        u.copyMemory(srcAddr, dstAddr, len);
    }

    private static void copyMemory(long srcAddr, Object dstArray, int len) {
        var u = theUnsafe;
        try {
            u.copyMemoryToPrimitiveArray(srcAddr, dstArray, 0, len);
            return;
        } catch (NoSuchMethodError ignored) {
        }
        Object[] arr = {dstArray};
        int dstAddr = u.getInt(arr, u.arrayBaseOffset(Object[].class))
                + u.arrayBaseOffset(dstArray.getClass());
        u.copyMemory(srcAddr, dstAddr, len);
    }

    private static long[] getNativeBridgeFunctions() {
        var elf = new ElfImg("/libnativebridge.so");
        long dlopen = elf.getSymbolAddress("NativeBridgeLoadLibrary");
        long dlsym, dlerror;
        if (dlopen != 0) {
            dlsym = elf.getSymbolAddress("NativeBridgeGetTrampoline");
            dlerror = elf.getSymbolAddress("NativeBridgeGetError");
        } else {
            dlopen = elf.getSymbolAddress("_ZN7android23NativeBridgeLoadLibraryEPKci");
            dlsym = elf.getSymbolAddress("_ZN7android25NativeBridgeGetTrampolineEPvPKcS2_j");
            dlerror = elf.getSymbolAddress("_ZN7android20NativeBridgeGetErrorEv");
        }
        return dlopen == 0 || dlsym == 0 ? new long[3] : new long[]{dlopen, dlsym, dlerror};
    }

    private static String toJavaString(long ptr) {
        final var maxStringSize = 1024;

        if (ptr >= 0 && ptr < 0x8000) {
            return "";
        }

        var buf = new byte[maxStringSize + 1];
        copyMemory(ptr, buf, maxStringSize);

        var length = 0;
        for (; ; length++) {
            if (buf[length] == 0) break;
        }

        return new String(buf, 0, length);
    }

    private static String getJniReturnedMessage(String path, int version) {
        return switch (version) {
            case JNI_ERR -> "JNI_ERR returned from JNI_OnLoad in \"" + path + '\"';
            case JNI_VERSION_1_6, JNI_VERSION_1_4, JNI_VERSION_1_2 -> null;
            default -> "Bad JNI version returned from JNI_OnLoad in \"" + path + "\": " + version;
        };
    }

    private static int getFdInt(FileDescriptor fd) {
        try {
            //noinspection JavaReflectionMemberAccess
            var method = FileDescriptor.class.getDeclaredMethod("getInt$");
            method.setAccessible(true);
            //noinspection DataFlowIssue
            return (int) method.invoke(fd);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }

    private static long callNativeMethod() {
        try {
            var r = nativeMethod.invoke(null);
            assert r != null;
            return (long) r;
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (InvocationTargetException e) {
            throw rethrow(e.getTargetException());
        }
    }

    @SuppressWarnings("unchecked")
    private static <X extends Throwable> RuntimeException rethrow(Throwable e) throws X {
        throw (X) e;
    }

    @SuppressWarnings("JavaJniMissingFunction")
    private static native long a();

    private void initTrampoline(long mem, String arch, long dlopen, long dlsym, long dlerror) {
        Object code;
        int length;
        long[] nativeBridgeFunctions = null;

        switch (arch) {
            case "arm64" -> {
                int[] shellcode = {
                        0xd10083ff, 0xf9000ffe, 0xf9400002, 0xf9436c42, 0x910023e1, 0xd63f0040,
                        0x10000f40, 0x52800041, 0xaa1f03e2, 0xaa1f03e3, 0x180003e5, 0x34000045,
                        0x100002c2, 0x58000424, 0xd63f0080, 0xb40001a0, 0xf9000be0, 0x10000461,
                        0x580003c2, 0xd63f0040, 0xaa0003e2, 0xb4000080, 0xa94087e0, 0xd63f0040,
                        0x14000007, 0x18000040, 0x14000005, 0x00010006, 0x580002c0, 0xd63f0000,
                        0xb2440000, 0xf9400ffe, 0x910083ff, 0xd65f03c0, 0x00000050, 0x00000000,
                        0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
                        0x00000000, 0x00000000, 0x00000000, 0x00000000,
                };
                code = shellcode;
                length = shellcode.length * 4;
                extinfoFdOffset = length - 4 * 5;
                extinfoFlagsOffset = -1; // arm64: extinfo embedded in shellcode, flags already set
                libraryNameOffset = SHELLCODE_SIZE;
                libraryFd = true;
            }
            case "x86_64" -> {
                byte[] shellcode = {
                        (byte) 0x41, (byte) 0x56, (byte) 0x53, (byte) 0x50, (byte) 0x48, (byte) 0x89, (byte) 0xe6, (byte) 0x48, (byte) 0x89, (byte) 0x3e, (byte) 0x48, (byte) 0x8b,
                        (byte) 0x07, (byte) 0xff, (byte) 0x90, (byte) 0xd8, (byte) 0x06, (byte) 0x00, (byte) 0x00, (byte) 0x48, (byte) 0x8d, (byte) 0x05, (byte) 0xcc, (byte) 0x00,
                        (byte) 0x00, (byte) 0x00, (byte) 0x48, (byte) 0x8d, (byte) 0x3d, (byte) 0xdf, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0xbe, (byte) 0x02, (byte) 0x00,
                        (byte) 0x00, (byte) 0x00, (byte) 0x48, (byte) 0x8d, (byte) 0x15, (byte) 0xe9, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xff, (byte) 0x15, (byte) 0xb3,
                        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x48, (byte) 0x85, (byte) 0xc0, (byte) 0x74, (byte) 0x30, (byte) 0x49, (byte) 0x89, (byte) 0xc6, (byte) 0x48,
                        (byte) 0x8d, (byte) 0x05, (byte) 0xac, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x48, (byte) 0x8d, (byte) 0x35, (byte) 0xed, (byte) 0x00, (byte) 0x00,
                        (byte) 0x00, (byte) 0x4c, (byte) 0x89, (byte) 0xf7, (byte) 0xff, (byte) 0x15, (byte) 0x9c, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x48, (byte) 0x89,
                        (byte) 0xc1, (byte) 0x48, (byte) 0x85, (byte) 0xc0, (byte) 0x74, (byte) 0x7c, (byte) 0x48, (byte) 0x8b, (byte) 0x3c, (byte) 0x24, (byte) 0x4c, (byte) 0x89,
                        (byte) 0xf6, (byte) 0xff, (byte) 0xd1, (byte) 0x48, (byte) 0x63, (byte) 0xd8, (byte) 0xeb, (byte) 0x73, (byte) 0x48, (byte) 0x8d, (byte) 0x0d, (byte) 0x87,
                        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x31, (byte) 0xc0, (byte) 0xff, (byte) 0x11, (byte) 0x48, (byte) 0x89, (byte) 0xc3, (byte) 0x48, (byte) 0x8b,
                        (byte) 0x0d, (byte) 0x81, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x48, (byte) 0x85, (byte) 0xc9, (byte) 0x74, (byte) 0x4d, (byte) 0x48, (byte) 0x8d,
                        (byte) 0x3d, (byte) 0x77, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0xbe, (byte) 0x02, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xff, (byte) 0xd1,
                        (byte) 0x48, (byte) 0x85, (byte) 0xc0, (byte) 0x74, (byte) 0x1c, (byte) 0x49, (byte) 0x89, (byte) 0xc6, (byte) 0x48, (byte) 0x8d, (byte) 0x05, (byte) 0x67,
                        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x48, (byte) 0x8d, (byte) 0x35, (byte) 0x90, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x4c, (byte) 0x89,
                        (byte) 0xf7, (byte) 0x31, (byte) 0xd2, (byte) 0x31, (byte) 0xc9, (byte) 0xff, (byte) 0x10, (byte) 0xeb, (byte) 0x2a, (byte) 0x48, (byte) 0x8d, (byte) 0x05,
                        (byte) 0x3e, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x48, (byte) 0x8b, (byte) 0x0d, (byte) 0x37, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x48,
                        (byte) 0x85, (byte) 0xc9, (byte) 0x74, (byte) 0x0b, (byte) 0x31, (byte) 0xc0, (byte) 0xff, (byte) 0xd1, (byte) 0x48, (byte) 0x85, (byte) 0xc0, (byte) 0x48,
                        (byte) 0x0f, (byte) 0x45, (byte) 0xd8, (byte) 0x48, (byte) 0x0f, (byte) 0xba, (byte) 0xeb, (byte) 0x3c, (byte) 0xeb, (byte) 0x05, (byte) 0xbb, (byte) 0x06,
                        (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x48, (byte) 0x89, (byte) 0xd8, (byte) 0x48, (byte) 0x83, (byte) 0xc4, (byte) 0x08, (byte) 0x5b, (byte) 0x41,
                        (byte) 0x5e, (byte) 0xc3
                };
                code = shellcode;
                length = shellcode.length;
                extinfoFdOffset = length + 48 + 24;
                extinfoFlagsOffset = length + 48;
                entrySlotOffset = length + 80;
                libraryNameOffset = SHELLCODE_SIZE;
                libraryFd = false;
            }
            case "arm" -> {
                int[] shellcode = {
                        0xe92d48f0, 0xe28db014, 0xe1a05000, 0xe24dd008, 0xe3a01000, 0xe5952000,
                        0xe28d1004, 0xe592236c, 0xe1a00005, 0xe12fff32, 0xe59d0004, 0xe3a04000,
                        0xe59fc07c, 0xe28f00e4, 0xe3a01000, 0xe28f20ac, 0xe12fff3c, 0xe3500000,
                        0x0a000010, 0xe1a06000, 0xe59fc060, 0xe1a00006, 0xe28f1070, 0xe12fff3c,
                        0xe3500000, 0x0a000006, 0xe1a07000, 0xe59d0004, 0xe1a01006, 0xe12fff37,
                        0xe1a04000, 0xe1a05fc0, 0xea000007, 0xe3a04006, 0xe3844801, 0xea000004,
                        0xe59fc024, 0xe12fff3c, 0xe3500000, 0x11a04000, 0xe3855201, 0xe1a00004,
                        0xe1a01005, 0xe24bd014, 0xe8bd88f0
                };
                code = shellcode;
                length = shellcode.length * 4;
                extinfoFlagsOffset = length + 60;
                extinfoFdOffset = length + 80;
                entrySlotOffset = length + 28;
                libraryNameOffset = length + 108;
                libraryFd = true;
            }
            case "x86" -> {
                byte[] shellcode = {
                        (byte) 0x55, (byte) 0x89, (byte) 0xe5, (byte) 0x53, (byte) 0x57, (byte) 0x56, (byte) 0x83, (byte) 0xe4, (byte) 0xf0, (byte) 0x83, (byte) 0xec, (byte) 0x10,
                        (byte) 0xe8, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x5b, (byte) 0x8d, (byte) 0x45, (byte) 0x08, (byte) 0x8b, (byte) 0x08, (byte) 0x8b,
                        (byte) 0x11, (byte) 0x83, (byte) 0xec, (byte) 0x08, (byte) 0x50, (byte) 0x51, (byte) 0xff, (byte) 0x92, (byte) 0x6c, (byte) 0x03, (byte) 0x00, (byte) 0x00,
                        (byte) 0x83, (byte) 0xc4, (byte) 0x08, (byte) 0x8d, (byte) 0xb3, (byte) 0xef, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x31, (byte) 0xff, (byte) 0x31,
                        (byte) 0xd2, (byte) 0x8d, (byte) 0x83, (byte) 0xa3, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x50, (byte) 0x6a, (byte) 0x00, (byte) 0x56, (byte) 0x8b,
                        (byte) 0x83, (byte) 0x8a, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xff, (byte) 0xd0, (byte) 0x83, (byte) 0xc4, (byte) 0x0c, (byte) 0x85, (byte) 0xc0,
                        (byte) 0x74, (byte) 0x31, (byte) 0x89, (byte) 0xc7, (byte) 0x83, (byte) 0xec, (byte) 0x08, (byte) 0x8d, (byte) 0x83, (byte) 0xc7, (byte) 0x00, (byte) 0x00,
                        (byte) 0x00, (byte) 0x50, (byte) 0x57, (byte) 0x8b, (byte) 0x83, (byte) 0x8e, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xff, (byte) 0xd0, (byte) 0x83,
                        (byte) 0xc4, (byte) 0x10, (byte) 0x85, (byte) 0xc0, (byte) 0x74, (byte) 0x26, (byte) 0x83, (byte) 0xec, (byte) 0x08, (byte) 0x57, (byte) 0xff, (byte) 0x75,
                        (byte) 0x08, (byte) 0xff, (byte) 0xd0, (byte) 0x83, (byte) 0xc4, (byte) 0x10, (byte) 0x89, (byte) 0xc7, (byte) 0x89, (byte) 0xc2, (byte) 0xc1, (byte) 0xfa,
                        (byte) 0x1f, (byte) 0xeb, (byte) 0x16, (byte) 0x8b, (byte) 0x83, (byte) 0x92, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xff, (byte) 0xd0, (byte) 0x89,
                        (byte) 0xc7, (byte) 0xba, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x10, (byte) 0xeb, (byte) 0x05, (byte) 0xbf, (byte) 0x06, (byte) 0x00, (byte) 0x01,
                        (byte) 0x00, (byte) 0x89, (byte) 0xf8, (byte) 0x8d, (byte) 0x65, (byte) 0xf4, (byte) 0x5e, (byte) 0x5f, (byte) 0x5b, (byte) 0x5d, (byte) 0xc3
                };
                code = shellcode;
                length = shellcode.length;
                nativeBridgeFunctions = getNativeBridgeFunctions();
                extinfoFlagsOffset = length + 25;
                extinfoFdOffset = length + 45;
                entrySlotOffset = length + 61;
                libraryNameOffset = SHELLCODE_SIZE;
                libraryFd = true;
            }
            default -> throw new RuntimeException(arch + " is unsupported");
        }

        var u = theUnsafe;
        copyMemory(code, mem, length);
        var mem64 = u.addressSize() == 8;
        if (extinfoFlagsOffset >= 0) {
            // new-style: slots at fixed offsets baked into the shellcode
            if (mem64) {
                u.putLong(mem + length, dlopen);
                u.putLong(mem + length + 8, dlsym);
                u.putLong(mem + length + 16, dlerror);
                if (nativeBridgeFunctions != null) {
                    u.putLong(mem + length + 24, nativeBridgeFunctions[0]);
                    u.putLong(mem + length + 32, nativeBridgeFunctions[1]);
                    u.putLong(mem + length + 40, nativeBridgeFunctions[2]);
                }
                u.putLong(mem + extinfoFlagsOffset, 0); // flags = plain dlopen
                u.putLong(mem + extinfoFlagsOffset + 8, 0); // reserved_addr
                u.putLong(mem + extinfoFlagsOffset + 16, 0); // reserved_size
            } else {
                u.putInt(mem + length, (int) dlopen);
                u.putInt(mem + length + 4, (int) dlsym);
                u.putInt(mem + length + 8, (int) dlerror);
                if (nativeBridgeFunctions != null) {
                    u.putInt(mem + length + 12, (int) nativeBridgeFunctions[0]);
                    u.putInt(mem + length + 16, (int) nativeBridgeFunctions[1]);
                    u.putInt(mem + length + 20, (int) nativeBridgeFunctions[2]);
                }
                u.putInt(mem + extinfoFlagsOffset, 0);
                u.putInt(mem + extinfoFlagsOffset + 4, 0);
                u.putInt(mem + extinfoFlagsOffset + 8, 0);
            }
            entryNameOffset = entrySlotOffset;
            putString(mem + entrySlotOffset, "JNI_OnLoad");
        } else {
            // arm64: legacy slot chain, extinfo embedded in the shellcode itself
            u.putLong(mem += length, dlopen);
            u.putLong(mem += 8, dlsym);
            u.putLong(mem += 8, dlerror);
            mem += 8;
            entryNameOffset = (int) (mem - mmapAddress);
            putString(mem, "JNI_OnLoad");
        }
    }

    private boolean ensureInitialized() {
        if (mmapAddress != 0) return true;
        try {
            var u = theUnsafe;
            var mem = mmapAddress = Os.mmap(0, u.pageSize(), 0x7, 0x22, FileDescriptor.in, 0);
            registerNative(nativeMethod, mem);

            var arch = ApiBridge.VMRuntime_vmInstructionSet();
            var is64Bit = u.addressSize() == 8;
            var hasMemoryElfSupport = true;
            var dl = new ElfImg(is64Bit ? "/system/lib64/libdl.so" : "/system/lib/libdl.so");

            long dlopen, dlsym, dlerror;

            if (dl.isEmpty()) {
                // sdk < 26
                var linker = new ElfImg(is64Bit ? "/system/bin/linker64" : "/system/bin/linker", true);
                dlopen = linker.getSymbolAddressBestMatch("android_dlopen_ext");
                if (dlopen == 0) {
                    throw new UnsupportedOperationException("dlopen not found in linker");
                }
                dlsym = linker.getSymbolAddress("__dl_dlsym");
                if (dlsym == 0) {
                    dlsym = linker.getSymbolAddressBestMatch("7__dlsym");
                }
                if (dlsym == 0) {
                    throw new UnsupportedOperationException("dlsym not found in linker");
                }
                dlerror = linker.getSymbolAddress("__dl_dlerror");
                if (dlerror == 0) {
                    dlerror = linker.getSymbolAddressBestMatch("9__dlerror");
                }
            } else {
                dlopen = dl.getSymbolAddress(hasMemoryElfSupport ? "android_dlopen_ext" : "dlopen");
                if (dlopen == 0) {
                    throw new UnsupportedOperationException("dlopen not found in libdl.so");
                }
                dlsym = dl.getSymbolAddress("dlsym");
                if (dlsym == 0) {
                    throw new UnsupportedOperationException("dlsym not found in libdl.so");
                }
                dlerror = dl.getSymbolAddress("dlerror");
            }

            initTrampoline(mem, arch, dlopen, dlsym, dlerror);
            return true;
        } catch (ErrnoException ignored) {
        }
        return false;
    }

    public boolean load(String path) {
        return load(path, null);
    }

    /**
     * Loads a library from a file path, calling a custom entry symbol instead of {@code JNI_OnLoad}
     * when {@code entrySymbol} is non-null. Falls back to no entry call when the symbol is absent.
     */
    public boolean load(String path, String entrySymbol) {
        if (!ensureInitialized() || path.length() >= 0x1000 - libraryNameOffset) return false;
        putString(mmapAddress + libraryNameOffset, path);
        if (entrySymbol != null) {
            putString(mmapAddress + entryNameOffset, entrySymbol);
        }
        var result = callNativeMethod();
        var msg = result >>> 56 != 0x10
                ? getJniReturnedMessage(path, (int) result)
                : toJavaString(result & ((1L << 56) - 1));
        if (msg != null) {
            throw new UnsatisfiedLinkError(msg);
        }
        return true;
    }

    public boolean load(byte[] elf) {
        return load(elf, 0, elf.length, null, null);
    }

    public boolean load(byte[] elf, String libraryId) {
        return load(elf, 0, elf.length, libraryId, null);
    }

    public boolean load(byte[] elf, String libraryId, String entrySymbol) {
        return load(elf, 0, elf.length, libraryId, entrySymbol);
    }

    public boolean load(byte[] elf, int off, int len, String libraryId) {
        return load(elf, off, len, libraryId, null);
    }

    /**
     * Loads an in-memory library, calling a custom entry symbol instead of {@code JNI_OnLoad} when
     * {@code entrySymbol} is non-null. Falls back to no entry call when the symbol is absent.
     */
    public boolean load(byte[] elf, int off, int len, String libraryId, String entrySymbol) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            throw new UnsupportedOperationException("memfd not available");
        }

        if (libraryId == null) {
            var random = new Random();
            char[] chars = new char[16];
            for (int i = 0; i < chars.length; i++) {
                chars[i] = (char) ('a' + random.nextInt(26));
            }
            libraryId = new String(chars);
        }

        if (!ensureInitialized() || libraryId.length() >= 0x1000 - libraryNameOffset) return false;

        FileDescriptor fd;
        try {
            fd = Os.memfd_create(libraryId, 0);
            Os.write(fd, elf, off, len);
        } catch (ErrnoException | InterruptedIOException e) {
            throw new RuntimeException(e);
        }

        String libraryName;
        if (extinfoFlagsOffset < 0) {
            // arm64: extinfo embedded in the shellcode, fd passed directly
            libraryName = libraryId;
            theUnsafe.putInt(mmapAddress + extinfoFdOffset, getFdInt(fd));
        } else if (libraryFd) {
            // arm/x86: fd passed through extinfo (ANDROID_DLEXT_USE_LIBRARY_FD)
            libraryName = libraryId;
            theUnsafe.putInt(mmapAddress + extinfoFlagsOffset, ANDROID_DLEXT_USE_LIBRARY_FD);
            theUnsafe.putInt(mmapAddress + extinfoFlagsOffset + 4, 0);
            theUnsafe.putInt(mmapAddress + extinfoFdOffset, getFdInt(fd));
        } else {
            // x86_64: dlopen(/proc/self/fd/N); extinfo flags stay 0
            libraryName = "/proc/self/fd/" + getFdInt(fd);
        }
        putString(mmapAddress + libraryNameOffset, libraryName);
        if (entrySymbol != null) {
            putString(mmapAddress + entryNameOffset, entrySymbol);
        }

        long result;

        try {
            result = callNativeMethod();
        } finally {
            if (extinfoFdOffset != 0) {
                theUnsafe.putInt(mmapAddress + extinfoFdOffset, 0);
            }
            if (extinfoFlagsOffset >= 0) {
                theUnsafe.putInt(mmapAddress + extinfoFlagsOffset, 0);
                theUnsafe.putInt(mmapAddress + extinfoFlagsOffset + 4, 0);
            }
            try {
                Os.close(fd);
            } catch (ErrnoException ignored) {
            }
        }

        var msg = result >>> 56 != 0x10
                ? getJniReturnedMessage(libraryId, (int) result)
                : toJavaString(result & ((1L << 56) - 1));
        if (msg != null) {
            throw new UnsatisfiedLinkError(msg);
        }

        cacheLoadedLibrary(libraryId, elf, off, len);
        return true;
    }

    /**
     * Returns the load base of a library previously loaded via {@link #load(byte[], String)}, or 0
     * if not found.
     */
    public long getLoadedBase(String libraryId) {
        var lib = loadedLibraries.get(libraryId);
        return lib == null ? 0 : lib.base;
    }

    /**
     * Returns the symbols of a library previously loaded via {@link #load(byte[], String)}, or null
     * if not found. Addresses are absolute (base + st_value).
     */
    public Map<String, Long> getLoadedSymbols(String libraryId) {
        var lib = loadedLibraries.get(libraryId);
        return lib == null ? null : lib.symbols;
    }

    /**
     * Resolves a symbol in a library previously loaded via {@link #load(byte[], String)}, or 0 if
     * not found.
     */
    public long getLoadedSymbolAddress(String libraryId, String symbol) {
        var symbols = getLoadedSymbols(libraryId);
        if (symbols == null) return 0;
        var address = symbols.get(symbol);
        return address == null ? 0 : address;
    }

    private void cacheLoadedLibrary(String libraryId, byte[] elf, int off, int len) {
        var base = findMemfdBase(libraryId);
        if (base == 0) return;
        var bytes = new byte[len];
        System.arraycopy(elf, off, bytes, 0, len);
        var img = new ElfImg(bytes, base, true);
        loadedLibraries.put(libraryId, new LoadedLibrary(base, img.getSymbols()));
    }

    private static long findMemfdBase(String libraryId) {
        var suffix = "/memfd:" + libraryId + " (deleted)";
        try (var reader = new BufferedReader(new FileReader("/proc/self/maps"))) {
            var first = 0L;
            for (String line; (line = reader.readLine()) != null; ) {
                if (!line.endsWith(suffix)) continue;
                var start = Long.parseLong(line.substring(0, line.indexOf('-')), 16);
                if (first == 0 || start < first) first = start;
            }
            return first;
        } catch (Exception ignored) {
            return 0;
        }
    }

    private record LoadedLibrary(long base, Map<String, Long> symbols) {}

    public void release() {
        if (mmapAddress == 0) return;
        try {
            Os.munmap(mmapAddress, theUnsafe.pageSize());
        } catch (ErrnoException ignored) {
        }
        mmapAddress = 0;
        entryNameOffset = 0;
        extinfoFdOffset = 0;
        extinfoFlagsOffset = 0;
        entrySlotOffset = 0;
        libraryNameOffset = 0;
        libraryFd = false;
        loadedLibraries.clear();
        instance = null;
    }
}
