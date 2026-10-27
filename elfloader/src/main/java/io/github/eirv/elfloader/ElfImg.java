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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel.MapMode;
import java.util.HashMap;
import java.util.Map;

public class ElfImg {
    private static final int EI_CLASS = 4;
    private static final int EI_NIDENT = 16;
    private static final int SHT_SYMTAB = 2;
    private static final int SHT_NOBITS = 8;
    private static final byte[] GNU_DEBUGDATA_NAME = {'.', 'g', 'n', 'u', '_', 'd', 'e', 'b', 'u', 'g', 'd', 'a', 't', 'a'};
    private static final int SHT_DYNSYM = 11;
    private static final int SHN_UNDEF = 0;
    private static final int PT_LOAD = 1;

    private final HashMap<String, Long> symbols = new HashMap<>();

    public ElfImg(String filename) {
        this(filename, false);
    }

    /**
     * Creates an image from raw ELF bytes already in memory (e.g. a library
     * loaded via {@link ElfLoader#load(byte[])}), with an explicit load base.
     */
    public ElfImg(byte[] elf, long base, boolean searchDebugSymbols) {
        var buffer = ByteBuffer.wrap(elf);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        symbols.putAll(parseSymbols(buffer, base, searchDebugSymbols, elf.length));
    }

    public ElfImg(String filename, boolean searchDebugSymbols) {
        try {
            filename = new File(filename).getCanonicalPath();
        } catch (IOException ignored) {
        }

        var base = 0L;
        try (var reader = new BufferedReader(new FileReader("/proc/self/maps"))) {
            var permissions = new char[4];
            for (String line; (line = reader.readLine()) != null; ) {
                if (line.isEmpty()) continue;

                var index = line.indexOf(' ') + 1;
                line.getChars(index, index + 4, permissions, 0);

                // r--p r-xp --xp
                if (permissions[1] == 'w') continue;
                if (permissions[3] != 'p') continue;
                if (permissions[0] != 'r' && permissions[2] != 'x') continue;
                if (!line.endsWith(filename)) continue;

                base = Long.parseLong(line.substring(0, line.indexOf('-')), 16);
                filename = line.substring(line.lastIndexOf(' ') + 1);
                break;
            }
        } catch (IOException ignored) {
        }

        if (base == 0) return;
        var file = new File(filename);
        var elfBuffer = ByteBuffer.allocateDirect(0);

        try (var raf = new FileInputStream(file)) {
            elfBuffer = raf.getChannel().map(MapMode.READ_ONLY, 0, file.length());
        } catch (IOException ignored) {
        }
        symbols.putAll(parseSymbols(elfBuffer, base, searchDebugSymbols, file.length()));
    }

    private static HashMap<String, Long> parseSymbols(ByteBuffer elf, long base, boolean searchDebugSymbols, long fileSize) {
        var symbols = new HashMap<String, Long>();
        elf.order(ByteOrder.LITTLE_ENDIAN);

        elf.position(EI_CLASS);
        var is64Bit = elf.get() == 2;
        var ptr = is64Bit ? 8 : 4;
        // e_phoff follows e_entry; e_shoff follows e_phoff
        elf.position(EI_NIDENT + 2 + 2 + 4 + ptr);
        var phoff = (int) getPointer(elf, is64Bit);
        var shoff = (int) getPointer(elf, is64Bit);
        // e_phentsize..e_shstrndx follow e_flags and e_ehsize
        elf.position(elf.position() + 4 + 2);
        var e_phentsize = elf.getShort();
        var e_phnum = elf.getShort();
        var e_shentsize = elf.getShort();
        var e_shnum = elf.getShort();
        var e_shstrndx = elf.getShort();

        var min_vaddr = Integer.MAX_VALUE;
        for (var i = 0; e_phnum > i; i++) {
            elf.position(phoff + i * e_phentsize);
            var p_type = elf.getInt();
            if (p_type != PT_LOAD) continue;
            elf.position(elf.position() + 4);
            var p_vaddr = (int) getPointer(elf, is64Bit);
            if (min_vaddr > p_vaddr) min_vaddr = p_vaddr;
        }
        base -= min_vaddr;

        boolean dynsym = false;
        boolean symtab = false;
        byte[] debugdata = null;

        if (searchDebugSymbols && e_shstrndx < e_shnum) {
            elf.position(shoff + e_shstrndx * e_shentsize + 4 + 4 + ptr * 2);
            var shstr_offset = (int) getPointer(elf, is64Bit);
            var shstr_size = (int) getPointer(elf, is64Bit);
            if (shstr_size <= 0 || shstr_offset < 0 || shstr_size > fileSize - shstr_offset) return symbols;
            var shstrtab = new byte[shstr_size];
            elf.position(shstr_offset);
            elf.get(shstrtab);

            for (var i = 0; e_shnum > i; i++) {
                elf.position(shoff + i * e_shentsize);
                var sh_name = elf.getInt();
                if (sh_name < 0 || sh_name >= shstr_size) continue;
                var nameEnd = sh_name;
                //noinspection StatementWithEmptyBody
                while (nameEnd < shstr_size && shstrtab[nameEnd] != 0) nameEnd++;
                if (nameEnd - sh_name != 14) continue;
                var match = true;
                for (var n = 0; 14 > n; n++) {
                    if (shstrtab[sh_name + n] != GNU_DEBUGDATA_NAME[n]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    elf.position(shoff + i * e_shentsize + 4 + 4 + ptr * 2);
                    var gd_offset = (int) getPointer(elf, is64Bit);
                    var gd_size = (int) getPointer(elf, is64Bit);
                    if (gd_size != 0 && gd_offset >= 0 && gd_size <= fileSize - gd_offset) {
                        var compressed = new byte[gd_size];
                        elf.position(gd_offset);
                        elf.get(compressed);
                        try {
                            debugdata = Xz.decompress(compressed);
                        } catch (RuntimeException ignored) {
                        }
                    }
                    break;
                }
            }
        }

        for (var i = 0; e_shnum > i; i++) {
            elf.position(shoff + i * e_shentsize + 4);
            var sh_type = elf.getInt();
            if (sh_type != SHT_DYNSYM && (!searchDebugSymbols || sh_type != SHT_SYMTAB))
                continue;
            elf.position(elf.position() + ptr * 2);
            var sym_offset = (int) getPointer(elf, is64Bit);
            var sh_size = getPointer(elf, is64Bit);
            var sh_link = elf.getInt();
            elf.position(elf.position() + 4 + ptr);
            var sym_count = (int) (sh_size / getPointer(elf, is64Bit));
            elf.position(shoff + sh_link * e_shentsize + 4 * 2 + ptr * 2);
            var str_offset = (int) getPointer(elf, is64Bit);
            var str_size = (int) getPointer(elf, is64Bit);
            if (sh_type == SHT_DYNSYM) {
                searchSymbols(
                        symbols,
                        base,
                        elf,
                        is64Bit,
                        sym_offset,
                        sym_count,
                        str_offset,
                        str_size);
                dynsym = true;
                if (!searchDebugSymbols) break;
            } else {
                searchSymbols(
                        symbols,
                        base,
                        elf,
                        is64Bit,
                        sym_offset,
                        sym_count,
                        str_offset,
                        str_size);
                symtab = true;
            }
            if (dynsym && symtab) break;
        }

        if (debugdata != null) {
            var mini = ByteBuffer.wrap(debugdata);
            mini.order(ByteOrder.LITTLE_ENDIAN);
            searchDebugData(symbols, base, mini);
        }

        return symbols;
    }

    /**
     * Searches the mini ELF embedded in {@code .gnu_debugdata} (xz-compressed,
     * symtab/strtab only) for debug symbols.
     */
    private static void searchDebugData(HashMap<String, Long> result, long base, ByteBuffer elf) {
        elf.position(EI_CLASS);
        var is64Bit = elf.get() == 2;
        var ptr = is64Bit ? 8 : 4;
        // e_shoff sits at EI_NIDENT + e_type + e_machine + e_version + e_entry + e_phoff
        elf.position(EI_NIDENT + 2 + 2 + 4 + ptr * 2);
        var shoff = (int) getPointer(elf, is64Bit);
        // e_shentsize, e_shnum, e_shstrndx follow e_flags, e_ehsize, e_phentsize, e_phnum
        elf.position(elf.position() + 4 + 2 + 2 + 2 + 2);
        var e_shentsize = elf.getShort();
        var e_shnum = elf.getShort();
        var e_shstrndx = elf.getShort();
        if (shoff == 0 || e_shnum == 0 || e_shstrndx >= e_shnum) return;

        int[] types = new int[e_shnum];
        long[] offsets = new long[e_shnum];
        long[] sizes = new long[e_shnum];
        int[] links = new int[e_shnum];
        long[] entsizes = new long[e_shnum];

        for (var i = 0; e_shnum > i; i++) {
            elf.position(shoff + i * e_shentsize + 4);
            types[i] = elf.getInt();
            elf.position(elf.position() + ptr * 2);
            offsets[i] = getPointer(elf, is64Bit);
            sizes[i] = getPointer(elf, is64Bit);
            links[i] = elf.getInt();
            elf.position(elf.position() + 4 + ptr);
            entsizes[i] = getPointer(elf, is64Bit);
        }

        for (var i = 0; e_shnum > i; i++) {
            if (types[i] != SHT_SYMTAB) continue;
            var str = links[i];
            if (str >= e_shnum) continue;
            searchSymbols(
                    result,
                    base,
                    elf,
                    is64Bit,
                    (int) offsets[i],
                    (int) (sizes[i] / entsizes[i]),
                    (int) offsets[str],
                    (int) sizes[str]);
        }
    }

    private static void searchSymbols(
            HashMap<String, Long> result,
            long base,
            ByteBuffer elf,
            boolean is64Bit,
            int sym_off,
            int sym_count,
            int str_off,
            int str_size) {
        if (sym_count == 0 || str_size == 0) {
            return;
        }

        var strings = new byte[str_size];
        elf.position(str_off);
        elf.get(strings);

        elf.position(sym_off);
        for (var n = 0; sym_count > n; n++) {
            var st_name = elf.getInt();
            long st_value;
            if (is64Bit) {
                elf.position(elf.position() + 1 + 1 + 2);
                st_value = elf.getLong();
                var st_size = elf.getLong();
                if (st_size == 0) continue;
            } else {
                st_value = elf.getInt();
                var st_size = elf.getInt();
                elf.position(elf.position() + 1 + 1 + 2);
                if (st_size == 0) continue;
            }
            if (st_name == SHN_UNDEF) continue;
            var length = -1;
            //noinspection StatementWithEmptyBody
            while (strings[st_name + ++length] != 0)
                ;
            if (length == 0) continue;
            result.put(new String(strings, st_name, length), base + st_value);
        }
    }

    private static long getPointer(ByteBuffer elf, boolean is64Bit) {
        return is64Bit ? elf.getLong() : elf.getInt();
    }

    public boolean isEmpty() {
        return symbols.isEmpty();
    }

    public long getSymbolAddress(String symbol) {
        var address = symbols.get(symbol);
        return address == null ? 0 : address;
    }

    public long getSymbolAddressBestMatch(String symbol) {
        Map.Entry<String, Long> previous = null;
        for (Map.Entry<String, Long> e : symbols.entrySet()) {
            if (!e.getKey().contains(symbol)) continue;
            if (previous == null) {
                previous = e;
            } else {
                throw new UnsupportedOperationException(
                        "Multiple symbols were found: '"
                                + previous.getKey()
                                + "', '"
                                + e.getKey()
                                + '\'');
            }
        }
        return previous == null ? 0 : previous.getValue();
    }

    public Map<String, Long> getSymbols() {
        return symbols;
    }
}
