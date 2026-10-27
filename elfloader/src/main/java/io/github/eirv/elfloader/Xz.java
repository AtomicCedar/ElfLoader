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

/**
 * Minimal xz container decoder for the streams produced by {@code objcopy} for
 * .gnu_debugdata sections: single block, single LZMA2 filter. The LZMA1 core is
 * a port of LzmaDec.c (Igor Pavlov, public domain).
 */
final class Xz {
    private static final int STREAM_HEADER_SIZE = 12;

    private static final int kNumTopBits = 24;
    private static final int kTopValue = 1 << kNumTopBits;
    private static final int kNumBitModelTotalBits = 11;
    private static final int kBitModelTotal = 1 << kNumBitModelTotalBits;
    private static final int kNumMoveBits = 5;

    private static final int kNumPosBitsMax = 4;

    private static final int kLenNumLowBits = 3;
    private static final int kLenNumLowSymbols = 1 << kLenNumLowBits;
    private static final int kLenNumHighBits = 8;
    private static final int kLenNumHighSymbols = 1 << kLenNumHighBits;
    private static final int kNumLenProbs = kLenNumHighSymbols + 2 * ((1 << kNumPosBitsMax) << kLenNumLowBits);

    private static final int kNumStates = 12;
    private static final int kNumStates2 = 16;
    private static final int kNumLitStates = 7;

    private static final int kStartPosModelIndex = 4;
    private static final int kEndPosModelIndex = 14;
    private static final int kNumFullDistances = 1 << (kEndPosModelIndex >> 1);

    private static final int kNumPosSlotBits = 6;
    private static final int kNumLenToPosStates = 4;

    private static final int kNumAlignBits = 4;
    private static final int kAlignTableSize = 1 << kNumAlignBits;

    private static final int kMatchMinLen = 2;
    private static final int kMatchSpecLenStart = kMatchMinLen + kLenNumLowSymbols * 2 + kLenNumHighSymbols;

    private static final int kStartOffset = 1664;

    private static final int SpecPos = -kStartOffset;
    private static final int IsRep0Long = SpecPos + kNumFullDistances;
    private static final int RepLenCoder = IsRep0Long + (kNumStates2 << kNumPosBitsMax);
    private static final int LenCoder = RepLenCoder + kNumLenProbs;
    private static final int IsMatch = LenCoder + kNumLenProbs;
    private static final int Align = IsMatch + (kNumStates2 << kNumPosBitsMax);
    private static final int IsRep = Align + kAlignTableSize;
    private static final int IsRepG0 = IsRep + kNumStates;
    private static final int IsRepG1 = IsRepG0 + kNumStates;
    private static final int IsRepG2 = IsRepG1 + kNumStates;
    private static final int PosSlot = IsRepG2 + kNumStates;
    private static final int Literal = PosSlot + (kNumLenToPosStates << kNumPosSlotBits);
    private static final int NUM_BASE_PROBS = Literal + kStartOffset;

    private static final int LZMA_LIT_SIZE = 0x300;

    private short[] probs;
    private int lc;
    private int lp;
    private int pb;
    private final int dicSize;

    private byte[] dic;
    private int dicPos;
    private int processedPos;
    private int checkDicSize;

    private int range;
    private int code;
    private byte[] in;
    private int inPos;
    private int inLimit;

    private int state;
    private final int[] reps = new int[4];
    private int remainLen;

    private Xz(int lc, int lp, int pb, int dicSize) {
        this.lc = lc;
        this.lp = lp;
        this.pb = pb;
        this.dicSize = dicSize;
        this.probs = new short[NUM_BASE_PROBS + (LZMA_LIT_SIZE << (lc + lp))];
    }

    private void resetState(boolean initDic) {
        for (var i = 0; probs.length > i; i++) probs[i] = (short) (kBitModelTotal >> 1);
        reps[0] = reps[1] = reps[2] = reps[3] = 1;
        state = 0;
        remainLen = kMatchSpecLenStart + (initDic ? 2 : 1);
        if (initDic) {
            processedPos = 0;
            checkDicSize = 0;
            dicPos = 0;
        }
    }

    private void initRangeCoder() {
        if (in[inPos] != 0) throw new IllegalArgumentException("corrupt xz data");
        code = ((in[inPos + 1] & 0xFF) << 24)
                | ((in[inPos + 2] & 0xFF) << 16)
                | ((in[inPos + 3] & 0xFF) << 8)
                | (in[inPos + 4] & 0xFF);
        range = 0xFFFFFFFF;
        inPos += 5;
        remainLen = 0;
    }

    private int decodeBit(int probIndex) {
        var ttt = probs[probIndex + kStartOffset] & 0xFFFF;
        if (Integer.compareUnsigned(range, kTopValue) < 0) {
            range <<= 8;
            code = (code << 8) | (in[inPos++] & 0xFF);
        }
        var bound = (range >>> kNumBitModelTotalBits) * ttt;
        if (Integer.compareUnsigned(code, bound) < 0) {
            range = bound;
            probs[probIndex + kStartOffset] = (short) (ttt + ((kBitModelTotal - ttt) >> kNumMoveBits));
            return 0;
        }
        range -= bound;
        code -= bound;
        probs[probIndex + kStartOffset] = (short) (ttt - (ttt >> kNumMoveBits));
        return 1;
    }

    private int decodeTree(int base, int bits) {
        var m = 1;
        for (var i = 0; bits > i; i++) m = (m << 1) + decodeBit(base + m);
        return m - (1 << bits);
    }

    private int decodeDirectBits(int numBits) {
        var result = 0;
        do {
            if (Integer.compareUnsigned(range, kTopValue) < 0) {
                range <<= 8;
                code = (code << 8) | (in[inPos++] & 0xFF);
            }
            range >>>= 1;
            code -= range;
            var t = -(code >>> 31);
            code += range & t;
            result = (result << 1) + (t + 1);
        } while (--numBits != 0);
        return result;
    }

    // Port of LzmaDec.c's align reverse decode (REV_BIT_CONST / REV_BIT_LAST):
    // the tree node is the running path value, not a fixed power of two.
    private int decodeAlign() {
        var i = 1;
        i += decodeBit(0 + i) != 0 ? 2 : 1;
        i += decodeBit(i) != 0 ? 4 : 2;
        i += decodeBit(i) != 0 ? 8 : 4;
        if (decodeBit(i) == 0) i -= 8;
        return i;
    }

    private int decodeLength(int base, int posState) {
        if (decodeBit(base) == 0) return decodeTree(base + posState, kLenNumLowBits);
        if (decodeBit(base + kLenNumLowSymbols) == 0)
            return kLenNumLowSymbols + decodeTree(base + kLenNumLowSymbols + posState, kLenNumLowBits);
        return kLenNumLowSymbols * 2 + decodeTree(base + ((1 << kNumPosBitsMax) << kLenNumLowBits) * 2, kLenNumHighBits);
    }

    private void writeRem(int limit) {
        if (remainLen != 0 && remainLen < kMatchSpecLenStart) {
            var len = remainLen;
            var rem = limit - dicPos;
            if (rem < len) len = rem;
            if (checkDicSize == 0 && dicSize - processedPos <= len) checkDicSize = dicSize;
            processedPos += len;
            remainLen -= len;
            while (len != 0) {
                len--;
                dic[dicPos] = reps[0] <= dicPos ? dic[dicPos - reps[0]] : 0;
                dicPos++;
            }
        }
    }

    private void decodeReal(int limit) {
        var pbMask = (1 << pb) - 1;
        var lpMask = (0x100 << lp) - (0x100 >> lc);
        var len = 0;

        do {
            var posState = (processedPos & pbMask) << 4;

            var probIndex = IsMatch + posState + state;
            var ttt = probs[probIndex + kStartOffset] & 0xFFFF;
            if (Integer.compareUnsigned(range, kTopValue) < 0) {
                range <<= 8;
                code = (code << 8) | (in[inPos++] & 0xFF);
            }
            var bound = (range >>> kNumBitModelTotalBits) * ttt;

            if (Integer.compareUnsigned(code, bound) < 0) {
                // literal
                range = bound;
                probs[probIndex + kStartOffset] = (short) (ttt + ((kBitModelTotal - ttt) >> kNumMoveBits));
                var litBase = Literal;
                if (processedPos != 0 || checkDicSize != 0)
                    litBase += 3 * ((((processedPos << 8) + (dic[dicPos - 1] & 0xFF)) & lpMask) << lc);
                processedPos++;

                var symbol = 1;
                if (state < kNumLitStates) {
                    state -= state < 4 ? state : 3;
                    do {
                        symbol = (symbol << 1) + decodeBit(litBase + symbol);
                    } while (symbol < 0x100);
                } else {
                    var matchByte = reps[0] <= dicPos ? dic[dicPos - reps[0]] & 0xFF : 0;
                    var offs = 0x100;
                    state -= state < 10 ? 3 : 6;
                    do {
                        matchByte <<= 1;
                        var bit = offs;
                        offs &= matchByte;
                        var probLit = litBase + (offs + bit + symbol);
                        var b = decodeBit(probLit);
                        symbol = (symbol << 1) + b;
                        if (b == 0) offs ^= bit;
                    } while (symbol < 0x100);
                }
                dic[dicPos++] = (byte) symbol;
                continue;
            }

            // match
            range -= bound;
            code -= bound;
            probs[probIndex + kStartOffset] = (short) (ttt - (ttt >> kNumMoveBits));

            int distance;
            if (decodeBit(IsRep + state) == 0) {
                state += kNumStates;
                len = decodeLength(LenCoder, posState) + kMatchMinLen;

                var lenState = len - kMatchMinLen;
                if (kNumLenToPosStates - 1 < lenState) lenState = kNumLenToPosStates - 1;
                var posSlot = decodeTree(PosSlot + (lenState << kNumPosSlotBits), kNumPosSlotBits);
                if (posSlot < kStartPosModelIndex) {
                    distance = posSlot;
                } else {
                    var numDirectBits = (posSlot >> 1) - 1;
                    distance = (2 | (posSlot & 1)) << numDirectBits;
                    if (posSlot < kEndPosModelIndex) {
                        var m = 1;
                        distance++;
                        do {
                            if (decodeBit(SpecPos + distance) == 0) {
                                distance += m;
                                m += m;
                            } else {
                                m += m;
                                distance += m;
                            }
                        } while (--numDirectBits != 0);
                        distance -= m;
                    } else {
                        numDirectBits -= kNumAlignBits;
                        distance += decodeDirectBits(numDirectBits) << kNumAlignBits;
                        distance += decodeAlign();
                    }
                    if (distance == 0xFFFFFFFF) {
                        // end of payload marker
                        state -= kNumStates;
                        remainLen = kMatchSpecLenStart;
                        len = 0;
                        break;
                    }
                }
                reps[3] = reps[2];
                reps[2] = reps[1];
                reps[1] = reps[0];
                if (distance >= (checkDicSize == 0 ? processedPos : checkDicSize)) {
                    throw new IllegalArgumentException("corrupt xz data");
                }
                reps[0] = distance + 1;
                state = state < kNumStates + kNumLitStates ? kNumLitStates : kNumLitStates + 3;
                if (distance >= (checkDicSize == 0 ? processedPos : checkDicSize)) {
                }
            } else {
                if (decodeBit(IsRepG0 + state) == 0) {
                    if (decodeBit(IsRep0Long + posState + state) == 0) {
                        // short rep
                        state = state < kNumLitStates ? 9 : 11;
                        dic[dicPos] = reps[0] <= dicPos ? dic[dicPos - reps[0]] : 0;
                        dicPos++;
                        processedPos++;
                        continue;
                    }
                    distance = reps[0];
                } else {
                    if (decodeBit(IsRepG1 + state) == 0) {
                        distance = reps[1];
                    } else {
                        if (decodeBit(IsRepG2 + state) == 0) {
                            distance = reps[2];
                        } else {
                            distance = reps[3];
                            reps[3] = reps[2];
                        }
                        reps[2] = reps[1];
                    }
                    reps[1] = reps[0];
                    reps[0] = distance;
                }
                state = state < kNumLitStates ? 8 : 11;
                len = decodeLength(RepLenCoder, posState) + kMatchMinLen;
            }

            var rem = limit - dicPos;
            if (rem == 0) throw new IllegalArgumentException("corrupt xz data");
            var curLen = rem < len ? rem : len;
            var pos = dicPos - reps[0];
            processedPos += curLen;
            len -= curLen;
            for (var i = 0; curLen > i; i++) dic[dicPos + i] = dic[pos + i];
            dicPos += curLen;
        } while (dicPos < limit);

        remainLen = len;
    }

    private static int propByteToLcLpPb(int propByte) {
        if (propByte >= 9 * 5 * 5) throw new IllegalArgumentException("corrupt xz data");
        var lc = propByte % 9;
        propByte /= 9;
        var lp = propByte % 5;
        var pb = propByte / 5;
        return lc | (lp << 8) | (pb << 16);
    }

    private static int dictSizeOf(int prop) {
        if (prop == 40) return 0xFFFFFFFF;
        return (2 | (prop & 1)) << (prop / 2 + 11);
    }

    static byte[] decompress(byte[] xz) {
        if (xz.length < STREAM_HEADER_SIZE + 2 || (xz[0] & 0xFF) != 0xFD || xz[1] != '7' || xz[2] != 'z'
                || xz[3] != 'X' || xz[4] != 'Z' || xz[5] != 0)
            throw new IllegalArgumentException("not xz data");
        var streamFlags = (xz[6] << 8) | (xz[7] & 0xFF);
        if ((streamFlags & 0xF0) != 0 || (streamFlags & 0x0F) > 0x0A)
            throw new IllegalArgumentException("unsupported xz stream");

        var pos = STREAM_HEADER_SIZE;
        if (pos >= xz.length) return new byte[0];
        var headerSize = (xz[pos] + 1) * 4;
        if (headerSize < 8) {
            // 0x00 block header = end of blocks: empty stream
            return new byte[0];
        }
        if (xz.length < pos + headerSize) throw new IllegalArgumentException("corrupt xz data");
        var blockFlags = xz[pos + 1] & 0x3F;
        var filterCount = (blockFlags & 0x03) + 1;
        if ((blockFlags & ~0x03) != 0 || filterCount != 1)
            throw new IllegalArgumentException("unsupported xz block");

        var p = pos + 2;
        var filterId = xz[p] & 0xFF;
        var propsSize = xz[p + 1] & 0xFF;
        if (filterId != 0x21 || propsSize != 1) throw new IllegalArgumentException("unsupported xz filter");
        var dictSizeProp = xz[p + 2] & 0xFF;
        if (dictSizeProp > 40) throw new IllegalArgumentException("unsupported xz filter");
        var dicSize = dictSizeOf(dictSizeProp);

        pos += headerSize;

        var decoder = new Xz(0, 0, 0, dicSize);
        decoder.dic = new byte[0];
        decoder.resetState(true);

        var totalUnpacked = 0;

        // LZMA2 chunk loop
        // (an empty LZMA2 stream just hits the end marker below and returns zero bytes)
        while (true) {
            if (pos >= xz.length) throw new IllegalArgumentException("corrupt xz data");
            var control = xz[pos] & 0xFF;
            if (control == 0) break; // end marker

            var dicReset = control >= 0xE0 || control == 1;
            var stateReset = control >= 0xA0 || dicReset;
            var newProps = control >= 0xC0 || dicReset;

            if (control < 0x80) {
                // uncompressed chunk
                if (control > 2) throw new IllegalArgumentException("corrupt xz data");
                var size = (((xz[pos + 1] & 0xFF) << 8) | (xz[pos + 2] & 0xFF)) + 1;
                if (xz.length < pos + 3 + size) throw new IllegalArgumentException("corrupt xz data");
                ensureDic(decoder, totalUnpacked + size);
                if (dicReset) decoder.resetState(true);
                System.arraycopy(xz, pos + 3, decoder.dic, decoder.dicPos, size);
                decoder.dicPos += size;
                decoder.processedPos += size;
                totalUnpacked += size;
                pos += 3 + size;
                continue;
            }

            // LZMA chunk
            var unpacked = ((control & 0x1F) << 16) + ((xz[pos + 1] & 0xFF) << 8) + (xz[pos + 2] & 0xFF) + 1;
            var compressed = ((xz[pos + 3] & 0xFF) << 8) | (xz[pos + 4] & 0xFF) + 1;
            var dataStart = pos + (newProps ? 6 : 5);
            if (xz.length < dataStart + compressed) throw new IllegalArgumentException("corrupt xz data");
            if (!newProps && decoder.needProps) throw new IllegalArgumentException("corrupt xz data");
            if (newProps) {
                var lclppb = propByteToLcLpPb(xz[pos + 5] & 0xFF);
                decoder.setProps(lclppb & 0xFF, (lclppb >> 8) & 0xFF, (lclppb >> 16) & 0xFF);
                decoder.needProps = false;
            }

            ensureDic(decoder, totalUnpacked + unpacked);
            if (dicReset) decoder.resetState(true);
            else if (stateReset) decoder.resetState(false);

            decoder.in = xz;
            decoder.inPos = dataStart;
            decoder.inLimit = dataStart + compressed;
            decoder.initRangeCoder();

            decoder.decodeReal(decoder.dicPos + unpacked);
            if (decoder.dicPos != decoder.dic.length - (decoder.dic.length - totalUnpacked - unpacked))
                throw new IllegalArgumentException("corrupt xz data");
            if (decoder.dicPos != totalUnpacked + unpacked) throw new IllegalArgumentException("corrupt xz data");

            totalUnpacked += unpacked;
            pos = dataStart + compressed;
        }

        var result = new byte[totalUnpacked];
        System.arraycopy(decoder.dic, 0, result, 0, totalUnpacked);
        return result;
    }

    private boolean needProps;

    private void setProps(int lc, int lp, int pb) {
        this.lc = lc;
        this.lp = lp;
        this.pb = pb;
        this.probs = new short[NUM_BASE_PROBS + (LZMA_LIT_SIZE << (lc + lp))];
    }

    private static void ensureDic(Xz decoder, int size) {
        if (decoder.dic.length < size) {
            var newDic = new byte[Math.max(size, decoder.dic.length * 2)];
            System.arraycopy(decoder.dic, 0, newDic, 0, decoder.dicPos);
            decoder.dic = newDic;
        }
    }
}