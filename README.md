# ElfLoader

![](https://img.shields.io/badge/Android-7%20~%2017-brightgreen)
![](https://img.shields.io/badge/Arch-arm%20%2F%20arm64%20%2F%20x86%20%2F%20x64-red.svg)

使用纯 java 在 android 上加载 ELF

## 特征

- [x] 加载动态库，如果存在则调用 `JNI_OnLoad`
- [x] 加载内存中的动态库
    - [x] arm64
    - [ ] arm
    - [ ] x86
    - [x] x64
- [x] 查找 `.dynsym` 中的符号
- [x] 查找 `.symtab` 中的调试符号
- [x] 查找 `.gnu_debugdata` 中的调试符号
