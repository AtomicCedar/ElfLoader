# ElfLoader 扩展计划清单

## P1 高价值 · 低风险

### 1. 加载后符号查询统一 API 【已完成】
- [x] `load()` 后记录基址，提供 `getLoadedBase(libraryId)` / `getLoadedSymbols(libraryId)` / `getLoadedSymbolAddress(libraryId, symbol)`
- [x] 实现：`ElfImg(byte[], base, boolean)` 从内存 ELF 字节解析；load 成功后从 `/proc/self/maps` 定位 `/memfd:<id>` 基址并缓存；真样本验证地址精确（base+st_value）
- 价值：现在 load 完只能靠 dlsym；查 `.gnu_debugdata`/隐藏符号需要知道基址 + 本地解析
- 参考：bionic `dl_iterate_phdr` 是公开 API（API 21+），可拿每个 so 的 base + phdr

### 2. `dlopen` 失败原因透出 【评估后不采纳】
- dlerror 字符串已透传给 `UnsatisfiedLinkError`，包含 linker 的具体原因（"library ... not found"/"has invalid ELF header" 等）
- 错误码分类须解析 linker 文本，跨版本脆弱，收益不值得

### 3. 多份同名 so 共存加载 【已确认无需改动】
- [x] 内存加载天然支持：每次 `memfd_create` 产生新 inode，linker 去重按 `st_dev+st_ino+offset`（AOSP linker.cpp `find_loaded_library_by_inode`），不同实例互不冲突
- 文件加载（`load(String)`）受 dlopen 语义限制不支持多实例（同 inode 返回已有 soinfo）

## P2 中价值 · 中等难度

### 5. so 加载后自动执行自定义入口 【已完成】
- [x] `load(byte[], String libraryId, String entrySymbol)` / `load(String path, String entrySymbol)`：entry 非空时写入 shellcode 的 entry 名槽位，替换默认 `JNI_OnLoad`
- [x] 符号不存在时 shellcode 的 null 检查（CBZ）跳过调用，安全降级

### 6. 16 KB page size 兼容 【已完成，无需代码改动】
- [x] `Os.mmap(0, u.pageSize(), …)` 动态取页大小，16K 页自动适配；`SHELLCODE_SIZE=0x200` + path/entry/fd 均远小于 16K，单页布局假设成立

## P3 可选 · 实验性

### 8. 内存加载的 fd 直传扩展 【shellcode 已重写；fd 直传保持 arm64】
- [x] 三份 shellcode（x86_64/arm/x86）全部改走 `android_dlopen_ext(name, flags, extinfo)`：extinfo 结构随槽位链写入页内，flags=0 时等价 dlopen（文件加载路径不变）
- [x] x86_64 新 shellcode 经 qemu + 真 bionic API25 实测：android_dlopen_ext 3 参调用 + JNI_OnLoad 返回 0x10006 PASS
- [x] fd 直传（USE_LIBRARY_FD）保持 arm64 专属（已实测）；x86_64 下 qemu-user 无法验证 fd 路径（guest stat 翻译缺陷，C 直接调用 android_dlopen_ext 也复现），故三新架构内存加载维持 `/proc/self/fd/N`，语义与原实现一致
- 收益：全架构统一 android_dlopen_ext 入口，为后续 fd 直传扩展铺路；Houdini 桥回退路径保留

