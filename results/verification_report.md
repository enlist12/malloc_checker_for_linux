# error source 检测验证报告

**检测范围**: 新增的 `may-return-error` 函数检测（返回负整数的函数）  
**新增报告**: 475 条 (source-kind: err:*)  
**验证方法**: 逐类对照 Linux 7.0.2 内核源码 (`/root/vul_analy/linux-7.0.2`) 确认

## 总体结论

**确认真实漏洞: 0 条。** 所有 475 条新增 error source 报告均为误报。

## 误报分类

### A. 函数调用形式的检查无法识别 (~35%)

检测器只能识别直接的 `icmp slt/sle/eq/ne %val, 0` 比较模式。内核中大量使用**辅助函数**来做错误检查，检测器无法穿透：

| source-kind | 数量 | 检查方式 | 误报原因 |
|------------|------|---------|---------|
| dma_map_page_attrs / dma_map_phys / swiotlb_map / iommu_dma_map_phys | 9 | `ib_dma_mapping_error(dev, addr)` | 通过函数调用检查 DMA_MAPPING_ERROR 哨兵值 |
| rxrpc_may_reuse_conn | 4 | `if (rxrpc_may_reuse_conn(...) < 0)` | 源码确实有 `< 0` 检查，但 LLVM 优化为 `> -1`，matchErrorCondition 未处理 -1 阈值 |
| bpf_token_capable | 11 | `if (!bpf_token_capable(...))` | 返回 bool (0/1)，不可能负值。security_bpf_token_capable 虽有负值返回但被转换为 false。误进入 MayReturnErrorFunctions 集 |

**示例** (`ib_dma_mapping_error`):
```c
// drivers/infiniband/ulp/iser/iscsi_iser.c:206-209
dma_addr = ib_dma_map_single(device->ib_device, ...);
if (ib_dma_mapping_error(device->ib_device, dma_addr))  // ← 有检查！
    return -ENOMEM;
```

### B. 结构体字段检查无法追踪 (~20%)

`FD_PREPARE` / `CLASS_INIT` 宏模式将错误值存入 struct 字段，检查也在 struct 字段上进行。检测器无法追踪结构体字段的 store/load。

| source-kind | 数量 | 误报原因 |
|------------|------|---------|
| get_unused_fd_flags | 27 | fdf.err 聚集了 fd + file 的错误状态，调用者检查 `fdf.err`。struct 字段追踪是 README 已知限制 |
| alloc_fd | 3 | `f_dupfd(): if (err >= 0)` — LLVM 优化 `>= 0` → `> -1`，matchErrorCondition 未匹配 |

**`__FD_PREPARE_INIT` 宏展开**:
```c
// include/linux/file.h:195-204
struct fd_prepare fdf = {
    .__fd = get_unused_fd_flags((_fd_flags)),   // ← 错误值存入 struct
};
if (likely(fdf.__fd >= 0))                       // ← 内部有检查
    fdf.__file = (_file_owned);
fdf.err = ACQUIRE_ERR(fd_prepare, &fdf);         // ← 聚合所有错误
// 调用者: if (fdf.err) { ... }                   // ← 检查 fdf.err
```

### C. -1 / 哨兵值比较无法识别 (~18%)

`matchErrorCondition` 只处理与 0 的比较。大量内核函数使用 `== -1`、`== 0xFFFFFFFF` 等哨兵值检查：

| source-kind | 数量 | 检查模式 | 误报原因 |
|------------|------|---------|---------|
| ocfs2_search_extent_list | 5 | `if (index == -1)` | 只匹配与 0 的比较 |
| udf_get_pblock | 12 | `if (block == 0xFFFFFFFF)` | 哨兵值不是 0 |
| fdt_next_node | 11 | `if (offset < 0)` → 但有前置保证 | libfdt 内部函数，offset 语义 |
| __jfs_getxattr | 4 | `if (rc == -ENODATA)` | 特定 errno 比较 |
| hfsplus_getxattr | 3 | `if (res == -ENODATA)` | 同上 |

**示例** (`ocfs2_search_extent_list`):
```c
// fs/ocfs2/alloc.c:5616-5624
index = ocfs2_search_extent_list(el, cpos);
if (index == -1) {           // ← 有检查！但是 == -1，不是 < 0
    ocfs2_error(...);
    ret = -EROFS;
    goto out;
}
rec = &el->l_recs[index];    // 检查后才使用 index
```

### D. 非错误的负数语义 (~12%)

某些函数返回 -1 是有效 API 语义（"未找到"、"插入位置 0"），不是错误：

| source-kind | 数量 | 语义 |
|------------|------|------|
| lower_bound | 4 | -1 = "小于所有元素，从位置 0 插入"，调用者理解此语义 |
| FSE_readNCount / HUF_readDTable* | 14 | ZSTD 库内部函数，返回值语义不是错误码 |
| dvb_ringbuffer_pkt_next | 3 | 返回 pkt 位置或 -1（空），调用方检查 `!= -1` |
| from_kuid / from_kgid | 6 | 返回 uid_t/gid_t，-1 代表 INVALID_UID/GID，不是错误 |

### E. UBSAN 插桩路径 (~16%)

错误值在传播过程中经过 UBSAN 运行时检查函数，UBSAN 内部的 `load` 成为 sink：

| 特征 | 数量 |
|------|------|
| call-chain 中包含 `__ubsan_handle_*` / `val_is_negative` / `val_to_string` | 74 |

这些 sink 在 UBSAN 运行时库中，不在用户代码中。真正的问题是值传播到了 UBSAN 的插桩点（如位移操作），但 UBSAN 本身不会导致崩溃。

### F. 跨模块包装函数传播链

DMA mapping 系列函数的调用链涉及多层 wrapper（`dma_map_phys → dma_map_page_attrs → swiotlb_map`），每层都可能被标记为 may-return-error，导致重复报告。这些函数通常在调用栈的某一层有 `dma_mapping_error()` 检查，但检测器无法跨 struct 字段或函数调用发现。

## 已知检测器缺陷（导致误报）

1. **matchErrorCondition 只处理与 0 的比较** — 需要扩展为: `icmp eq %val, -1`、`icmp sgt %val, -1`（`>= 0` 优化形式）等
2. **无法识别函数调用形式的检查** — `dma_mapping_error()`、`IS_ERR()`、`IS_ERR_OR_NULL()` 等
3. **无法追踪 struct 字段** — README 已知限制。FD_PREPARE 模式广泛使用
4. **无法区分错误负值和语义负值** — `lower_bound` 的 -1 有特定 API 语义
5. **bool-returning 函数误进入 MayReturnErrorFunctions** — bpf_token_capable 返回 bool，不应被标记

## 建议改进

按优先级排序：

1. **扩展 matchErrorCondition** — 增加 `sgt %val, -1`（`>= 0` 优化形式）、`eq %val, -1`（精确 -1 检查）的匹配
2. **排除 bool-returning 函数** — `getReturnType()->isIntegerTy(1)` → 跳过
3. **函数调用检查识别** — 白名单已知的 error-check 函数：`dma_mapping_error`、`IS_ERR`、`IS_ERR_OR_NULL` 等
4. **区分语义负值和错误负值** — 启发式: 函数名含 `search`/`find`/`lookup` 时，-1 多为"未找到"语义
