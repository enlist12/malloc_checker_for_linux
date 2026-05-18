# null-ptr-checker

基于 LLVM IR 的 Linux 内核空指针未检查解引用检测器，不仅限于内存分配函数，而是面向**所有可能返回 NULL 的函数**。同时支持**错误返回值未检查检测**（函数返回负整数 errno 但调用者未检查直接使用）。

目标是发现这类问题：

```c
// 空指针未检查
p = some_func_that_may_return_null(...);
p->field = 1;  // 如果 p 为 NULL，解引用导致空指针访问

// 错误返回值未检查
ret = some_func_that_may_return_error(...);
arr[ret] = val;  // 如果 ret 为负值（如 -ENOMEM），数组索引越界
```

## 整体方法论

本项目采用 **"LLVM 静态分析 + DeepSeek V4 Pro 三轮验证"** 的流水线：

```
Linux 内核 .bc/.ll
       │
       ▼
┌─────────────────────────┐
│   null-ptr-checker      │  第一轮：LLVM 静态分析（9 阶段流水线）
│   全量扫描，生成原始报告 │  输出约 3000 条候选发现
│   (含 NULL + error 两类) │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│  DeepSeek V4 Pro 审核    │  第二轮：AI 辅助逐条验证
│  结合源码、调用上下文、   │  约 370 条标记为候选真实漏洞
│  函数语义进行初筛        │  (NULL 检测约 370 条)
│                          │  (error 检测单独验证)
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│  DeepSeek V4 Pro 复核    │  第三轮：独立交叉验证
│  重新分析每条候选漏洞的   │  最终确认 3 个 NULL 相关真实漏洞
│  触发条件和可达性        │  (confirmed.txt)
└───────────┬─────────────┘
            │
            ▼
       最终报告

```

每轮验证重点关注两个核心问题：

1. **func 是否真的可能返回 NULL**：原先函数内部约束可能很复杂（例如 NULL 路径有 BUG() 守卫、GFP 标志保证永不失败、调用上下文决定了不可达），静态分析难以全部建模
2. **func 返回到 use 之间是否真的没有 check**：包括上游 argc 校验、包装函数保护、跨变量的隐式不变式保护等

## 验证结果摘要

基于 Linux 7.0.2 内核全量扫描，经三轮 DeepSeek V4 Pro 验证后的最终结论：

### NULL 检测

| 漏洞 | 数量 | 触发场景 |
|------|------|---------|
| snd_ctl_new1 | 27 | 极端 OOM + 驱动探测时分配失败返回 NULL，直接传入 `snd_hda_ctl_add()` 解引用 |
| skb_pull_data (btintel) | 1 | `btintel_print_fseq_info()` 长度检查与实际消耗量不匹配，截断蓝牙固件响应可触发 |
| hsr_port_get_hsr | 1 | 端口移除后 prune timer 触发前的窄竞态窗口，netlink 查询可命中 NULL |

**总计：约 2500 条 NULL 静态分析发现 → 约 370 条候选 → 3 个确认真实漏洞（共 29 个发现点）。**

### Error 检测

新增 error miss check 检测后，额外产生约 **475 条** `err:*` 来源的候选报告。经单独验证，**确认真实漏洞 0 条**，全部为误报。主要误报原因：
- 函数调用形式的检查无法穿透（如 `dma_mapping_error()`）
- 结构体字段检查无法追踪（如 `FD_PREPARE` 模式）
- -1 / 哨兵值比较无法识别（`matchErrorCondition` 仅处理与 0 的比较）
- 非错误的负数语义（如 `lower_bound` 的 -1 表示"未找到"）
- UBSAN 插桩路径中的虚假 sink

详细 error 检测验证报告见 `results/verification_report.md`。

其他所有候选（cifs_sb_tlink、xfs_group_get、dm_shift_arg、bio_alloc_bioset、txLock、sock_from_file、bond_opt_get_val、btf_type_skip_modifiers、intel_atomic_*、__genradix_ptr 等）经深入分析均为误报。

主要误报来源（占约 99%）：ERR_PTR 与 NULL 语义混淆（约 350+）、框架设计不变式（约 300+）、隐式语义保证（约 150+）、container_of 永不为 NULL（约 41）、上游验证保护、GFP 标志保证等。

## 目录结构

```
.
├── build.sh
├── Makefile
├── README.md
├── bc.list
├── src/
│   ├── MallocCheckerAnalyzer.h            # 共享数据结构和函数声明
│   ├── MallocCheckerAnalyzerCore.cpp      # 核心分析引擎（~2060 行）
│   ├── MallocCheckerAnalyzerMain.cpp      # 程序入口（9 阶段流水线）
│   ├── MallocCheckerAnalyzerOptions.cpp   # CLI 参数解析与 I/O
│   ├── IndirectCallResolver.h             # MLTA 间接调用解析、结构体字段追踪类型
│   └── IndirectCallResolver.cpp           # MLTA 间接调用解析实现（~800 行）
├── tests/
│   ├── smoke.c                            # 冒烟测试（直接分配、受保护、包装函数等模式）
│   ├── nofail_smoke.c                     # __GFP_NOFAIL 测试
│   └── *.bc                              # 预编译的 bitcode
├── results/
│   ├── result.txt                         # 全量原始扫描结果
│   ├── verification_report.md             # Error 检测验证报告
│   └── sure/
│       ├── confirmed.txt                  # 初始候选列表（第二轮标记为真实，第三轮最终修正）
│       ├── false_positives.txt            # 确认误报
│       ├── verification_report.md         # 第二轮验证报告
│       └── final_verification_report.md   # 第三轮最终验证报告
├── build/
│   └── null-ptr-checker                   # 构建产物（.gitignore 忽略）
└── tools/
    └── IRDumper/                          # LLVM pass 插件工具（写 bitcode 到磁盘）
```

## 检测目标

面向**所有可能返回 NULL 的指针函数**，不仅限于内存分配函数。具体包括两大类：

### 1. 白名单分配函数（精确名称匹配）

- `kmalloc` / `kzalloc` / `kcalloc` / `krealloc`
- `kvmalloc` / `kvzalloc` / `kvcalloc`
- `vmalloc` / `vzalloc` / `vcalloc`
- `kmem_cache_alloc` 系列（含 `_node` / `_zalloc` 变体）
- `kstrdup` / `kstrndup` / `kasprintf` / `kvasprintf`
- `devm_*` 系列（`devm_kmalloc` / `devm_kzalloc` / `devm_kstrdup`）
- `dma_alloc_*` / `usb_alloc_*` 系列
- 各系列对应的 `noprof` 变体

采用**精确白名单函数名匹配**，不是前缀命中。因此 `vmalloc_to_page` 这类虽以 "vmalloc" 开头但实际不是 allocator 的函数不会被误识别。

以下几类**默认不检查**：

- `memdup*` / `kmemdup*` / `vmemdup_user` / `strndup_user`（失败语义为 `ERR_PTR`，不是普通 NULL）

### 2. 跨函数 may-return-null 分析

通过不动点分析自动推导哪些函数的指针返回值可能为 NULL：
- 函数调用了白名单 allocator（且非 `__GFP_NOFAIL`）→ 标记为 may-return-null
- 函数内部 `return NULL` → 标记为 may-return-null
- 函数调用其他 may-return-null 函数 → 传播标记

这使得分析器可以检测类似 `snd_ctl_new1()` 这类非直接 allocator 的 NULL 返回使用。

### 3. 跨函数 may-return-error 分析

通过不动点分析自动推导哪些函数的整数返回值可能为负（errno）：
- 函数内部 `return -Exxx`（负常量）→ 标记为 may-return-error
- 函数调用其他 may-return-error 函数 → 传播标记
- 通过 `phi` / `select` / `load` 传播 error 值流

## 分析流程（9 阶段流水线）

分析器是一个独立可执行程序，不是 `opt` pass。输入为 `.bc` / `.ll` 文件。

1. **Phase 1: 加载模块** — 解析 LLVM IR / bitcode 文件，构建函数查找表；检测 opaque pointer
2. **Phase 2: 构建 MLTA 间接调用数据** — 多层类型分析（MLTA），为间接调用解析可能的目标函数集
3. **Phase 3: 构建调用图** — 建立反向调用关系（每个函数被哪些调用点调用），包括间接调用
4. **Phase 4: 收集 PANIC slab cache** — 识别 `kmem_cache_create` 时带 `PANIC` 标志的永不失败 slab
5. **Phase 5: 计算 may-return-null 函数集** — 跨函数不动点分析，判断哪些函数的指针返回值可能为 NULL
6. **Phase 6: 计算 may-return-error 函数集** — 跨函数不动点分析，判断哪些函数的整数返回值可能为负（errno）
7. **Phase 7: 收集 source** — 从白名单分配函数 + may-return-null 函数的调用点（指针类型）以及 may-return-error 函数的调用点（整数类型）中，经所有过滤策略后识别出候选源
8. **Phase 8: 分析 source → sink** — 从每个 source 出发做前向保守值流传播，找到所有未受保护的使用点（sink），去重排序后输出报告
9. **Phase 9: 写报告** — 输出结果到文件或 stdout

### 值流传播方式

| 传播方式 | 说明 |
|---------|------|
| SSA 直接传播 | 追踪同一函数内 SSA use 链 |
| `bitcast` / `addrspacecast` | 类型转换，值不变 |
| `gep` | 指针偏移，可能为 NULL 的性质不变 |
| `phi` / `select` | 控制流合并 |
| 实参入被调函数 | 追踪到 callee 的对应参数（含间接调用目标） |
| 包装函数返回 | `return` 传播回所有 caller 的调用点 |
| `alloca` 栈槽位 | 局部栈变量的简单 spill/reload |
| 结构体字段 store/load | 同函数内 GEP 写入结构体字段后，从同字段 load 时恢复追踪链 |

### Sink 类型

- 对被追踪指针本身的 `load`
- 对被追踪指针本身的 `store`
- `atomicrmw` / `cmpxchg`
- 明确内存写入类调用的目标参数：`memcpy` / `memmove` / `memset` / `strcpy` / `strscpy` / `strlcpy`

## MLTA 间接调用解析

针对 Linux 内核大量使用函数指针和 ops 结构体的特点，实现了多层类型分析（MLTA）来解析间接调用：

- 通过类型哈希对函数签名进行分组，构建候选目标函数集
- 追踪全局变量初始化列表中的类型信息，将函数指针字段与具体实现关联
- 追踪结构体类型的层间传播（第 0 层 → 第 1 层 → ...，最多 10 层）
- 对每处 `call %funcptr` 尝试解析可能的目标函数集合

**限制**：MLTA 依赖 LLVM typed pointer 的 `getPointerElementType()` API。对于 opaque-pointer IR（新版本 LLVM/clang 默认），MLTA 会被自动禁用。此外，仅维护一个简单的 `GlobalFuncMap`（按地址排序的全局函数列表）用于间接调用目标查找。

## Error 检测

新增 `err:*` source-kind 检测，针对**函数返回负整数 errno 但调用者未检查直接使用**的模式。

### 检测目标

```c
ret = some_func_that_returns_negative_errno(...);
arr[ret] = val;  // ret 可能为 -ENOMEM，用作数组索引导致越界
```

### Error source 识别

- 函数返回类型为整数类型（`isIntegerTy()`）
- 函数内部 `return -Exxx`（负的 `ConstantInt`）或调用了其他 may-return-error 函数
- 不限于特定白名单，通过不动点分析传播

### Error check 匹配

`matchErrorCondition()` 识别以下比较模式：

| 模式 | LLVM IR 形式 | 含义 |
|------|-------------|------|
| `ret < 0` | `icmp slt %ret, 0` | 检查是否为负 |
| `ret <= 0` | `icmp sle %ret, 0` | 检查是否为非正 |
| `ret == 0` | `icmp eq %ret, 0` | 等于 0 = 成功 |
| `ret != 0` | `icmp ne %ret, 0` | 不等于 0 = 失败 |
| `ret >= 0` | `icmp sge %ret, 0` | 非负 = 成功 |
| `ret > 0` | `icmp sgt %ret, 0` | 正数 = 成功 |

`matchErrPtrNonnullCompare()` 额外匹配 ERR_PTR 相关的阈值比较模式（`IS_ERR()` 展开后的 `icmp uge %val, -4095` 等）。

### Error 检测已知限制

1. **仅匹配与 0 的比较**：`== -1`、`== 0xFFFFFFFF` 等哨兵值无法识别
2. **函数调用形式的检查无法穿透**：如 `dma_mapping_error()`、`IS_ERR_OR_NULL()` 等
3. **无法区分语义负值和错误负值**：如 `lower_bound` 的 -1 表示"未找到"而非错误
4. **bool-returning 函数可能误入**：返回 `i1` 的函数若调用了 may-return-error 函数可能被误标记
5. **UBSAN 插桩路径中的虚假 sink**：错误值经过 UBSAN 运行时检查时，UBSAN 内部的 load 被误报为 sink

详细验证见 `results/verification_report.md`。

## 降低误报的保守裁剪（8 项）

当前版本**优先压低误报**，因此做了以下激进裁剪：

1. **白名单精确匹配**：不做前缀匹配，避免 `vmalloc_to_page` 等误识别
2. **外层 wrapper 优先**：`kzalloc_obj` / `kmalloc_obj` 优先于底层的 `__kmalloc` 等实现，避免双重上报
3. **NULL 比较即剪枝**：只要分配返回值在值流中出现过 `NULL` 比较（含 phi/select/gep/cast 传播和 `return -> caller` 跨函数返回链），该 source 直接丢弃
4. **`__GFP_NOFAIL` 跳过**：不仅支持直接常量，也支持 `flags | __GFP_NOFAIL` 和 wrapper 中的参数转发。对于 `kmem_cache_alloc*`，还检查 slab cache 创建时的 `PANIC` 标志
5. **dup 家族整体排除**：`memdup*` / `kmemdup*` / `vmemdup_user` / `strndup_user`（ERR_PTR 语义）
6. **`.init.text` / `__init` 代码跳过**：启动期初始化失败不属于运行期关注的漏洞
7. **释放函数终止传播**：`kfree` / `kvfree` / `vfree` / `kmem_cache_free` 等不作为 sink，也不继续向内传播
8. **增强 null-check 条件匹配**：识别 `select` 指令表达的短路求值模式（`A && B` / `A || B`），以及 `and`/`or` 组合条件中的多变量联合检查

## 已知限制

当前版本存在以下限制：

### 间接调用部分支持

已实现 MLTA（多层类型分析）来解析间接调用，但存在以下局限：

- 仅支持 typed-pointer IR：对于 opaque-pointer IR（新版本 LLVM/clang 默认），MLTA 自动禁用，间接调用完全不追踪
- 类型分析精度有限：最多 10 层类型传播，最多 50 个间接调用目标
- 跨模块类型匹配：不同 `.bc` 文件中相同结构体的类型哈希可能不一致，依赖 fuzzy type matching
- 函数指针存储到全局变量之外的路径（如堆上分配、动态注册）无法追踪

### 结构体字段追踪部分支持

已实现同函数内的结构体字段 store/load 回读追踪，但存在以下局限：

- **仅限同函数内**：store 和 load 必须在同一个函数中，跨函数的 struct 字段传播不追踪
- **BasePtr 匹配**：通过 stripPointerCasts 后的 base pointer 匹配，不支持跨别名的 base pointer 匹配
- **嵌套结构体（`a->b->ptr`）**：多层 GEP 索引的嵌套字段 store/load 已支持（通过 `StructFieldKey::Indices` 链），但 base pointer 必须严格一致
- **堆对象字段、全局对象字段**：不追踪（`alloca` 之外的内存对象）
- **跨函数 struct 传播**：若 struct 通过参数传递给 callee，callee 内对字段的访问无法与 caller 的 store 关联

### Error 检测限制

参见上方 [Error 检测已知限制](#error-检测已知限制)。

### 其他限制

- **非完整路径敏感**：不区分不同调用路径上的值状态差异
- **不追踪复杂别名**：指针间的别名关系不做精细建模
- **ERR_PTR 语义不识别**：`IS_ERR()` 与 `NULL` 检查是两种不同的保护方式，当前工具会将 ERR_PTR 返回函数误报为"未做 NULL 检查"（这是误报的最大来源，约 350+ 条）
- **跨变量不变式不可见**：如 `new_state != NULL ⇒ old_state != NULL` 这类设计不变式无法建模
- **NULL 比较裁剪过于激进**：只要值流中出现过 NULL 比较就裁掉 source，会漏掉"比较存在但不能真正保护 sink"的情况
- **不识别复杂错误处理宏**：如 `IS_ERR_OR_NULL()`、`BUG_ON()`、`WARN_ON()` 等

由于以上限制，本工具更适合作为：

- 第一轮快速筛查工具
- 辅助人工/AI 复核的候选生成器

不适合作为"零误报、零漏报"的最终结论工具。

## 可能的漏报来源

即使通过了 LLVM 静态分析 + DeepSeek V4 Pro 三轮验证，仍可能存在以下漏报原因：

### 1. LLM 幻觉导致真实漏洞被误判为误报

第三轮 AI 验证中，模型可能：

- 对复杂函数语义产生错误理解，将"其实无法保证非 NULL"的情况错误推断为"永远安全"
- 在缺少完整调用上下文时，过度信任代码注释或函数命名，做出过于乐观的安全假设
- 验证规模过大时（约 370 条候选），注意力衰减可能导致部分条目分析不充分

缓解措施：最终确认的 `confirmed.txt` 仅 3 个漏洞，拒绝率约 99%。高拒绝率本身意味着大量"真实漏洞可能被误杀"的风险。

### 2. 函数过于底层或复杂导致静态分析失败

- **间接调用**：已通过 MLTA 部分支持，但 opaque-pointer IR 下完全禁用，typed-pointer IR 下也有类型分析精度和函数指针存储路径的局限
- **深度内联/优化破坏可追踪性**：编译器优化可能将多级 wrapper 内联合并，使得原本清晰的 `alloc → check → use` 模式在 IR 层面变得模糊
- **复杂的 PHI/分支结构**：某些函数的 NULL 路径经过多层嵌套分支，静态分析在有限深度内无法推断其返回值可能为 NULL，导致该函数根本不会进入 `MayReturnNullFunctions` 集合

### 3. .bc 文件覆盖度受内核配置影响

- 本项目的 `.bc` 文件来自特定内核配置（`defconfig` 或类似配置）的编译导出
- 不同配置（`allyesconfig`、`allmodconfig`、特定架构/驱动配置）会包含不同的源文件集合
- 条件编译（`#ifdef CONFIG_XXX`）会使同一文件在不同配置下编译出不同的函数集合
- 这意味着：**被本次扫描覆盖的代码子集之外，可能存在未被分析的分配-解引用模式**
- 此外，内联汇编（`asm`）中的内存访问完全不可见于 LLVM IR

### 与其他漏报来源的关系

以上三项并非独立：底层函数的静态分析失败（来源 2）× 有限的配置覆盖（来源 3）= 某些子系统中的漏洞可能从 pipeline 最前端就不可见。而 LLM 幻觉（来源 1）则作用于 pipeline 后端，可能导致本可识别的漏洞在验证环节被过滤。

## 构建

要求：

- `clang++-15`
- `llvm-config-15`

```bash
./build.sh
# 或
make
```

产物：

```
./build/null-ptr-checker
```

同时构建 analyzer 与 IRDumper：

```bash
make analyzer
make irdumper
```

## 使用方法

### 直接分析

```bash
./build/null-ptr-checker input.bc
./build/null-ptr-checker input.ll
```

### 分析多个文件

```bash
./build/null-ptr-checker a.bc b.bc c.bc
```

### 文件列表输入

```bash
./build/null-ptr-checker --bc-list files.list
./build/null-ptr-checker files.list   # 自动识别 .list 后缀
```

### 输出到文件

```bash
./build/null-ptr-checker input.bc -filename result.txt
```

## 常用参数

| 参数 | 说明 |
|------|------|
| `--bc-list` | 从列表文件读取输入路径 |
| `-filename` | 指定输出文件，默认标准输出 |
| `--show-progress` | 打印进度日志到 stderr |
| `--progress-interval` | 每隔 N 个 source 打印一次进度（默认 100） |
| `--max-call-depth` | 最大跨函数传播深度（默认 6） |
| `--max-visits-per-source` | 每个 source 最多展开状态数（默认 20000） |

## 输出格式

```
[1] unchecked nullable return use
  source-kind: kmalloc
  source-func: foo
  source-loc:  fs/x.c:10
  sink-func:  bar
  sink-kind:  store
  sink-loc:   fs/y.c:42
  call-chain:
    foo -> bar @ fs/y.c:40
```

字段含义：

- `source-kind`: 识别到的分配函数类别，或 `may-return-null` 函数名，或 `err:<funcname>`（error 检测源）
- `source-func`: 分配/调用发生的函数
- `source-loc`: 分配/调用点源码位置
- `sink-func`: sink 所在函数
- `sink-kind`: sink 类型（`load` / `store` / `atomicrmw` / `cmpxchg` / `call-arg-deref`）
- `sink-loc`: sink 源码位置
- `call-chain`: 跨函数传播链

## 代码结构

| 文件 | 说明 |
|------|------|
| `MallocCheckerAnalyzer.h` | 共享数据结构声明（`Report`, `Source`, `AnalysisState` 等） |
| `MallocCheckerAnalyzerMain.cpp` | 程序入口，9 阶段流水线编排 |
| `MallocCheckerAnalyzerOptions.cpp` | CLI 参数解析、输入输出设置 |
| `MallocCheckerAnalyzerCore.cpp` | 核心分析逻辑（白名单、NULL/error 值流传播、sink 检测、条件匹配等） |
| `IndirectCallResolver.h` | MLTA 间接调用解析声明及结构体字段追踪类型 |
| `IndirectCallResolver.cpp` | MLTA 间接调用解析实现（类型哈希、层间传播、目标函数约束等） |
| `build.sh` | 构建脚本 |
| `Makefile` | 顶层构建入口 |
| `tools/IRDumper/` | LLVM pass 插件工具（写 bitcode 到磁盘） |

## 后续改进方向

如果后续要继续提升检测质量，建议优先做：

1. **间接调用解析增强**：提升 opaque-pointer IR 下的间接调用解析能力（当前 MLTA 仅在 typed-pointer IR 下工作）；扩大函数指针存储路径的追踪范围（当前仅覆盖全局变量初始化列表）
2. **跨函数结构体字段追踪**：将 struct 字段传播从同函数扩展到跨函数边界（当前已实现同函数内的 store/load 回读）
3. **ERR_PTR 语义识别**：识别 `IS_ERR()` / `IS_ERR_OR_NULL()` / `PTR_ERR()` 等模式，不再将 ERR_PTR 返回函数误报为 NULL 未检查
4. **Error check 增强**：扩展 `matchErrorCondition` 支持与 -1 等哨兵值的比较；识别函数调用形式的 error check（如 `dma_mapping_error()`）
5. **更精细的 null-check 建模**：避免"出现过 NULL 比较就裁掉 source"的过度保守策略
6. **跨变量不变式推理**：识别类似 `new_state != NULL ⇒ old_state != NULL` 的配对保证
7. **Linux 常见错误处理宏语义识别**：`BUG_ON`、`WARN_ON`、`likely/unlikely` 等
