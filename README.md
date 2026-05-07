# malloc_checker

基于 LLVM IR 的 Linux 内存分配返回值未检查检测器。

目标是发现这类问题：

```c
p = kmalloc(...);
p->field = 1;
```

如果 `kmalloc` 失败，`p` 为 `NULL`，后续解引用会导致空指针访问。

当前实现输入为 `.bc` / `.ll` 文件，输出“分配点 -> 解引用点”的报告。

## 当前版本的主要修改

为了降低 Linux 内核大规模 IR 上的误报，当前版本相对最初原型做了几类重要收敛：

1. source 识别改成了白名单，而不是宽松前缀匹配。

这可以避免把 `vmalloc_to_page` 这类“名字前缀像 allocator，但实际不是 allocator”的函数误识别成分配源。

2. 外层 allocator wrapper 优先于底层 `__` 系列实现。

例如：

- `kzalloc_obj`
- `kmalloc_obj`
- `kmalloc_node`

这类外层接口会优先作为 source；
而像 `__kmalloc`、`__kmalloc_node_track_caller_noprof` 这种底层实现，在明显处于 wrapper 内部时会降级，不优先从底层起报。

3. 只要分配返回值在值流中出现过 `NULL` 比较，就直接裁掉该 source。

并且这个裁剪支持：

- 函数内 SSA 传播
- `phi/select/gep/cast`
- 简单栈槽位 `store/load`
- `return -> caller` 的跨函数返回链

因此像“包装函数返回后，调用点立即 `if (!p)` 检查”这种情况也会被裁掉。

4. `__GFP_NOFAIL` 分配直接跳过。

不仅支持直接常量 flags，也支持：

- `flags | __GFP_NOFAIL`
- `gfp` 作为参数在 wrapper 中层层转发

只要最终可回溯到 `__GFP_NOFAIL`，就会被视为不可失败分配并跳过。

5. 若干内部已封装错误语义的 API 家族被整体排除。

当前默认不检查：

- `memdup*`
- `kmemdup*`
- `vmemdup_user`
- `strndup_user`

原因是它们常带有内部错误路径、`ERR_PTR` 语义，继续按“普通可能返回 `NULL` 的分配”分析会显著放大误报。

6. `.init.text` / `__init` 代码整体跳过。

启动期初始化失败通常不属于当前更关注的运行期问题，继续纳入只会增加噪声。

7. 释放函数不再作为 sink，也不再向内传播。

当前把下面这类释放族函数当作终止点：

- `kfree`
- `kvfree`
- `vfree`
- `kmem_cache_free`
- `kfree_sensitive`
- `kfree_const`
- `free_percpu`

这样可以避免把 `kfree(NULL)` 之类合法路径一路追进 `slub` 调试代码，再在 `memchr_inv`、`check_object` 之类内部函数上产生假阳性。

## 检测目标

重点关注 Linux 内核中常见的返回指针的分配函数，例如：

- `kmalloc`
- `kzalloc`
- `kcalloc`
- `krealloc`
- `kvmalloc`
- `kvzalloc`
- `vmalloc`
- `vzalloc`
- `kmem_cache_alloc`
- `kstrdup`
- `kstrndup`
- `kasprintf`
- `devm_kmalloc`
- `devm_kzalloc`
- `devm_kstrdup`

代码里采用的是“前缀匹配”，因此也覆盖诸如 `__kmalloc`、`kmem_cache_alloc_noprof`、`krealloc_node_align_noprof` 这类变体。

当前 source 识别已经改成“明确白名单函数名”，不是任意前缀命中。

以下几类当前默认不检查：

- `memdup*`
- `kmemdup*`
- `vmemdup_user`
- `strndup_user`

原因是这类接口经常把失败编码为内部错误路径或 `ERR_PTR` 语义，继续按“普通可能返回 `NULL` 的分配”处理会产生大量误报。

## 当前实现思路

分析器是一个独立可执行程序，不是 `opt` pass。

整体流程：

1. 读取一个或多个 LLVM IR / bitcode 模块。
2. 扫描所有调用点，识别内存分配 source。
3. 从 source 出发做保守的值流传播。
4. 找可能的 sink。
5. 输出分配点和对应 sink。

当前保留的传播方式：

- SSA 直接传播
- `bitcast` / `addrspacecast`
- `gep`
- `phi`
- `select`
- 实参进入被调函数
- 包装函数返回到调用点
- 局部 `alloca` 栈槽位上的简单 `store/load`

当前 sink 主要包括：

- 对被追踪指针本身的 `load`
- 对被追踪指针本身的 `store`
- `atomicrmw`
- `cmpxchg`
- 明确的内存写类调用目标参数，例如：
  - `memcpy`
  - `memmove`
  - `memset`
  - `strcpy`
  - `strscpy`
  - `strlcpy`

## 为降低误报做的保守裁剪

当前版本优先压低误报，因此做了几条比较激进的裁剪：

1. 只要某个分配返回值在其后续值流里出现过 `NULL` 比较，这个 source 就直接不再追踪。

例如：

```llvm
%p = call ptr @kmalloc(...)
%cmp = icmp eq ptr %p, null
br i1 %cmp, ...
```

这种 source 会被直接过滤。

2. 带 `__GFP_NOFAIL` 的分配直接跳过。

例如：

```c
p = kmalloc(size, GFP_KERNEL | __GFP_NOFAIL);
```

这类分配在 Linux 语义下应视为“不会以 `NULL` 失败返回”，因此当前不会作为候选 source。

3. `memdup*` / `kmemdup*` / `vmemdup_user` / `strndup_user` 默认不检查。

例如：

```c
res = memdup_user(in, len);
if (!IS_ERR(res))
    use(res);
```

这类接口的失败处理通常封装在内部，返回值语义也往往不是“普通 `NULL` 指针失败”，继续纳入当前规则会显著增加误报。

4. 不再追踪结构体字段、堆对象字段、全局对象上的泛化 `store/load` 回读。

只保留局部 `alloca` 栈槽位上的简单 spill / reload。

5. `call-arg-deref` 被大幅收紧，只保留高置信度目标参数。

6. `kfree` / `kvfree` / `vfree` 等释放族函数不会作为 sink，也不会继续向其内部传播。

这样做的结果是：

- 误报会明显下降
- 漏报会增加

也就是说，当前版本更偏“保守报警”而不是“尽量全报”。

## 已知限制

当前版本有这些限制：

- 不是完整路径敏感分析
- 不追踪复杂别名
- 不追踪结构体字段写回后的普遍回读
- 只支持直接调用，不处理完整的间接调用目标集合
- 只做比较保守的 null-check 裁剪，不理解更复杂的错误处理宏语义
- 为降低误报，只要出现过 `NULL` 比较就会裁掉 source，这会漏掉“比较存在但不能真正保护 sink”的情况

因此它更适合作为：

- 第一轮快速筛查工具
- 辅助人工复核的候选生成器

不适合作为“零误报、零漏报”的最终结论工具。

## 构建

要求：

- `clang++-15`
- `llvm-config-15`

构建：

```bash
./build.sh
```

产物：

```bash
./malloc-checker-analyzer
```

## 使用方法

### 1. 直接分析单个 `.bc` / `.ll`

```bash
./malloc-checker-analyzer input.bc
./malloc-checker-analyzer input.ll
```

### 2. 分析多个文件

```bash
./malloc-checker-analyzer a.bc b.bc c.bc
```

### 3. 通过列表文件输入

```bash
./malloc-checker-analyzer --bc-list files.list
```

或者：

```bash
./malloc-checker-analyzer files.list
```

其中 `files.list` 每行一个路径。

### 4. 输出到文件

```bash
./malloc-checker-analyzer input.bc -filename result.txt
```

## 常用参数

- `--bc-list`
  - 从列表文件读取输入路径
- `-filename`
  - 指定输出文件，默认标准输出
- `--show-progress`
  - 是否打印进度日志
- `--progress-interval`
  - 每隔多少个 source 打印一次进度
- `--max-call-depth`
  - 最大跨函数传播深度
- `--max-visits-per-source`
  - 每个 source 最多展开多少个状态

## 输出格式

报告示例：

```text
[1] unchecked allocation use
  alloc-kind: kmalloc
  alloc-func: foo
  alloc-loc:  fs/x.c:10
  sink-func:  bar
  sink-kind:  store
  sink-loc:   fs/y.c:42
  call-chain:
    foo -> bar @ fs/y.c:40
```

字段含义：

- `alloc-kind`: 识别到的分配函数类别
- `alloc-func`: 分配发生的函数
- `alloc-loc`: 分配点源码位置
- `sink-func`: sink 所在函数
- `sink-kind`: sink 类型
- `sink-loc`: sink 源码位置
- `call-chain`: 跨函数传播链

## 代码结构

- `MallocCheckerAnalyzerMain.cpp`
  - 程序入口
- `MallocCheckerAnalyzerOptions.cpp`
  - 命令行参数、输入输出选项
- `MallocCheckerAnalyzerCore.cpp`
  - 核心分析逻辑
- `MallocCheckerAnalyzer.h`
  - 共享数据结构声明
- `build.sh`
  - 构建脚本

## 后续改进方向

如果后续要继续提升质量，建议优先做：

1. 更精细的 null-check 建模
2. 结构体字段 / 堆字段的受限回读传播
3. 更准确的 sink 分类
4. 更好的调用上下文裁剪
5. 对 Linux 常见错误处理宏的语义识别
