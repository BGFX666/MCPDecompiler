# MCPDecompiler (Python 并发版)

高性能的 `.mcp` 脚本包解包 / 解密工具，是 MCPDecompiler C# 版（Rotor.Crypto.dll）的纯 Python 移植。支持把 `.mcp` 容器内的全部加密脚本批量还原为 Python 2.7 字节码（`.pyc`），并可选调用 uncompyle6 反编译回 `.py` 源码。

## 特性

- **纯 Python 实现 Rotor 转子密码**：从 `Rotor.Crypto.dll`（IDA 逆向）移植，无任何原生依赖
- **多进程并发**：`ProcessPoolExecutor` 绕过 GIL；worker 内 Rotor 状态只初始化一次，之后每个文件仅复位 6 字节里程计
- **mmap 零拷贝**：mcp 数据按批从内存映射中切片，避免大文件重复读取
- **Marshal 重建**：三遍 `r_object` 与 C# 版逐 case 对应（含字符串 intern 去重、XOR / RC4 加密字符串还原、opcode 重映射）
- **诱饵函数修复**：自动识别并替换加密诱饵函数（`*_01dVersi0n` 等后缀），等价于 FixFinal.py 后处理，可用 `--no-fix` 关闭
- **一键反编译**：`--decompile` 自动编排 Python 2.7 子进程并发运行 uncompyle6

## 环境要求

- Python 3.6+（解包阶段，无第三方依赖）
- 可选：Python 2.7 + uncompyle6（仅 `--decompile` 反编译阶段需要）

## 用法

```bash
# 解包整个 mcp 容器
python mcp_decompile.py 3715.mcp [-o OUTPUT_DIR] [-w WORKERS]

# 解包后自动反编译为 .py 源码（需 Python 2.7 + uncompyle6）
python mcp_decompile.py 3715.mcp --decompile --py2 C:\Python27\python.exe

# 单个 mcs 文件解包
python mcp_decompile.py --mcs some.mcs [-o out.mcs]
```

| 参数 | 说明 |
| --- | --- |
| `input` | 输入的 `.mcp` 文件（或配合 `--mcs` 的单个 `.mcs` 文件） |
| `-o, --outdir` | 输出目录，默认为 mcp 文件名去扩展名 |
| `-w, --workers` | 并发 worker 数，默认 `min(CPU 核数, 16)` |
| `--mcs` | 输入是单个 mcs 文件 |
| `--decompile` | 解包后自动调用 uncompyle6 反编译出 `.py` |
| `--py2` | Python 2.7 解释器路径，默认 `C:\Python27\python.exe` |
| `--no-fix` | 不替换加密诱饵函数 |

输出为带 Python 2.7 magic header 的 `.pyc` 文件，按包内原始目录结构写入输出目录；`--decompile` 时源码写入 `<输出目录>_src`。

## 实现说明

- Rotor 转子密码：DLL 中每次 `Decrypt` 调用前状态都会复位，因此每个文件可完全独立解密，这是整体可并行的前提。
- opcode 重映射：code object 尾部的 magic 值区分 vanilla / mod 两套 opcode 映射表（`OPCODE_MAGIC_VANILLA` / `OPCODE_MAGIC_MOD`）。
- Marshal 解析保留了 C# 版的原始字节级行为（包括个别边界 bug），以最大化与原实现产物的兼容性。

## 免责声明

本项目仅用于对自有资源做格式研究、互操作与安全分析，请遵守当地法律及目标软件的服务条款，勿用于侵权用途。

## License

MIT
