[![Read in English](https://img.shields.io/badge/Language-Read%20in%20English-blue)](README.en.md)

# MCP-Frida-Agent 高级内存指针操作框架

这个项目提供了一套强大的Frida Native API的RPC封装系统，让开发者能够从Node.js端安全、高效地操作目标进程的内存指针和系统资源。该框架不仅支持基础的内存读写，还集成了进程操作、网络通信、代码执行跟踪和内核交互等高级功能。无论是游戏分析、安全研究还是性能调优，MCP-Frida-Agent都能成为您不可或缺的工具。

## 核心优势

- 全面封装Frida所有核心API，包括NativePointer、Memory、Process、Socket、Stalker、Interceptor和Kernel
- 设计精良的RPC接口架构，确保远程操作的稳定性和效率
- 严格的类型安全设计，提供TypeScript类型定义，减少运行时错误
- 完善的错误处理机制，所有API均返回标准化结果对象，提供清晰的错误反馈
- 支持多种内存读写操作，包括各种数据类型和格式的读写
- 批量操作支持，提高大规模内存操作的效率
- 高性能实现，最小化跨进程通信开销
- 完整的文档和示例，降低学习门槛

## 功能特点

- **全面的指针操作**：支持所有NativePointer操作，包括算术运算、比较、位运算等
- **多样数据类型支持**：读写各种数据类型，从基本的整数到浮点数、字符串和指针
- **内存管理**：内存分配、保护、复制和执行补丁等功能
- **进程操作**：获取进程信息、枚举模块和内存区域、线程管理等
- **网络功能**：Socket监听、连接、数据发送和接收
- **执行跟踪**：使用Stalker API进行代码执行跟踪和事件监控
- **函数拦截**：通过Interceptor API拦截和修改函数调用
- **内核交互**：支持与系统内核的交互操作（在支持的平台上）
- **批量操作**：高效执行批量内存操作，减少RPC调用开销
- **错误保护**：完善的错误检测和处理机制，防止崩溃和安全问题
- **跨平台**：支持Windows、Linux、macOS和Android平台
- **扩展性**：模块化设计，易于扩展和定制

## 快速开始

### 安装

```bash
# 克隆仓库
git clone https://github.com/iconFehu/mcp-frida-agent.git
cd mcp-frida-agent

# 安装依赖
npm install

# 构建项目
npm run build
```

### 基本使用流程

1. **安装并配置环境**
   - 确保已安装Node.js和npm
   - 安装Frida CLI工具：`npm install -g frida-tools`

2. **集成到您的项目**
   - 安装依赖：`npm install mcp-frida-agent`
   - 引入包：`import { MCP } from 'mcp-frida-agent'`

3. **连接目标进程**
   - 通过进程名、PID或USB设备连接
   - 支持注入、附加和启动模式

4. **执行内存操作**
   - 创建和操作内存指针
   - 读写各种数据类型
   - 使用高级功能如进程分析、函数拦截等

### 代码示例

以下是一个完整的示例，展示如何使用MCP-Frida-Agent探索内存：

```javascript
import frida from 'frida';
import fs from 'fs';

async function main() {
  try {
    // 附加到目标进程
    console.log("⚡ 正在附加到目标进程...");
    const session = await frida.attach("target-process");
    
    // 加载Agent脚本
    console.log("📜 正在加载Agent脚本...");
    const script = await session.createScript(fs.readFileSync('./dist/_agent.js', 'utf8'));
    await script.load();
    
    // 获取RPC接口
    const api = script.exports;
    console.log("🔗 RPC接口已准备就绪!");
    
    // 创建一个指针 (例如，指向一个已知的内存地址)
    const baseAddress = "0x12345678";
    console.log(`🔍 正在创建指针: ${baseAddress}`);
    const result = await api.nativePointerCreate(baseAddress);
    
    if (result.success) {
      const pointerStr = result.data.address;
      console.log(`✅ 指针创建成功: ${pointerStr}`);
      
      // 读取内存中的32位无符号整数
      const readResult = await api.nativePointerReadU32(pointerStr);
      if (readResult.success) {
        console.log(`📖 读取到的U32值: ${readResult.data.value} (0x${readResult.data.value.toString(16)})`);
        
        // 指针偏移操作
        const offsetResult = await api.nativePointerAdd(pointerStr, 4);
        if (offsetResult.success) {
          console.log(`➕ 指针偏移+4: ${offsetResult.data.address}`);
          
          // 读取偏移后的值
          const nextValue = await api.nativePointerReadU32(offsetResult.data.address);
          if (nextValue.success) {
            console.log(`📖 偏移后读取值: ${nextValue.data.value}`);
          }
        }
        
        // 写入内存
        console.log("✏️ 正在写入内存...");
        const writeResult = await api.nativePointerWriteU32(pointerStr, 42);
        if (writeResult.success) {
          console.log("✅ 写入成功!");
          
          // 验证写入
          const verifyResult = await api.nativePointerReadU32(pointerStr);
          if (verifyResult.success && verifyResult.data.value === 42) {
            console.log("✓ 验证写入成功: 值已更新为42");
          }
        }
      }
    } else {
      console.error(`❌ 创建指针失败: ${result.error}`);
    }
    
    // 断开连接
    console.log("👋 正在断开连接...");
    await session.detach();
    console.log("🎉 操作完成!");
  } catch (error) {
    console.error("❌ 发生错误:", error);
  }
}

main();
```

### 高级使用场景

- **内存扫描与搜索**：搜索特定值或模式，使用`memoryScan`和`memoryScanSync`API
- **模块与函数分析**：枚举模块和内存区域，使用`processEnumerateModules`和相关API
- **函数拦截与替换**：使用`interceptorAttach`和`interceptorReplace`拦截或替换目标函数
- **执行跟踪**：使用`stalkerFollow`系列API跟踪代码执行流程
- **网络通信分析**：使用Socket API监控和分析网络通信
- **批量内存操作**：使用`nativePointerBatchOperate`执行批量内存操作

更多高级用法请参考[高级示例](./examples/advanced.md)文档。

## API 参考

### NativePointer操作

- `nativePointerCreate(address)` - 创建一个新指针
- `nativePointerIsNull(pointerStr)` - 检查指针是否为空
- `nativePointerAdd(pointerStr, value)` - 指针加法
- `nativePointerSub(pointerStr, value)` - 指针减法
- `nativePointerAnd(pointerStr, value)` - 按位与
- `nativePointerOr(pointerStr, value)` - 按位或
- `nativePointerXor(pointerStr, value)` - 按位异或
- `nativePointerShl(pointerStr, value)` - 左移
- `nativePointerShr(pointerStr, value)` - 右移
- `nativePointerNot(pointerStr)` - 按位非
- `nativePointerSign(pointerStr, config)` - 指针签名
- `nativePointerStrip(pointerStr, key)` - 去除指针签名
- `nativePointerBlend(pointerStr, smallInteger)` - 指针混合
- `nativePointerCompare(pointerStr, otherAddress)` - 指针比较
- `nativePointerEquals(pointerStr, otherAddress)` - 指针相等检查
- `nativePointerToInt32(pointerStr)` - 转换为Int32
- `nativePointerToUInt32(pointerStr)` - 转换为UInt32
- `nativePointerToString(pointerStr, radix)` - 转换为字符串
- `nativePointerToMatchPattern(pointerStr)` - 转换为匹配模式
- `nativePointerBatchOperate(operations)` - 批量指针操作

### 读取操作

- `nativePointerReadPointer(pointerStr)` - 读取指针
- `nativePointerReadS8(pointerStr)` - 读取有符号8位整数
- `nativePointerReadU8(pointerStr)` - 读取无符号8位整数
- `nativePointerReadS16(pointerStr)` - 读取有符号16位整数
- `nativePointerReadU16(pointerStr)` - 读取无符号16位整数
- `nativePointerReadS32(pointerStr)` - 读取有符号32位整数
- `nativePointerReadU32(pointerStr)` - 读取无符号32位整数
- `nativePointerReadS64(pointerStr)` - 读取有符号64位整数
- `nativePointerReadU64(pointerStr)` - 读取无符号64位整数
- `nativePointerReadFloat(pointerStr)` - 读取浮点数
- `nativePointerReadDouble(pointerStr)` - 读取双精度浮点数
- `nativePointerReadByteArray(pointerStr, length)` - 读取字节数组
- `nativePointerReadCString(pointerStr, size)` - 读取C字符串
- `nativePointerReadUtf8String(pointerStr, size)` - 读取UTF8字符串
- `nativePointerReadUtf16String(pointerStr, size)` - 读取UTF16字符串
- `nativePointerReadAnsiString(pointerStr, size)` - 读取ANSI字符串

### 写入操作

- `nativePointerWritePointer(pointerStr, value)` - 写入指针
- `nativePointerWriteS8(pointerStr, value)` - 写入有符号8位整数
- `nativePointerWriteU8(pointerStr, value)` - 写入无符号8位整数
- `nativePointerWriteS16(pointerStr, value)` - 写入有符号16位整数
- `nativePointerWriteU16(pointerStr, value)` - 写入无符号16位整数
- `nativePointerWriteS32(pointerStr, value)` - 写入有符号32位整数
- `nativePointerWriteU32(pointerStr, value)` - 写入无符号32位整数
- `nativePointerWriteS64(pointerStr, value)` - 写入有符号64位整数
- `nativePointerWriteU64(pointerStr, value)` - 写入无符号64位整数
- `nativePointerWriteFloat(pointerStr, value)` - 写入浮点数
- `nativePointerWriteDouble(pointerStr, value)` - 写入双精度浮点数
- `nativePointerWriteByteArray(pointerStr, bytes)` - 写入字节数组
- `nativePointerWriteUtf8String(pointerStr, text)` - 写入UTF8字符串
- `nativePointerWriteUtf16String(pointerStr, text)` - 写入UTF16字符串
- `nativePointerWriteAnsiString(pointerStr, text)` - 写入ANSI字符串

### 内存操作

- `memoryScan(address, size, pattern)` - 扫描内存
- `memoryScanSync(address, size, pattern)` - 同步扫描内存
- `memoryAlloc(size, options)` - 分配内存
- `memoryAllocUtf8String(text)` - 分配并写入UTF8字符串
- `memoryAllocUtf16String(text)` - 分配并写入UTF16字符串
- `memoryAllocAnsiString(text)` - 分配并写入ANSI字符串
- `memoryCopy(dst, src, size)` - 复制内存
- `memoryDup(address, size)` - 复制内存区域
- `memoryProtect(address, size, protection)` - 设置内存保护
- `memoryQueryProtection(address)` - 查询内存保护
- `memoryPatchCode(address, bytes)` - 修补代码

### 进程操作

- `processGetInfo()` - 获取进程信息
- `processGetDirs()` - 获取进程目录
- `processIsDebuggerAttached()` - 检查调试器是否附加
- `processGetCurrentThreadId()` - 获取当前线程ID
- `processEnumerateThreads()` - 枚举线程
- `processFindModuleByAddress(address)` - 根据地址查找模块
- `processFindModuleByName(name)` - 根据名称查找模块
- `processEnumerateModules()` - 枚举模块
- `processFindRangeByAddress(address)` - 根据地址查找范围
- `processEnumerateRanges(protection)` - 枚举内存范围
- `processEnumerateMallocRanges()` - 枚举堆分配范围

### 返回值格式

所有API函数都返回以下格式的结果：

```typescript
{
  success: boolean;      // 操作是否成功
  error?: string;        // 如果失败，包含错误信息
  data?: {               // 操作成功时的数据
    address?: string;    // 返回的指针地址
    value?: any;         // 读取的值或操作结果
    [key: string]: any;  // 其他特定于操作的数据
  }
}
```

## 应用场景

- **游戏分析与修改**：分析游戏内存结构，实现自动化辅助功能
- **安全研究**：逆向工程分析，漏洞挖掘与验证
- **应用调试**：复杂应用的内存级别调试与分析
- **性能优化**：识别内存泄漏与性能瓶颈
- **自动化测试**：基于内存状态的高级自动化测试
- **网络协议分析**：分析和修改网络通信
- **系统监控**：监控系统行为和资源使用
- **恶意软件分析**：分析恶意软件的行为和特征
- **教育目的**：学习内存管理和系统级编程

## 注意事项

- **指针安全**：所有指针均作为字符串处理，避免JavaScript中的整数精度问题
- **错误处理**：所有API函数内置错误处理，建议始终检查返回值的`success`字段
- **内存安全**：操作前务必确保目标地址有效，避免触发目标进程崩溃
- **权限要求**：在某些平台上可能需要特权访问才能附加到进程
- **性能考量**：频繁的RPC调用可能影响性能，尽可能使用批量操作API
- **兼容性**：不同的操作系统和架构可能有细微差异，请注意测试
- **版本依赖**：确保使用兼容的Frida版本(推荐16.x+)

## 贡献指南

欢迎贡献代码、报告问题或提出改进建议！请查看我们的[贡献指南](CONTRIBUTING.md)了解更多信息。

## 许可证

MIT