# MCP-Frida-Agent Advanced Memory Pointer Operation Framework

This project provides a powerful RPC encapsulation system for Frida's Native APIs, enabling developers to securely and efficiently manipulate memory pointers and system resources of target processes from the Node.js side. The framework not only supports basic memory read/write operations but also integrates advanced features like process manipulation, network communication, code execution tracing, and kernel interaction. Whether for game analysis, security research, or performance tuning, MCP-Frida-Agent can be an indispensable tool.

## Core Advantages

- Comprehensive encapsulation of all core Frida APIs, including NativePointer, Memory, Process, Socket, Stalker, Interceptor, and Kernel
- Well-designed RPC interface architecture ensuring stability and efficiency for remote operations
- Strict type safety design with TypeScript definitions to reduce runtime errors
- Robust error handling mechanism; all APIs return standardized result objects for clear error feedback
- Support for various memory read/write operations, including different data types and formats
- Batch operation support to enhance the efficiency of large-scale memory operations
- High-performance implementation minimizing cross-process communication overhead
- Complete documentation and examples to lower the learning curve

## Features

- **Comprehensive Pointer Operations**: Supports all NativePointer operations, including arithmetic, comparison, bitwise operations, etc.
- **Diverse Data Type Support**: Read and write various data types, from basic integers to floating-point numbers, strings, and pointers
- **Memory Management**: Features like memory allocation, protection, copying, and code patching
- **Process Operations**: Get process information, enumerate modules and memory regions, thread management, etc.
- **Network Functions**: Socket listening, connecting, sending, and receiving data
- **Execution Tracing**: Use the Stalker API for code execution tracing and event monitoring
- **Function Interception**: Intercept and modify function calls using the Interceptor API
- **Kernel Interaction**: Supports interaction with the system kernel (on supported platforms)
- **Batch Operations**: Efficiently execute batch memory operations, reducing RPC call overhead
- **Error Protection**: Comprehensive error detection and handling mechanisms to prevent crashes and security issues
- **Cross-Platform**: Supports Windows, Linux, macOS, and Android platforms
- **Extensibility**: Modular design, easy to extend and customize

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/iconFehu/mcp-frida-agent.git
cd mcp-frida-agent

# Install dependencies
npm install

# Build the project
npm run build
```

### Basic Usage Flow

1.  **Install and Configure Environment**
    *   Ensure Node.js and npm are installed
    *   Install Frida CLI tools: `npm install -g frida-tools`

2.  **Integrate into Your Project**
    *   Install dependency: `npm install mcp-frida-agent`
    *   Import the package: `import { MCP } from 'mcp-frida-agent'`

3.  **Connect to Target Process**
    *   Connect via process name, PID, or USB device
    *   Supports inject, attach, and spawn modes

4.  **Perform Memory Operations**
    *   Create and manipulate memory pointers
    *   Read and write various data types
    *   Use advanced features like process analysis, function interception, etc.

### Code Example

Here is a complete example demonstrating how to explore memory using MCP-Frida-Agent:

```javascript
import frida from 'frida';
import fs from 'fs';

async function main() {
  try {
    // Attach to the target process
    console.log("⚡ Attaching to the target process...");
    const session = await frida.attach("target-process");

    // Load the Agent script
    console.log("📜 Loading Agent script...");
    const script = await session.createScript(fs.readFileSync('./dist/_agent.js', 'utf8'));
    await script.load();

    // Get the RPC interface
    const api = script.exports;
    console.log("🔗 RPC interface is ready!");

    // Create a pointer (e.g., pointing to a known memory address)
    const baseAddress = "0x12345678";
    console.log(`🔍 Creating pointer: ${baseAddress}`);
    const result = await api.nativePointerCreate(baseAddress);

    if (result.success) {
      const pointerStr = result.data.address;
      console.log(`✅ Pointer created successfully: ${pointerStr}`);

      // Read a 32-bit unsigned integer from memory
      const readResult = await api.nativePointerReadU32(pointerStr);
      if (readResult.success) {
        console.log(`📖 Read U32 value: ${readResult.data.value} (0x${readResult.data.value.toString(16)})`);

        // Pointer offset operation
        const offsetResult = await api.nativePointerAdd(pointerStr, 4);
        if (offsetResult.success) {
          console.log(`➕ Pointer offset +4: ${offsetResult.data.address}`);

          // Read the value at the offset
          const nextValue = await api.nativePointerReadU32(offsetResult.data.address);
          if (nextValue.success) {
            console.log(`📖 Read value after offset: ${nextValue.data.value}`);
          }
        }

        // Write to memory
        console.log("✏️ Writing to memory...");
        const writeResult = await api.nativePointerWriteU32(pointerStr, 42);
        if (writeResult.success) {
          console.log("✅ Write successful!");

          // Verify the write
          const verifyResult = await api.nativePointerReadU32(pointerStr);
          if (verifyResult.success && verifyResult.data.value === 42) {
            console.log("✓ Write verified successfully: Value updated to 42");
          }
        }
      }
    } else {
      console.error(`❌ Failed to create pointer: ${result.error}`);
    }

    // Disconnect
    console.log("👋 Disconnecting...");
    await session.detach();
    console.log("🎉 Operation complete!");
  } catch (error) {
    console.error("❌ An error occurred:", error);
  }
}

main();
```

### Advanced Use Cases

-   **Memory Scanning and Searching**: Search for specific values or patterns using `memoryScan` and `memoryScanSync` APIs
-   **Module and Function Analysis**: Enumerate modules and memory regions using `processEnumerateModules` and related APIs
-   **Function Interception and Replacement**: Use `interceptorAttach` and `interceptorReplace` to intercept or replace target functions
-   **Execution Tracing**: Use the `stalkerFollow` series APIs to trace code execution flow
-   **Network Communication Analysis**: Use Socket APIs to monitor and analyze network traffic
-   **Batch Memory Operations**: Use `nativePointerBatchOperate` to perform batch memory operations

For more advanced usage, please refer to the [Advanced Examples](./examples/advanced.md) documentation.

## API Reference

### NativePointer Operations

-   `nativePointerCreate(address)` - Create a new pointer
-   `nativePointerIsNull(pointerStr)` - Check if the pointer is null
-   `nativePointerAdd(pointerStr, value)` - Pointer addition
-   `nativePointerSub(pointerStr, value)` - Pointer subtraction
-   `nativePointerAnd(pointerStr, value)` - Bitwise AND
-   `nativePointerOr(pointerStr, value)` - Bitwise OR
-   `nativePointerXor(pointerStr, value)` - Bitwise XOR
-   `nativePointerShl(pointerStr, value)` - Left shift
-   `nativePointerShr(pointerStr, value)` - Right shift
-   `nativePointerNot(pointerStr)` - Bitwise NOT
-   `nativePointerSign(pointerStr, config)` - Pointer signing
-   `nativePointerStrip(pointerStr, key)` - Strip pointer signature
-   `nativePointerBlend(pointerStr, smallInteger)` - Pointer blending
-   `nativePointerCompare(pointerStr, otherAddress)` - Pointer comparison
-   `nativePointerEquals(pointerStr, otherAddress)` - Pointer equality check
-   `nativePointerToInt32(pointerStr)` - Convert to Int32
-   `nativePointerToUInt32(pointerStr)` - Convert to UInt32
-   `nativePointerToString(pointerStr, radix)` - Convert to string
-   `nativePointerToMatchPattern(pointerStr)` - Convert to match pattern
-   `nativePointerBatchOperate(operations)` - Batch pointer operations

### Read Operations

-   `nativePointerReadPointer(pointerStr)` - Read pointer
-   `nativePointerReadS8(pointerStr)` - Read signed 8-bit integer
-   `nativePointerReadU8(pointerStr)` - Read unsigned 8-bit integer
-   `nativePointerReadS16(pointerStr)` - Read signed 16-bit integer
-   `nativePointerReadU16(pointerStr)` - Read unsigned 16-bit integer
-   `nativePointerReadS32(pointerStr)` - Read signed 32-bit integer
-   `nativePointerReadU32(pointerStr)` - Read unsigned 32-bit integer
-   `nativePointerReadS64(pointerStr)` - Read signed 64-bit integer
-   `nativePointerReadU64(pointerStr)` - Read unsigned 64-bit integer
-   `nativePointerReadFloat(pointerStr)` - Read float
-   `nativePointerReadDouble(pointerStr)` - Read double
-   `nativePointerReadByteArray(pointerStr, length)` - Read byte array
-   `nativePointerReadCString(pointerStr, size)` - Read C string
-   `nativePointerReadUtf8String(pointerStr, size)` - Read UTF8 string
-   `nativePointerReadUtf16String(pointerStr, size)` - Read UTF16 string
-   `nativePointerReadAnsiString(pointerStr, size)` - Read ANSI string

### Write Operations

-   `nativePointerWritePointer(pointerStr, value)` - Write pointer
-   `nativePointerWriteS8(pointerStr, value)` - Write signed 8-bit integer
-   `nativePointerWriteU8(pointerStr, value)` - Write unsigned 8-bit integer
-   `nativePointerWriteS16(pointerStr, value)` - Write signed 16-bit integer
-   `nativePointerWriteU16(pointerStr, value)` - Write unsigned 16-bit integer
-   `nativePointerWriteS32(pointerStr, value)` - Write signed 32-bit integer
-   `nativePointerWriteU32(pointerStr, value)` - Write unsigned 32-bit integer
-   `nativePointerWriteS64(pointerStr, value)` - Write signed 64-bit integer
-   `nativePointerWriteU64(pointerStr, value)` - Write unsigned 64-bit integer
-   `nativePointerWriteFloat(pointerStr, value)` - Write float
-   `nativePointerWriteDouble(pointerStr, value)` - Write double
-   `nativePointerWriteByteArray(pointerStr, bytes)` - Write byte array
-   `nativePointerWriteUtf8String(pointerStr, text)` - Write UTF8 string
-   `nativePointerWriteUtf16String(pointerStr, text)` - Write UTF16 string
-   `nativePointerWriteAnsiString(pointerStr, text)` - Write ANSI string

### Memory Operations

-   `memoryScan(address, size, pattern)` - Scan memory
-   `memoryScanSync(address, size, pattern)` - Synchronously scan memory
-   `memoryAlloc(size, options)` - Allocate memory
-   `memoryAllocUtf8String(text)` - Allocate and write UTF8 string
-   `memoryAllocUtf16String(text)` - Allocate and write UTF16 string
-   `memoryAllocAnsiString(text)` - Allocate and write ANSI string
-   `memoryCopy(dst, src, size)` - Copy memory
-   `memoryDup(address, size)` - Duplicate memory region
-   `memoryProtect(address, size, protection)` - Set memory protection
-   `memoryQueryProtection(address)` - Query memory protection
-   `memoryPatchCode(address, bytes)` - Patch code

### Process Operations

-   `processGetInfo()` - Get process information
-   `processGetDirs()` - Get process directories
-   `processIsDebuggerAttached()` - Check if a debugger is attached
-   `processGetCurrentThreadId()` - Get current thread ID
-   `processEnumerateThreads()` - Enumerate threads
-   `processFindModuleByAddress(address)` - Find module by address
-   `processFindModuleByName(name)` - Find module by name
-   `processEnumerateModules()` - Enumerate modules
-   `processFindRangeByAddress(address)` - Find range by address
-   `processEnumerateRanges(protection)` - Enumerate memory ranges
-   `processEnumerateMallocRanges()` - Enumerate heap allocation ranges

### Return Value Format

All API functions return results in the following format:

```typescript
{
  success: boolean;      // Whether the operation was successful
  error?: string;        // Error message if failed
  data?: {               // Data if the operation succeeded
    address?: string;    // Returned pointer address
    value?: any;         // Read value or operation result
    [key: string]: any;  // Other operation-specific data
  }
}
```

## Application Scenarios

-   **Game Analysis and Modification**: Analyze game memory structures, implement automated assistance features
-   **Security Research**: Reverse engineering analysis, vulnerability discovery and validation
-   **Application Debugging**: Memory-level debugging and analysis for complex applications
-   **Performance Optimization**: Identify memory leaks and performance bottlenecks
-   **Automated Testing**: Advanced automated testing based on memory state
-   **Network Protocol Analysis**: Analyze and modify network communications
-   **System Monitoring**: Monitor system behavior and resource usage
-   **Malware Analysis**: Analyze malware behavior and characteristics
-   **Educational Purposes**: Learn about memory management and system-level programming

## Notes

-   **Pointer Safety**: All pointers are handled as strings to avoid JavaScript's integer precision issues
-   **Error Handling**: All API functions have built-in error handling; always check the `success` field of the return value
-   **Memory Safety**: Ensure the target address is valid before operating to avoid crashing the target process
-   **Permission Requirements**: Privileged access may be required on some platforms to attach to processes
-   **Performance Considerations**: Frequent RPC calls can impact performance; use batch operation APIs whenever possible
-   **Compatibility**: There may be minor differences across operating systems and architectures; please test accordingly
-   **Version Dependency**: Ensure you are using a compatible Frida version (16.x+ recommended)

## Contribution Guide

Contributions, issue reports, and suggestions for improvement are welcome! Please see our [Contribution Guide](CONTRIBUTING.md) for more information.

## License

MIT 