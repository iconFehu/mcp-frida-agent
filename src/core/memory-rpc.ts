/**
 * Memory API的RPC导出包装器
 * 
 * 该模块封装了Frida的Memory API并通过RPC导出，
 * 使得可以在Node.js端直接操作目标进程的内存。
 */

import { MemoryOperationResult, MemoryScanMatch, PageProtection, MemoryAllocOptions, MemoryScanOptions } from '../types/memory-types.js';

// 声明Memory类型以避免TypeScript错误
declare namespace Memory {
  function scan(address: NativePointer, size: number, pattern: string, callbacks: any): Promise<void>;
  function scanSync(address: NativePointer, size: number, pattern: string): any[];
  function alloc(size: number, options?: MemoryAllocOptions): NativePointer;
  function allocUtf8String(str: string): NativePointer;
  function allocUtf16String(str: string): NativePointer;
  function allocAnsiString(str: string): NativePointer;
  function copy(dst: NativePointer, src: NativePointer, n: number): void;
  function dup(address: NativePointer, size: number): NativePointer;
  function protect(address: NativePointer, size: number, protection: PageProtection): boolean;
  function queryProtection(address: NativePointer): PageProtection;
  function patchCode(address: NativePointer, size: number, apply: (ptr: NativePointer) => void): void;
}

declare class NativePointer {
  constructor(value: string | number);
  toString(): string;
  add(offset: number): NativePointer;
  writeU8(value: number): void;
}

/**
 * 扫描内存中的特定模式
 */
export async function scan(baseAddress: string, size: number, pattern: string, options?: MemoryScanOptions): Promise<MemoryOperationResult> {
  try {
    const base = new NativePointer(baseAddress);
    const matches: MemoryScanMatch[] = [];
    
    // 限制最大匹配数量，防止返回过多数据
    const limit = options?.limit || 1000;
    let matchCount = 0;
    
    await Memory.scan(base, size, pattern, {
      onMatch(address: NativePointer) {
        if (matchCount < limit) {
          matches.push({
            address: address.toString()
          });
          matchCount++;
        }
      },
      onError(reason: string) {
        throw new Error(`扫描错误: ${reason}`);
      },
      onComplete() {
        // 扫描完成
      }
    });
    
    return {
      success: true,
      data: matches
    };
  } catch (error) {
    return {
      success: false,
      error: `内存扫描失败: ${error}`
    };
  }
}

/**
 * 同步扫描内存中的特定模式
 */
export function scanSync(baseAddress: string, size: number, pattern: string, options?: MemoryScanOptions): MemoryOperationResult {
  try {
    const base = new NativePointer(baseAddress);
    const rawMatches = Memory.scanSync(base, size, pattern);
    
    // 限制最大匹配数量，防止返回过多数据
    const limit = options?.limit || 1000;
    const matches = rawMatches.slice(0, limit).map(match => ({
      address: match.address.toString()
    }));
    
    return {
      success: true,
      data: matches
    };
  } catch (error) {
    return {
      success: false,
      error: `同步内存扫描失败: ${error}`
    };
  }
}

/**
 * 分配内存
 */
export function alloc(size: number, options?: MemoryAllocOptions): MemoryOperationResult {
  try {
    // 处理近似地址选项
    const allocOptions: any = {};
    
    if (options?.near) {
      allocOptions.near = new NativePointer(options.near);
    }
    
    if (options?.maxDistance) {
      allocOptions.maxDistance = options.maxDistance;
    }
    
    if (options?.protection) {
      allocOptions.protection = options.protection;
    }
    
    const pointer = Memory.alloc(size, allocOptions);
    
    return {
      success: true,
      address: pointer.toString()
    };
  } catch (error) {
    return {
      success: false,
      error: `内存分配失败: ${error}`
    };
  }
}

/**
 * 分配UTF8字符串
 */
export function allocUtf8String(text: string): MemoryOperationResult {
  try {
    const pointer = Memory.allocUtf8String(text);
    
    return {
      success: true,
      address: pointer.toString()
    };
  } catch (error) {
    return {
      success: false,
      error: `UTF8字符串分配失败: ${error}`
    };
  }
}

/**
 * 分配UTF16字符串
 */
export function allocUtf16String(text: string): MemoryOperationResult {
  try {
    const pointer = Memory.allocUtf16String(text);
    
    return {
      success: true,
      address: pointer.toString()
    };
  } catch (error) {
    return {
      success: false,
      error: `UTF16字符串分配失败: ${error}`
    };
  }
}

/**
 * 分配ANSI字符串
 */
export function allocAnsiString(text: string): MemoryOperationResult {
  try {
    const pointer = Memory.allocAnsiString(text);
    
    return {
      success: true,
      address: pointer.toString()
    };
  } catch (error) {
    return {
      success: false,
      error: `ANSI字符串分配失败: ${error}`
    };
  }
}

/**
 * 复制内存
 */
export function copy(dstAddress: string, srcAddress: string, size: number): MemoryOperationResult {
  try {
    const dst = new NativePointer(dstAddress);
    const src = new NativePointer(srcAddress);
    
    Memory.copy(dst, src, size);
    
    return {
      success: true
    };
  } catch (error) {
    return {
      success: false,
      error: `内存复制失败: ${error}`
    };
  }
}

/**
 * 复制内存区域
 */
export function dup(address: string, size: number): MemoryOperationResult {
  try {
    const src = new NativePointer(address);
    const result = Memory.dup(src, size);
    
    return {
      success: true,
      address: result.toString()
    };
  } catch (error) {
    return {
      success: false,
      error: `内存复制失败: ${error}`
    };
  }
}

/**
 * 修改内存页保护属性
 */
export function protect(address: string, size: number, protection: PageProtection): MemoryOperationResult {
  try {
    const ptr = new NativePointer(address);
    const result = Memory.protect(ptr, size, protection);
    
    return {
      success: result,
      data: { 
        protected: result 
      }
    };
  } catch (error) {
    return {
      success: false,
      error: `修改内存保护属性失败: ${error}`
    };
  }
}

/**
 * 查询内存页保护属性
 */
export function queryProtection(address: string): MemoryOperationResult {
  try {
    const ptr = new NativePointer(address);
    const protection = Memory.queryProtection(ptr);
    
    return {
      success: true,
      data: { 
        protection 
      }
    };
  } catch (error) {
    return {
      success: false,
      error: `查询内存保护属性失败: ${error}`
    };
  }
}

/**
 * 安全修改代码内存
 * 注意：由于回调函数无法通过RPC传递，此函数需要接收要写入的字节数组
 */
export function patchCode(address: string, bytes: number[]): MemoryOperationResult {
  try {
    const ptr = new NativePointer(address);
    
    Memory.patchCode(ptr, bytes.length, (code) => {
      for (let i = 0; i < bytes.length; i++) {
        code.add(i).writeU8(bytes[i]);
      }
    });
    
    return {
      success: true
    };
  } catch (error) {
    return {
      success: false,
      error: `代码内存修改失败: ${error}`
    };
  }
}
