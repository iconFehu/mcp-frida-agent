/**
 * Kernel API的RPC导出包装器
 */

import {
  KernelOperationResult,
  KernelModuleDetails,
  KernelRangeDetails,
  KernelModuleRangeDetails,
  KernelMemoryScanMatch,
  KernelMemoryScanCallbacks,
  PageProtection,
  KernelScanOptions,
  KernelInfo
} from '../types/kernel-types.js';

// 声明Kernel类型以避免TypeScript错误
declare namespace Kernel {
  const available: boolean;
  let base: UInt64;
  const pageSize: number;
  
  function enumerateModules(): any[];
  function enumerateRanges(specifier: string): any[];
  function enumerateModuleRanges(name: string | null, protection: string): any[];
  function alloc(size: number | UInt64): UInt64;
  function protect(address: UInt64, size: number | UInt64, protection: string): boolean;
  function scan(address: UInt64, size: number | UInt64, pattern: string, callbacks: any): Promise<void>;
  function scanSync(address: UInt64, size: number | UInt64, pattern: string): any[];
  
  // 读取函数
  function readS8(address: UInt64): number;
  function readU8(address: UInt64): number;
  function readS16(address: UInt64): number;
  function readU16(address: UInt64): number;
  function readS32(address: UInt64): number;
  function readU32(address: UInt64): number;
  function readS64(address: UInt64): Int64;
  function readU64(address: UInt64): UInt64;
  function readFloat(address: UInt64): number;
  function readDouble(address: UInt64): number;
  function readByteArray(address: UInt64, length: number): ArrayBuffer | null;
  function readCString(address: UInt64, size: number): string | null;
  function readUtf8String(address: UInt64, size: number): string | null;
  function readUtf16String(address: UInt64, length: number): string | null;
  
  // 写入函数
  function writeS8(address: UInt64, value: number | Int64): void;
  function writeU8(address: UInt64, value: number | UInt64): void;
  function writeS16(address: UInt64, value: number | Int64): void;
  function writeU16(address: UInt64, value: number | UInt64): void;
  function writeS32(address: UInt64, value: number | Int64): void;
  function writeU32(address: UInt64, value: number | UInt64): void;
  function writeS64(address: UInt64, value: number | Int64): void;
  function writeU64(address: UInt64, value: number | UInt64): void;
  function writeFloat(address: UInt64, value: number): void;
  function writeDouble(address: UInt64, value: number): void;
  function writeByteArray(address: UInt64, value: ArrayBuffer | number[]): void;
  function writeUtf8String(address: UInt64, value: string): void;
  function writeUtf16String(address: UInt64, value: string): void;
}

/**
 * 获取内核API可用性和基本信息
 */
export function getInfo(): KernelOperationResult {
  try {
    const info: KernelInfo = {
      available: Kernel.available,
      base: Kernel.base.toString(),
      pageSize: Kernel.pageSize
    };
    
    return {
      success: true,
      data: info
    };
  } catch (error) {
    return {
      success: false,
      error: `获取内核信息失败: ${error}`
    };
  }
}

/**
 * 枚举内核模块
 */
export function enumerateModules(): KernelOperationResult {
  try {
    if (!Kernel.available) {
      return {
        success: false,
        error: '内核API不可用'
      };
    }
    
    const modules = Kernel.enumerateModules().map(module => ({
      name: module.name,
      base: module.base.toString(),
      size: module.size
    }));
    
    return {
      success: true,
      data: { modules }
    };
  } catch (error) {
    return {
      success: false,
      error: `枚举内核模块失败: ${error}`
    };
  }
}

/**
 * 枚举内核内存范围
 */
export function enumerateRanges(protection: string): KernelOperationResult {
  try {
    if (!Kernel.available) {
      return {
        success: false,
        error: '内核API不可用'
      };
    }
    
    const ranges = Kernel.enumerateRanges(protection).map(range => ({
      base: range.base.toString(),
      size: range.size,
      protection: range.protection
    }));
    
    return {
      success: true,
      data: { ranges }
    };
  } catch (error) {
    return {
      success: false,
      error: `枚举内存范围失败: ${error}`
    };
  }
}

/**
 * 枚举模块内存范围
 */
export function enumerateModuleRanges(name: string | null, protection: string): KernelOperationResult {
  try {
    if (!Kernel.available) {
      return {
        success: false,
        error: '内核API不可用'
      };
    }
    
    const ranges = Kernel.enumerateModuleRanges(name, protection).map(range => ({
      name: range.name,
      base: range.base.toString(),
      size: range.size,
      protection: range.protection,
      path: range.path
    }));
    
    return {
      success: true,
      data: { ranges }
    };
  } catch (error) {
    return {
      success: false,
      error: `枚举模块范围失败: ${error}`
    };
  }
}

/**
 * 分配内核内存
 */
export function alloc(size: number): KernelOperationResult {
  try {
    if (!Kernel.available) {
      return {
        success: false,
        error: '内核API不可用'
      };
    }
    
    const address = Kernel.alloc(size);
    
    return {
      success: true,
      data: { address: address.toString() }
    };
  } catch (error) {
    return {
      success: false,
      error: `分配内核内存失败: ${error}`
    };
  }
}

/**
 * 修改内核内存保护
 */
export function protect(address: string, size: number, protection: string): KernelOperationResult {
  try {
    if (!Kernel.available) {
      return {
        success: false,
        error: '内核API不可用'
      };
    }
    
    const success = Kernel.protect(new UInt64(address), size, protection);
    
    return {
      success,
      error: success ? undefined : '修改内存保护失败'
    };
  } catch (error) {
    return {
      success: false,
      error: `修改内存保护失败: ${error}`
    };
  }
}

/**
 * 扫描内核内存
 */
export function scan(
  address: string,
  size: number,
  pattern: string,
  options: KernelScanOptions
): KernelOperationResult {
  try {
    if (!Kernel.available) {
      return {
        success: false,
        error: '内核API不可用'
      };
    }
    
    const callbacks: KernelMemoryScanCallbacks = {
      onMatch: (address: string) => options.onMatch?.(address),
      onComplete: () => options.onComplete?.(),
      onError: (error: Error) => options.onError?.(error)
    };
    
    Kernel.scan(new UInt64(address), size, pattern, callbacks);
    
    return {
      success: true
    };
  } catch (error) {
    return {
      success: false,
      error: `扫描内核内存失败: ${error}`
    };
  }
}

/**
 * 同步扫描内核内存
 */
export function scanSync(address: string, size: number, pattern: string): KernelOperationResult {
  try {
    if (!Kernel.available) {
      return {
        success: false,
        error: '内核API不可用'
      };
    }
    
    const matches = Kernel.scanSync(new UInt64(address), size, pattern).map(match => ({
      address: match.address.toString()
    }));
    
    return {
      success: true,
      data: { matches }
    };
  } catch (error) {
    return {
      success: false,
      error: `同步扫描内核内存失败: ${error}`
    };
  }
}

// 读取函数
export function readS8(address: string): KernelOperationResult {
  try {
    if (!Kernel.available) return { success: false, error: '内核API不可用' };
    return { success: true, data: { value: Kernel.readS8(new UInt64(address)) } };
  } catch (error) {
    return { success: false, error: `读取失败: ${error}` };
  }
}

export function readU8(address: string): KernelOperationResult {
  try {
    if (!Kernel.available) return { success: false, error: '内核API不可用' };
    return { success: true, data: { value: Kernel.readU8(new UInt64(address)) } };
  } catch (error) {
    return { success: false, error: `读取失败: ${error}` };
  }
}

export function readS16(address: string): KernelOperationResult {
  try {
    if (!Kernel.available) return { success: false, error: '内核API不可用' };
    return { success: true, data: { value: Kernel.readS16(new UInt64(address)) } };
  } catch (error) {
    return { success: false, error: `读取失败: ${error}` };
  }
}

export function readU16(address: string): KernelOperationResult {
  try {
    if (!Kernel.available) return { success: false, error: '内核API不可用' };
    return { success: true, data: { value: Kernel.readU16(new UInt64(address)) } };
  } catch (error) {
    return { success: false, error: `读取失败: ${error}` };
  }
}

export function readS32(address: string): KernelOperationResult {
  try {
    if (!Kernel.available) return { success: false, error: '内核API不可用' };
    return { success: true, data: { value: Kernel.readS32(new UInt64(address)) } };
  } catch (error) {
    return { success: false, error: `读取失败: ${error}` };
  }
}

export function readU32(address: string): KernelOperationResult {
  try {
    if (!Kernel.available) return { success: false, error: '内核API不可用' };
    return { success: true, data: { value: Kernel.readU32(new UInt64(address)) } };
  } catch (error) {
    return { success: false, error: `读取失败: ${error}` };
  }
}

export function readFloat(address: string): KernelOperationResult {
  try {
    if (!Kernel.available) return { success: false, error: '内核API不可用' };
    return { success: true, data: { value: Kernel.readFloat(new UInt64(address)) } };
  } catch (error) {
    return { success: false, error: `读取失败: ${error}` };
  }
}

export function readDouble(address: string): KernelOperationResult {
  try {
    if (!Kernel.available) return { success: false, error: '内核API不可用' };
    return { success: true, data: { value: Kernel.readDouble(new UInt64(address)) } };
  } catch (error) {
    return { success: false, error: `读取失败: ${error}` };
  }
}

export function readByteArray(address: string, length: number): KernelOperationResult {
  try {
    if (!Kernel.available) return { success: false, error: '内核API不可用' };
    const array = Kernel.readByteArray(new UInt64(address), length);
    return { success: true, data: { value: array } };
  } catch (error) {
    return { success: false, error: `读取失败: ${error}` };
  }
}

export function readCString(address: string, size: number): KernelOperationResult {
  try {
    if (!Kernel.available) return { success: false, error: '内核API不可用' };
    return { success: true, data: { value: Kernel.readCString(new UInt64(address), size) } };
  } catch (error) {
    return { success: false, error: `读取失败: ${error}` };
  }
}

export function readUtf8String(address: string, size: number): KernelOperationResult {
  try {
    if (!Kernel.available) return { success: false, error: '内核API不可用' };
    return { success: true, data: { value: Kernel.readUtf8String(new UInt64(address), size) } };
  } catch (error) {
    return { success: false, error: `读取失败: ${error}` };
  }
}

export function readUtf16String(address: string, length: number): KernelOperationResult {
  try {
    if (!Kernel.available) return { success: false, error: '内核API不可用' };
    return { success: true, data: { value: Kernel.readUtf16String(new UInt64(address), length) } };
  } catch (error) {
    return { success: false, error: `读取失败: ${error}` };
  }
}

// 写入函数
export function writeS8(address: string, value: number): KernelOperationResult {
  try {
    if (!Kernel.available) return { success: false, error: '内核API不可用' };
    Kernel.writeS8(new UInt64(address), value);
    return { success: true };
  } catch (error) {
    return { success: false, error: `写入失败: ${error}` };
  }
}

export function writeU8(address: string, value: number): KernelOperationResult {
  try {
    if (!Kernel.available) return { success: false, error: '内核API不可用' };
    Kernel.writeU8(new UInt64(address), value);
    return { success: true };
  } catch (error) {
    return { success: false, error: `写入失败: ${error}` };
  }
}

export function writeS16(address: string, value: number): KernelOperationResult {
  try {
    if (!Kernel.available) return { success: false, error: '内核API不可用' };
    Kernel.writeS16(new UInt64(address), value);
    return { success: true };
  } catch (error) {
    return { success: false, error: `写入失败: ${error}` };
  }
}

export function writeU16(address: string, value: number): KernelOperationResult {
  try {
    if (!Kernel.available) return { success: false, error: '内核API不可用' };
    Kernel.writeU16(new UInt64(address), value);
    return { success: true };
  } catch (error) {
    return { success: false, error: `写入失败: ${error}` };
  }
}

export function writeS32(address: string, value: number): KernelOperationResult {
  try {
    if (!Kernel.available) return { success: false, error: '内核API不可用' };
    Kernel.writeS32(new UInt64(address), value);
    return { success: true };
  } catch (error) {
    return { success: false, error: `写入失败: ${error}` };
  }
}

export function writeU32(address: string, value: number): KernelOperationResult {
  try {
    if (!Kernel.available) return { success: false, error: '内核API不可用' };
    Kernel.writeU32(new UInt64(address), value);
    return { success: true };
  } catch (error) {
    return { success: false, error: `写入失败: ${error}` };
  }
}

export function writeFloat(address: string, value: number): KernelOperationResult {
  try {
    if (!Kernel.available) return { success: false, error: '内核API不可用' };
    Kernel.writeFloat(new UInt64(address), value);
    return { success: true };
  } catch (error) {
    return { success: false, error: `写入失败: ${error}` };
  }
}

export function writeDouble(address: string, value: number): KernelOperationResult {
  try {
    if (!Kernel.available) return { success: false, error: '内核API不可用' };
    Kernel.writeDouble(new UInt64(address), value);
    return { success: true };
  } catch (error) {
    return { success: false, error: `写入失败: ${error}` };
  }
}

export function writeByteArray(address: string, value: ArrayBuffer | number[]): KernelOperationResult {
  try {
    if (!Kernel.available) return { success: false, error: '内核API不可用' };
    Kernel.writeByteArray(new UInt64(address), value);
    return { success: true };
  } catch (error) {
    return { success: false, error: `写入失败: ${error}` };
  }
}

export function writeUtf8String(address: string, value: string): KernelOperationResult {
  try {
    if (!Kernel.available) return { success: false, error: '内核API不可用' };
    Kernel.writeUtf8String(new UInt64(address), value);
    return { success: true };
  } catch (error) {
    return { success: false, error: `写入失败: ${error}` };
  }
}

export function writeUtf16String(address: string, value: string): KernelOperationResult {
  try {
    if (!Kernel.available) return { success: false, error: '内核API不可用' };
    Kernel.writeUtf16String(new UInt64(address), value);
    return { success: true };
  } catch (error) {
    return { success: false, error: `写入失败: ${error}` };
  }
} 