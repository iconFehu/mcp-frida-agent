/**
 * Process API的RPC导出包装器
 * 
 * 该模块封装了Frida的Process API并通过RPC导出，
 * 使得可以在Node.js端直接获取和操作目标进程的信息。
 */

import { ProcessInfo, ThreadDetails, ModuleDetails, RangeDetails, EnumerateRangesSpecifier, ProcessOperationResult } from '../types/process-types.js';

// 声明Process类型以避免TypeScript错误
declare namespace Process {
  const id: number;
  const arch: string;
  const platform: string;
  const pageSize: number;
  const pointerSize: number;
  const codeSigningPolicy: string;
  const mainModule: any;
  
  function getCurrentDir(): string;
  function getHomeDir(): string;
  function getTmpDir(): string;
  function isDebuggerAttached(): boolean;
  function getCurrentThreadId(): number;
  function enumerateThreads(): any[];
  function findModuleByAddress(address: NativePointer): any | null;
  function getModuleByAddress(address: NativePointer): any;
  function findModuleByName(name: string): any | null;
  function getModuleByName(name: string): any;
  function enumerateModules(): any[];
  function findRangeByAddress(address: NativePointer): any | null;
  function getRangeByAddress(address: NativePointer): any;
  function enumerateRanges(specifier: string | EnumerateRangesSpecifier): any[];
  function enumerateMallocRanges(): any[];
  function setExceptionHandler(callback: (details: any) => boolean): void;
}

declare class NativePointer {
  constructor(value: string | number);
  toString(): string;
}

/**
 * 获取进程基本信息
 */
export function getProcessInfo(): ProcessOperationResult {
  try {
    const info: ProcessInfo = {
      id: Process.id,
      arch: Process.arch,
      platform: Process.platform,
      pageSize: Process.pageSize,
      pointerSize: Process.pointerSize,
      codeSigningPolicy: Process.codeSigningPolicy
    };
    
    return {
      success: true,
      data: info
    };
  } catch (error) {
    return {
      success: false,
      error: `获取进程信息失败: ${error}`
    };
  }
}

/**
 * 获取进程目录信息
 */
export function getProcessDirs(): ProcessOperationResult {
  try {
    const dirs = {
      current: Process.getCurrentDir(),
      home: Process.getHomeDir(),
      temp: Process.getTmpDir()
    };
    
    return {
      success: true,
      data: dirs
    };
  } catch (error) {
    return {
      success: false,
      error: `获取进程目录信息失败: ${error}`
    };
  }
}

/**
 * 获取调试器状态
 */
export function isDebuggerAttached(): ProcessOperationResult {
  try {
    const attached = Process.isDebuggerAttached();
    
    return {
      success: true,
      data: {
        attached
      }
    };
  } catch (error) {
    return {
      success: false,
      error: `获取调试器状态失败: ${error}`
    };
  }
}

/**
 * 获取当前线程ID
 */
export function getCurrentThreadId(): ProcessOperationResult {
  try {
    const threadId = Process.getCurrentThreadId();
    
    return {
      success: true,
      data: {
        threadId
      }
    };
  } catch (error) {
    return {
      success: false,
      error: `获取线程ID失败: ${error}`
    };
  }
}

/**
 * 枚举所有线程
 */
export function enumerateThreads(): ProcessOperationResult {
  try {
    const threads = Process.enumerateThreads().map(thread => ({
      id: thread.id,
      state: thread.state,
      context: thread.context
    }));
    
    return {
      success: true,
      data: threads
    };
  } catch (error) {
    return {
      success: false,
      error: `枚举线程失败: ${error}`
    };
  }
}

/**
 * 通过地址查找模块
 */
export function findModuleByAddress(address: string): ProcessOperationResult {
  try {
    const ptr = new NativePointer(address);
    const module = Process.findModuleByAddress(ptr);
    
    if (!module) {
      return {
        success: true,
        data: null
      };
    }
    
    const moduleDetails: ModuleDetails = {
      name: module.name,
      base: module.base.toString(),
      size: module.size,
      path: module.path
    };
    
    return {
      success: true,
      data: moduleDetails
    };
  } catch (error) {
    return {
      success: false,
      error: `通过地址查找模块失败: ${error}`
    };
  }
}

/**
 * 通过名称查找模块
 */
export function findModuleByName(name: string): ProcessOperationResult {
  try {
    const module = Process.findModuleByName(name);
    
    if (!module) {
      return {
        success: true,
        data: null
      };
    }
    
    const moduleDetails: ModuleDetails = {
      name: module.name,
      base: module.base.toString(),
      size: module.size,
      path: module.path
    };
    
    return {
      success: true,
      data: moduleDetails
    };
  } catch (error) {
    return {
      success: false,
      error: `通过名称查找模块失败: ${error}`
    };
  }
}

/**
 * 枚举所有已加载模块
 */
export function enumerateModules(): ProcessOperationResult {
  try {
    const modules = Process.enumerateModules().map(module => ({
      name: module.name,
      base: module.base.toString(),
      size: module.size,
      path: module.path
    }));
    
    return {
      success: true,
      data: modules
    };
  } catch (error) {
    return {
      success: false,
      error: `枚举模块失败: ${error}`
    };
  }
}

/**
 * 通过地址查找内存范围
 */
export function findRangeByAddress(address: string): ProcessOperationResult {
  try {
    const ptr = new NativePointer(address);
    const range = Process.findRangeByAddress(ptr);
    
    if (!range) {
      return {
        success: true,
        data: null
      };
    }
    
    const rangeDetails: RangeDetails = {
      base: range.base.toString(),
      size: range.size,
      protection: range.protection
    };
    
    if (range.file) {
      rangeDetails.file = {
        path: range.file.path,
        offset: range.file.offset,
        size: range.file.size
      };
    }
    
    return {
      success: true,
      data: rangeDetails
    };
  } catch (error) {
    return {
      success: false,
      error: `通过地址查找内存范围失败: ${error}`
    };
  }
}

/**
 * 枚举内存范围
 */
export function enumerateRanges(specifier: string | EnumerateRangesSpecifier): ProcessOperationResult {
  try {
    const ranges = Process.enumerateRanges(specifier).map(range => {
      const rangeDetails: RangeDetails = {
        base: range.base.toString(),
        size: range.size,
        protection: range.protection
      };
      
      if (range.file) {
        rangeDetails.file = {
          path: range.file.path,
          offset: range.file.offset,
          size: range.file.size
        };
      }
      
      return rangeDetails;
    });
    
    return {
      success: true,
      data: ranges
    };
  } catch (error) {
    return {
      success: false,
      error: `枚举内存范围失败: ${error}`
    };
  }
}

/**
 * 枚举堆内存范围
 */
export function enumerateMallocRanges(): ProcessOperationResult {
  try {
    const ranges = Process.enumerateMallocRanges().map(range => {
      const rangeDetails: RangeDetails = {
        base: range.base.toString(),
        size: range.size,
        protection: range.protection
      };
      
      if (range.file) {
        rangeDetails.file = {
          path: range.file.path,
          offset: range.file.offset,
          size: range.file.size
        };
      }
      
      return rangeDetails;
    });
    
    return {
      success: true,
      data: ranges
    };
  } catch (error) {
    return {
      success: false,
      error: `枚举堆内存范围失败: ${error}`
    };
  }
} 