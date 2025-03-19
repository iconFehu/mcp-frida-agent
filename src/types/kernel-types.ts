/**
 * Kernel API的类型定义
 */

// 操作结果接口
export interface KernelOperationResult {
  success: boolean;
  error?: string;
  data?: any;
}

// 模块详细信息
export interface KernelModuleDetails {
  name: string;
  base: string;
  size: number;
}

// 内存范围详细信息
export interface KernelRangeDetails {
  base: string;
  size: number;
  protection: string;
}

// 模块范围详细信息
export interface KernelModuleRangeDetails extends KernelRangeDetails {
  name: string;
  path?: string;
}

// 内存扫描匹配
export interface KernelMemoryScanMatch {
  address: string;
}

// 内存扫描回调
export interface KernelMemoryScanCallbacks {
  onMatch: (address: string) => void;
  onComplete: () => void;
  onError?: (error: Error) => void;
}

// 页面保护枚举
export enum PageProtection {
  NoAccess = '---',
  Read = 'r--',
  Write = '-w-',
  Execute = '--x',
  ReadWrite = 'rw-',
  ReadExecute = 'r-x',
  ReadWriteExecute = 'rwx'
}

// 内存扫描选项
export interface KernelScanOptions {
  onMatch?: (address: string) => void;
  onComplete?: () => void;
  onError?: (error: Error) => void;
}

// 内核信息
export interface KernelInfo {
  available: boolean;
  base: string;
  pageSize: number;
} 