/**
 * Process API相关类型定义
 */

// 进程基本信息接口
export interface ProcessInfo {
  id: number;
  arch: string;
  platform: string;
  pageSize: number;
  pointerSize: number;
  codeSigningPolicy: string;
}

// 线程详情接口
export interface ThreadDetails {
  id: number;
  state: string;
  context: any;
}

// 模块详情接口
export interface ModuleDetails {
  name: string;
  base: string;
  size: number;
  path: string;
}

// 内存范围详情接口
export interface RangeDetails {
  base: string;
  size: number;
  protection: string;
  file?: {
    path: string;
    offset: number;
    size: number;
  };
}

// 内存范围枚举选项
export interface EnumerateRangesSpecifier {
  protection: string;
  coalesce: boolean;
}

// Process操作结果接口
export interface ProcessOperationResult {
  success: boolean;
  error?: string;
  data?: any;
} 