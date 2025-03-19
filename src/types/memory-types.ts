/**
 * Memory操作相关类型定义
 */

// Memory操作结果接口
export interface MemoryOperationResult {
  success: boolean;
  error?: string;
  address?: string;
  data?: any;
}

// 内存扫描匹配结果
export interface MemoryScanMatch {
  address: string;
  size?: number;
}

// 内存页保护属性
export type PageProtection = 
  | '---' 
  | 'r--' 
  | '-w-' 
  | '--x' 
  | 'r-x' 
  | 'rw-' 
  | '-wx' 
  | 'rwx';

// 内存分配选项
export interface MemoryAllocOptions {
  near?: string;   // 内存分配的附近地址
  maxDistance?: number; // 与near地址的最大距离
  protection?: PageProtection; // 内存保护属性
}

// 内存扫描选项
export interface MemoryScanOptions {
  limit?: number;  // 最大匹配数量
  encoding?: string; // 模式编码
}
