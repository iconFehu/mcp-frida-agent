/**
 * Stalker API的类型定义
 */

// 事件类型枚举
export enum StalkerEventType {
  CALL = 'call',
  RET = 'ret',
  EXEC = 'exec',
  BLOCK = 'block',
  COMPILE = 'compile'
}

// 事件数据接口
export interface StalkerEvent {
  type: StalkerEventType;
  location?: string;
  target?: string;
  depth?: number;
  data?: any;
}

// 跟踪选项接口
export interface StalkerOptions {
  events?: {
    call?: boolean;
    ret?: boolean;
    exec?: boolean;
    block?: boolean;
    compile?: boolean;
  };
  transform?: StalkerTransformCallback;
  onEvent?: StalkerEventCallback;
  onReceive?: (events: ArrayBuffer) => void;
  onCallSummary?: (summary: { [target: string]: number }) => void;
  onCallProbe?: StalkerCallProbeCallback;
  queueCapacity?: number;
  queueDrainInterval?: number;
}

// 转换回调函数类型
export type StalkerTransformCallback = (iterator: any) => void;

// 事件回调函数类型
export type StalkerEventCallback = (event: StalkerEvent) => void;

// 调用探针回调函数类型
export type StalkerCallProbeCallback = ((args: any[]) => void) | NativeCallback<any, any[]>;

// 操作结果接口
export interface StalkerOperationResult {
  success: boolean;
  error?: string;
  data?: any;
}

// 探针信息接口
export interface StalkerProbeInfo {
  id: string;
  address: string;
  callback: StalkerCallProbeCallback;
}

// 线程跟踪状态接口
export interface StalkerThreadState {
  threadId: number;
  options: StalkerOptions;
  events: StalkerEvent[];
  probes: Map<string, StalkerProbeInfo>;
}

// 内存范围接口
export interface StalkerMemoryRange {
  base: string;
  size: number;
}

// 配置接口
export interface StalkerConfig {
  trustThreshold: number;
  queueCapacity: number;
  queueDrainInterval: number;
} 