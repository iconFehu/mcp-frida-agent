/**
 * Interceptor API的类型定义
 */

// 拦截操作的结果类型
export interface InterceptorOperationResult {
  success: boolean;
  error?: string;
  data?: any;
}

// 拦截器监听器ID
export interface InterceptorListenerId {
  id: string;
}

// 回调类型
export enum InterceptorCallbackType {
  OnEnter = 'onEnter',
  OnLeave = 'onLeave'
}

// 回调上下文参数
export interface InterceptorCallbackContext {
  returnAddress?: string;
  threadId?: number;
  depth?: number;
  context?: any;
  args?: Array<{
    value: string;
    asInt?: number;
    asFloat?: number;
    asPointer?: string;
  }>;
  returnValue?: {
    value: string;
    asInt?: number;
    asFloat?: number;
    asPointer?: string;
  };
}

// 回调参数
export interface InterceptorCallbackParams {
  type: InterceptorCallbackType;
  registerId: string;
  context: InterceptorCallbackContext;
}

// 替换函数模式
export enum ReplacementMode {
  Normal = 'normal',
  Fast = 'fast'
}

// 拦截配置
export interface InterceptorAttachConfig {
  onEnter?: boolean;
  onLeave?: boolean;
  synchronous?: boolean;
  // 是否收集调用上下文
  collectContext?: boolean;
  // 收集参数的数量(默认8)
  argCount?: number;
  // 是否收集返回值
  collectReturnValue?: boolean;
}

// 断点类型
export type BreakpointKind = 'soft' | 'hard';

// 替换函数配置
export interface ReplacementConfig {
  mode: ReplacementMode;
  // 是否保存原始函数
  saveOriginal?: boolean;
  // 替换函数的数据
  data?: NativePointer;
}

// 拦截器事件类型
export enum InterceptorEventType {
  Enter = 'interceptor:onEnter',
  Leave = 'interceptor:onLeave',
  Error = 'interceptor:onError'
}

// 拦截器事件数据
export interface InterceptorEventData {
  type: InterceptorEventType;
  targetId: string;
  context: InterceptorCallbackContext;
  error?: string;
  timestamp: number;
} 