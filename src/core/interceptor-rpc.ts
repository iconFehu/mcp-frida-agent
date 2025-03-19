/**
 * Interceptor API的RPC导出包装器
 */

import {
  InterceptorOperationResult,
  InterceptorListenerId,
  InterceptorCallbackType,
  InterceptorCallbackParams,
  InterceptorCallbackContext,
  ReplacementMode,
  BreakpointKind,
  InterceptorAttachConfig,
  ReplacementConfig,
  InterceptorEventType,
  InterceptorEventData
} from '../types/interceptor-types.js';

// 保存活跃的监听器
const activeListeners = new Map<string, InvocationListener>();
// 保存替换的原始函数
const replacedTargets = new Map<string, NativePointer>();
// 保存快速替换的原始函数
const fastReplacedTargets = new Map<string, NativePointer>();
// 保存回调函数
const callbackHandlers = new Map<string, Function>();

// 生成唯一ID
function generateId(): string {
  return Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
}

/**
 * 收集参数信息
 */
function collectArguments(args: any[], count: number = 8): any[] {
  const result = [];
  for (let i = 0; i < count && i < args.length; i++) {
    const arg = args[i];
    result.push({
      value: arg.toString(),
      asInt: arg.toInt32(),
      asFloat: arg instanceof NativePointer ? null : parseFloat(arg.toString()),
      asPointer: arg instanceof NativePointer ? arg.toString() : null
    });
  }
  return result;
}

/**
 * 收集返回值信息
 */
function collectReturnValue(retval: any): any {
  return {
    value: retval.toString(),
    asInt: retval.toInt32(),
    asFloat: retval instanceof NativePointer ? null : parseFloat(retval.toString()),
    asPointer: retval instanceof NativePointer ? retval.toString() : null
  };
}

/**
 * 创建事件数据
 */
function createEventData(type: InterceptorEventType, targetId: string, context: InterceptorCallbackContext, error?: string): InterceptorEventData {
  return {
    type,
    targetId,
    context,
    error,
    timestamp: Date.now()
  };
}

/**
 * 附加拦截器
 */
export function attach(targetAddress: string, config: InterceptorAttachConfig): InterceptorOperationResult {
  try {
    const id = generateId();
    const target = ptr(targetAddress);
    
    const callbacks: any = {};
    
    if (config.onEnter) {
      callbacks.onEnter = function(args: any) {
        try {
          const context: InterceptorCallbackContext = {};
          
          if (config.collectContext) {
            context.returnAddress = this.returnAddress.toString();
            context.threadId = this.threadId;
            context.depth = this.depth;
            context.context = this.context;
          }
          
          if (config.argCount !== 0) {
            context.args = collectArguments(args, config.argCount);
          }
          
          const eventData = createEventData(
            InterceptorEventType.Enter,
            id,
            context
          );
          
          send(eventData);
          
        } catch (error: any) {
          const errorData = createEventData(
            InterceptorEventType.Error,
            id,
            {},
            error.toString()
          );
          send(errorData);
        }
      };
    }
    
    if (config.onLeave) {
      callbacks.onLeave = function(retval: any) {
        try {
          const context: InterceptorCallbackContext = {};
          
          if (config.collectReturnValue) {
            context.returnValue = collectReturnValue(retval);
          }
          
          const eventData = createEventData(
            InterceptorEventType.Leave,
            id,
            context
          );
          
          send(eventData);
          
          return retval;
          
        } catch (error: any) {
          const errorData = createEventData(
            InterceptorEventType.Error,
            id,
            {},
            error.toString()
          );
          send(errorData);
          return retval;
        }
      };
    }
    
    const listener = Interceptor.attach(target, callbacks);
    activeListeners.set(id, listener);
    
    return {
      success: true,
      data: { id }
    };
    
  } catch (error) {
    return {
      success: false,
      error: `附加拦截器失败: ${error}`
    };
  }
}

/**
 * 分离拦截器
 */
export function detach(listenerId: string): InterceptorOperationResult {
  try {
    const listener = activeListeners.get(listenerId);
    
    if (!listener) {
      return {
        success: false,
        error: `未找到ID为 ${listenerId} 的监听器`
      };
    }
    
    listener.detach();
    activeListeners.delete(listenerId);
    
    return {
      success: true
    };
    
  } catch (error) {
    return {
      success: false,
      error: `分离拦截器失败: ${error}`
    };
  }
}

/**
 * 分离所有拦截器
 */
export function detachAll(): InterceptorOperationResult {
  try {
    Interceptor.detachAll();
    activeListeners.clear();
    
    return {
      success: true
    };
    
  } catch (error) {
    return {
      success: false,
      error: `分离所有拦截器失败: ${error}`
    };
  }
}

/**
 * 替换函数
 */
export function replace(targetAddress: string, replacementAddress: string, config: ReplacementConfig): InterceptorOperationResult {
  try {
    const target = ptr(targetAddress);
    const replacement = ptr(replacementAddress);
    
    if (config.mode === ReplacementMode.Fast) {
      const original = Interceptor.replaceFast(target, replacement);
      
      if (config.saveOriginal) {
        fastReplacedTargets.set(targetAddress, original);
      }
      
      return {
        success: true,
        data: { 
          originalAddress: original.toString() 
        }
      };
      
    } else {
      Interceptor.replace(target, replacement, config.data);
      
      if (config.saveOriginal) {
        replacedTargets.set(targetAddress, target);
      }
      
      return {
        success: true
      };
    }
    
  } catch (error) {
    return {
      success: false,
      error: `替换函数失败: ${error}`
    };
  }
}

/**
 * 恢复替换的函数
 */
export function revert(targetAddress: string): InterceptorOperationResult {
  try {
    const target = ptr(targetAddress);
    
    Interceptor.revert(target);
    replacedTargets.delete(targetAddress);
    fastReplacedTargets.delete(targetAddress);
    
    return {
      success: true
    };
    
  } catch (error) {
    return {
      success: false,
      error: `恢复函数失败: ${error}`
    };
  }
}

/**
 * 刷新内存变更
 */
export function flush(): InterceptorOperationResult {
  try {
    Interceptor.flush();
    
    return {
      success: true
    };
    
  } catch (error) {
    return {
      success: false,
      error: `刷新失败: ${error}`
    };
  }
}

/**
 * 获取断点类型
 */
export function getBreakpointKind(): InterceptorOperationResult {
  try {
    // @ts-ignore: 只在裸机后端可用
    if ('breakpointKind' in Interceptor) {
      return {
        success: true,
        // @ts-ignore: 只在裸机后端可用
        data: { kind: Interceptor.breakpointKind }
      };
    } else {
      return {
        success: false,
        error: '断点类型只在裸机后端可用'
      };
    }
    
  } catch (error) {
    return {
      success: false,
      error: `获取断点类型失败: ${error}`
    };
  }
}

/**
 * 设置断点类型
 */
export function setBreakpointKind(kind: BreakpointKind): InterceptorOperationResult {
  try {
    // @ts-ignore: 只在裸机后端可用
    if ('breakpointKind' in Interceptor) {
      // @ts-ignore: 只在裸机后端可用
      Interceptor.breakpointKind = kind;
      
      return {
        success: true
      };
    } else {
      return {
        success: false,
        error: '断点类型只在裸机后端可用'
      };
    }
    
  } catch (error) {
    return {
      success: false,
      error: `设置断点类型失败: ${error}`
    };
  }
} 