/**
 * Stalker API的RPC导出包装器
 * 
 * 该模块封装了Frida的Stalker API并通过RPC导出，
 * 使得可以在Node.js端直接操作目标进程的执行跟踪。
 */

import {
  StalkerEventType,
  StalkerEvent,
  StalkerOptions,
  StalkerOperationResult,
  StalkerProbeInfo,
  StalkerThreadState,
  StalkerMemoryRange,
  StalkerConfig,
  StalkerCallProbeCallback
} from '../types/stalker-types.js';

// 修正声明以包含属性
declare namespace Stalker {
  var trustThreshold: number;
  var queueCapacity: number;
  var queueDrainInterval: number;
  function exclude(range: any): void;
  function follow(threadId?: number, options?: any): void;
  function unfollow(threadId?: number): void;
  function parse(events: ArrayBuffer, options?: any): any[];
  function flush(): void;
  function garbageCollect(): void;
  function invalidate(threadId: number, address: NativePointer): void;
  function addCallProbe(address: NativePointer, callback: StalkerCallProbeCallback, data?: NativePointer): number;
  function removeCallProbe(callbackId: number): void;
}

// 存储活动的线程状态
const activeThreads = new Map<number, StalkerThreadState>();

// 存储探针信息
const probes = new Map<string, StalkerProbeInfo>();

// 配置对象
let config: StalkerConfig = {
  trustThreshold: 1,
  queueCapacity: 16384,
  queueDrainInterval: 250
};

/**
 * 开始跟踪线程执行
 */
export function follow(threadId: number, options: StalkerOptions): StalkerOperationResult {
  try {
    // 设置事件处理回调
    const events: StalkerEvent[] = [];
    
    // 创建正确的跟踪选项
    const wrappedOptions: any = { ...options };
    
    // 删除onEvent，使用onReceive代替
    delete wrappedOptions.onEvent;
    
    // 添加onReceive回调
    wrappedOptions.onReceive = (buffer: any) => {
      try {
        const parsedEvents = Stalker.parse(buffer, { annotate: true });
        
        // 转换成我们的事件格式并存储
        const stalkerEvents = parsedEvents.map((event: any) => {
          // 确保所有字段被正确处理
          const stalkerEvent: StalkerEvent = {
            type: (event.type as StalkerEventType) || StalkerEventType.CALL,
            location: event.location ? event.location.toString() : undefined,
            target: event.target ? event.target.toString() : undefined,
            depth: event.depth || 0,
            data: event.data || {}
          };
          return stalkerEvent;
        });
        
        // 添加到事件数组
        events.push(...stalkerEvents);
        
        // 如果用户提供了回调，调用它
        if (options.onEvent) {
          stalkerEvents.forEach(e => options.onEvent?.(e));
        }
      } catch (error) {
        console.error(`解析事件数据失败: ${error}`);
      }
    };

    // 启动跟踪
    Stalker.follow(threadId, wrappedOptions);

    // 保存线程状态
    activeThreads.set(threadId, {
      threadId,
      options: wrappedOptions,
      events,
      probes: new Map()
    });

    return {
      success: true,
      data: { threadId }
    };
  } catch (error) {
    return {
      success: false,
      error: `跟踪线程失败: ${error}`
    };
  }
}

/**
 * 停止跟踪线程执行
 */
export function unfollow(threadId: number): StalkerOperationResult {
  try {
    // 停止跟踪
    Stalker.unfollow(threadId);

    // 清理线程状态
    activeThreads.delete(threadId);

    return {
      success: true
    };
  } catch (error) {
    return {
      success: false,
      error: `停止跟踪失败: ${error}`
    };
  }
}

/**
 * 排除内存范围
 */
export function exclude(range: StalkerMemoryRange): StalkerOperationResult {
  try {
    Stalker.exclude({
      base: ptr(range.base),
      size: range.size
    });

    return {
      success: true
    };
  } catch (error) {
    return {
      success: false,
      error: `排除内存范围失败: ${error}`
    };
  }
}

/**
 * 解析事件数据
 */
export function parse(events: ArrayBuffer): StalkerOperationResult {
  try {
    const parsed = Stalker.parse(events);

    return {
      success: true,
      data: parsed
    };
  } catch (error) {
    return {
      success: false,
      error: `解析事件失败: ${error}`
    };
  }
}

/**
 * 刷新事件缓冲区
 */
export function flush(): StalkerOperationResult {
  try {
    Stalker.flush();

    return {
      success: true
    };
  } catch (error) {
    return {
      success: false,
      error: `刷新缓冲区失败: ${error}`
    };
  }
}

/**
 * 执行垃圾回收
 */
export function garbageCollect(): StalkerOperationResult {
  try {
    Stalker.garbageCollect();

    return {
      success: true
    };
  } catch (error) {
    return {
      success: false,
      error: `垃圾回收失败: ${error}`
    };
  }
}

/**
 * 使代码缓存失效
 */
export function invalidate(threadId: number, address: string): StalkerOperationResult {
  try {
    Stalker.invalidate(threadId, ptr(address));

    return {
      success: true
    };
  } catch (error) {
    return {
      success: false,
      error: `使代码缓存失效失败: ${error}`
    };
  }
}

/**
 * 添加调用探针
 */
export function addCallProbe(address: string, callback: StalkerCallProbeCallback): StalkerOperationResult {
  try {
    // 创建一个原生回调函数包装JavaScript回调
    const nativeCallback = new NativeCallback((args: any) => {
      try {
        // 调用JavaScript回调,处理类型
        if (typeof callback === 'function') {
          callback(args);
        }
      } catch (error) {
        console.error(`调用探针回调出错: ${error}`);
      }
    }, 'void', ['pointer']);

    // 在引用丢失前存储回调
    const probeId = Stalker.addCallProbe(ptr(address), nativeCallback);
    const probeInfo: StalkerProbeInfo = {
      id: probeId.toString(),
      address,
      callback: nativeCallback
    };
    probes.set(probeInfo.id, probeInfo);

    return {
      success: true,
      data: { probeId: probeInfo.id }
    };
  } catch (error) {
    return {
      success: false,
      error: `添加调用探针失败: ${error}`
    };
  }
}

/**
 * 移除调用探针
 */
export function removeCallProbe(probeId: string): StalkerOperationResult {
  try {
    const probe = probes.get(probeId);
    if (!probe) {
      return {
        success: false,
        error: '探针不存在'
      };
    }

    Stalker.removeCallProbe(parseInt(probeId));
    probes.delete(probeId);

    return {
      success: true
    };
  } catch (error) {
    return {
      success: false,
      error: `移除调用探针失败: ${error}`
    };
  }
}

/**
 * 获取线程事件
 */
export function getThreadEvents(threadId: number): StalkerOperationResult {
  try {
    const state = activeThreads.get(threadId);
    if (!state) {
      return {
        success: false,
        error: '线程未被跟踪'
      };
    }

    return {
      success: true,
      data: {
        events: state.events
      }
    };
  } catch (error) {
    return {
      success: false,
      error: `获取线程事件失败: ${error}`
    };
  }
}

/**
 * 清空线程事件
 */
export function clearThreadEvents(threadId: number): StalkerOperationResult {
  try {
    const state = activeThreads.get(threadId);
    if (!state) {
      return {
        success: false,
        error: '线程未被跟踪'
      };
    }

    state.events = [];

    return {
      success: true
    };
  } catch (error) {
    return {
      success: false,
      error: `清空线程事件失败: ${error}`
    };
  }
}

/**
 * 设置配置
 */
export function setConfig(newConfig: Partial<StalkerConfig>): StalkerOperationResult {
  try {
    config = {
      ...config,
      ...newConfig
    };

    if (typeof newConfig.trustThreshold === 'number') {
      Stalker.trustThreshold = newConfig.trustThreshold;
    }
    if (typeof newConfig.queueCapacity === 'number') {
      Stalker.queueCapacity = newConfig.queueCapacity;
    }
    if (typeof newConfig.queueDrainInterval === 'number') {
      Stalker.queueDrainInterval = newConfig.queueDrainInterval;
    }

    return {
      success: true,
      data: { config }
    };
  } catch (error) {
    return {
      success: false,
      error: `设置配置失败: ${error}`
    };
  }
}

/**
 * 获取配置
 */
export function getConfig(): StalkerOperationResult {
  try {
    return {
      success: true,
      data: { config }
    };
  } catch (error) {
    return {
      success: false,
      error: `获取配置失败: ${error}`
    };
  }
}