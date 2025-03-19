/**
 * Socket API的RPC导出包装器
 * 
 * 该模块封装了Frida的Socket API并通过RPC导出，
 * 使得可以在Node.js端直接操作目标进程的网络连接。
 */

import {
  SocketType,
  SocketEndpointAddress,
  SocketListenOptions,
  SocketConnectOptions,
  SocketConnection,
  SocketListener,
  SocketOperationResult
} from '../types/socket-types.js';

// 声明Socket类型以避免TypeScript错误
declare namespace Socket {
  function listen(options?: SocketListenOptions): Promise<any>;
  function connect(options: SocketConnectOptions): Promise<any>;
  function type(handle: number): string | null;
  function localAddress(handle: number): any | null;
  function peerAddress(handle: number): any | null;
}

// 存储活动的Socket连接和监听器
const activeConnections = new Map<string, any>();
const activeListeners = new Map<string, any>();

/**
 * 创建Socket监听器
 */
export async function listen(options: SocketListenOptions): Promise<SocketOperationResult> {
  try {
    const listener = await Socket.listen(options);
    const id = generateId();
    
    // 转换地址信息
    const address = convertAddress(await listener.address);
    
    // 存储监听器实例
    activeListeners.set(id, listener);
    
    const listenerInfo: SocketListener = {
      id,
      type: options.type || 'tcp',
      address
    };
    
    return {
      success: true,
      data: listenerInfo
    };
  } catch (error) {
    return {
      success: false,
      error: `创建Socket监听器失败: ${error}`
    };
  }
}

/**
 * 连接到Socket服务器
 */
export async function connect(options: SocketConnectOptions): Promise<SocketOperationResult> {
  try {
    const connection = await Socket.connect(options);
    const id = generateId();
    
    // 转换地址信息
    const localAddress = convertAddress(await connection.localAddress);
    const peerAddress = convertAddress(await connection.peerAddress);
    
    // 存储连接实例
    activeConnections.set(id, connection);
    
    const connectionInfo: SocketConnection = {
      id,
      type: options.type || 'tcp',
      localAddress,
      peerAddress
    };
    
    return {
      success: true,
      data: connectionInfo
    };
  } catch (error) {
    return {
      success: false,
      error: `连接Socket服务器失败: ${error}`
    };
  }
}

/**
 * 获取Socket类型
 */
export function getSocketType(handle: number): SocketOperationResult {
  try {
    const type = Socket.type(handle);
    
    return {
      success: true,
      data: {
        type
      }
    };
  } catch (error) {
    return {
      success: false,
      error: `获取Socket类型失败: ${error}`
    };
  }
}

/**
 * 获取Socket本地地址
 */
export function getLocalAddress(handle: number): SocketOperationResult {
  try {
    const address = Socket.localAddress(handle);
    
    if (!address) {
      return {
        success: true,
        data: null
      };
    }
    
    return {
      success: true,
      data: convertAddress(address)
    };
  } catch (error) {
    return {
      success: false,
      error: `获取Socket本地地址失败: ${error}`
    };
  }
}

/**
 * 获取Socket对端地址
 */
export function getPeerAddress(handle: number): SocketOperationResult {
  try {
    const address = Socket.peerAddress(handle);
    
    if (!address) {
      return {
        success: true,
        data: null
      };
    }
    
    return {
      success: true,
      data: convertAddress(address)
    };
  } catch (error) {
    return {
      success: false,
      error: `获取Socket对端地址失败: ${error}`
    };
  }
}

/**
 * 关闭Socket连接
 */
export async function closeConnection(id: string): Promise<SocketOperationResult> {
  try {
    const connection = activeConnections.get(id);
    
    if (!connection) {
      return {
        success: false,
        error: '连接不存在'
      };
    }
    
    await connection.close();
    activeConnections.delete(id);
    
    return {
      success: true
    };
  } catch (error) {
    return {
      success: false,
      error: `关闭Socket连接失败: ${error}`
    };
  }
}

/**
 * 关闭Socket监听器
 */
export async function closeListener(id: string): Promise<SocketOperationResult> {
  try {
    const listener = activeListeners.get(id);
    
    if (!listener) {
      return {
        success: false,
        error: '监听器不存在'
      };
    }
    
    await listener.close();
    activeListeners.delete(id);
    
    return {
      success: true
    };
  } catch (error) {
    return {
      success: false,
      error: `关闭Socket监听器失败: ${error}`
    };
  }
}

/**
 * 发送数据
 */
export async function send(id: string, data: string | ArrayBuffer): Promise<SocketOperationResult> {
  try {
    const connection = activeConnections.get(id);
    
    if (!connection) {
      return {
        success: false,
        error: '连接不存在'
      };
    }
    
    await connection.output.write(data);
    
    return {
      success: true
    };
  } catch (error) {
    return {
      success: false,
      error: `发送数据失败: ${error}`
    };
  }
}

/**
 * 接收数据
 */
export async function receive(id: string, size: number): Promise<SocketOperationResult> {
  try {
    const connection = activeConnections.get(id);
    
    if (!connection) {
      return {
        success: false,
        error: '连接不存在'
      };
    }
    
    const data = await connection.input.read(size);
    
    return {
      success: true,
      data
    };
  } catch (error) {
    return {
      success: false,
      error: `接收数据失败: ${error}`
    };
  }
}

// 工具函数：生成唯一ID
function generateId(): string {
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
}

// 工具函数：转换地址格式
function convertAddress(address: any): SocketEndpointAddress {
  if (!address) {
    return {};
  }
  
  const result: SocketEndpointAddress = {};
  
  if (address.ip) {
    result.ip = address.ip;
  }
  
  if (address.port) {
    result.port = address.port;
  }
  
  if (address.path) {
    result.path = address.path;
  }
  
  if (address.family) {
    result.family = address.family;
  }
  
  return result;
} 