/**
 * Socket API相关类型定义
 */

// Socket类型枚举
export type SocketType = 'tcp' | 'tcp6' | 'unix';

// Socket地址类型
export interface SocketEndpointAddress {
  ip?: string;
  port?: number;
  path?: string;
  family?: string;
}

// Socket监听选项
export interface SocketListenOptions {
  // TCP选项
  type?: SocketType;
  port?: number;
  address?: string;
  backlog?: number;
  // Unix选项
  path?: string;
  // 通用选项
  exclusive?: boolean;
}

// Socket连接选项
export interface SocketConnectOptions {
  // TCP选项
  type?: SocketType;
  host?: string;
  port?: number;
  // Unix选项
  path?: string;
  // 通用选项
  timeout?: number;
}

// Socket连接接口
export interface SocketConnection {
  id: string;
  type: SocketType;
  localAddress: SocketEndpointAddress;
  peerAddress: SocketEndpointAddress;
}

// Socket监听器接口
export interface SocketListener {
  id: string;
  type: SocketType;
  address: SocketEndpointAddress;
}

// Socket操作结果接口
export interface SocketOperationResult {
  success: boolean;
  error?: string;
  data?: any;
} 