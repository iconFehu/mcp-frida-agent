/**
 * 环境检查工具
 * 用于确保代码在正确的环境中运行
 */

// 声明全局变量以避免TypeScript错误
declare const global: any;

// 检查当前是否为Frida Agent环境
export function isFridaAgentEnvironment(): boolean {
  return typeof global !== 'undefined' && 
         typeof global.Process !== 'undefined' && 
         typeof global.Module !== 'undefined';
}

// 断言当前环境为Frida Agent环境
export function assertFridaAgentEnvironment(): void {
  if (!isFridaAgentEnvironment()) {
    throw new Error('此代码必须在Frida Agent环境中运行');
  }
}

// Frida环境专用装饰器
export function FridaAgentOnly() {
  return function (
    target: any,
    propertyKey: string,
    descriptor: PropertyDescriptor
  ) {
    const originalMethod = descriptor.value;
    descriptor.value = function (...args: any[]) {
      assertFridaAgentEnvironment();
      return originalMethod.apply(this, args);
    };
    return descriptor;
  };
}
