/**
 * 指针相关类型定义
 */

// 指针操作结果接口
export interface PointerOperationResult {
  success: boolean;
  error?: string;
  pointer?: string;
  data?: any;
}

/**
 * NativePointer API的类型定义
 */

// 指针值类型
export interface PointerValue {
  address: string;
}

// 指针比较结果
export enum PointerCompareResult {
  LessThan = -1,
  Equal = 0,
  GreaterThan = 1
}

// 指针验证结果
export interface PointerValidityResult {
  isValid: boolean;
  isNull: boolean;
}

// 指针读取选项
export interface PointerReadOptions {
  // 是否使用volatile读取
  volatile?: boolean;
  // 自定义长度
  length?: number;
  // 字符串长度限制
  maxLength?: number;
}

// 指针写入选项
export interface PointerWriteOptions {
  // 是否使用volatile写入
  volatile?: boolean;
}

// 指针认证密钥
export type PointerAuthKey = 'ia' | 'ib' | 'da' | 'db';

// 指针认证配置
export interface PointerAuthConfig {
  key: PointerAuthKey;
  data?: string; // 指针地址字符串
}

// 指针数学运算类型
export enum PointerOperation {
  Add = 'add',
  Subtract = 'sub',
  And = 'and',
  Or = 'or',
  Xor = 'xor',
  ShiftLeft = 'shl',
  ShiftRight = 'shr'
}

// 指针读取数据类型
export enum PointerReadType {
  Pointer = 'pointer',
  S8 = 's8',
  U8 = 'u8',
  S16 = 's16',
  U16 = 'u16',
  S32 = 's32',
  U32 = 'u32',
  S64 = 's64',
  U64 = 'u64',
  Short = 'short',
  UShort = 'ushort',
  Int = 'int',
  UInt = 'uint',
  Long = 'long',
  ULong = 'ulong',
  Float = 'float',
  Double = 'double',
  ByteArray = 'byteArray',
  CString = 'cstring',
  Utf8String = 'utf8string',
  Utf16String = 'utf16string',
  AnsiString = 'ansistring'
}

// 指针写入数据类型
export enum PointerWriteType {
  Pointer = 'pointer',
  S8 = 's8',
  U8 = 'u8',
  S16 = 's16',
  U16 = 'u16',
  S32 = 's32',
  U32 = 'u32',
  S64 = 's64',
  U64 = 'u64',
  Short = 'short',
  UShort = 'ushort',
  Int = 'int',
  UInt = 'uint',
  Long = 'long',
  ULong = 'ulong',
  Float = 'float',
  Double = 'double',
  ByteArray = 'byteArray',
  Utf8String = 'utf8string',
  Utf16String = 'utf16string',
  AnsiString = 'ansistring'
}

// 数值转换结果
export interface NumberConversionResult {
  int32Value?: number;
  uint32Value?: number;
  stringValue: string;
}

// 批量操作请求
export interface BatchOperationRequest {
  operations: PointerOperation[];
  addresses: string[];
}

// 批量操作结果
export interface BatchOperationResult {
  results: PointerOperationResult[];
}
