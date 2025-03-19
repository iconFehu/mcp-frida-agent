/**
 * NativePointer API的RPC导出包装器
 */

import {
  PointerOperationResult,
  PointerValue,
  PointerCompareResult,
  PointerValidityResult,
  PointerReadOptions,
  PointerWriteOptions,
  PointerAuthKey,
  PointerAuthConfig,
  PointerOperation,
  PointerReadType,
  PointerWriteType,
  NumberConversionResult,
  BatchOperationRequest,
  BatchOperationResult
} from '../types/nativepointer-types.js';

/**
 * 创建一个NativePointer
 */
export function create(address: string | number): PointerOperationResult {
  try {
    const pointer = ptr(address.toString());
    return {
      success: true,
      data: {
        address: pointer.toString()
      }
    };
  } catch (error: any) {
    return {
      success: false,
      error: `创建指针失败: ${error.message || error}`
    };
  }
}

/**
 * 检查指针是否为null
 */
export function isNull(address: string): PointerOperationResult {
  try {
    const pointer = ptr(address);
    const result = pointer.isNull();
    
    return {
      success: true,
      data: {
        isNull: result
      }
    };
  } catch (error: any) {
    return {
      success: false,
      error: `检查指针失败: ${error.message || error}`
    };
  }
}

/**
 * 执行指针运算
 */
export function operate(operation: PointerOperation, address: string, operand: string | number): PointerOperationResult {
  try {
    const pointer = ptr(address);
    let result: NativePointer;
    
    switch (operation) {
      case PointerOperation.Add:
        result = pointer.add(operand);
        break;
      case PointerOperation.Subtract:
        result = pointer.sub(operand);
        break;
      case PointerOperation.And:
        result = pointer.and(operand);
        break;
      case PointerOperation.Or:
        result = pointer.or(operand);
        break;
      case PointerOperation.Xor:
        result = pointer.xor(operand);
        break;
      case PointerOperation.ShiftLeft:
        result = pointer.shl(operand);
        break;
      case PointerOperation.ShiftRight:
        result = pointer.shr(operand);
        break;
      default:
        return {
          success: false,
          error: `不支持的操作: ${operation}`
        };
    }
    
    return {
      success: true,
      data: {
        address: result.toString()
      }
    };
  } catch (error: any) {
    return {
      success: false,
      error: `指针运算失败: ${error.message || error}`
    };
  }
}

/**
 * 指针加法
 */
export function add(address: string, operand: string | number): PointerOperationResult {
  return operate(PointerOperation.Add, address, operand);
}

/**
 * 指针减法
 */
export function sub(address: string, operand: string | number): PointerOperationResult {
  return operate(PointerOperation.Subtract, address, operand);
}

/**
 * 指针按位与
 */
export function and(address: string, operand: string | number): PointerOperationResult {
  return operate(PointerOperation.And, address, operand);
}

/**
 * 指针按位或
 */
export function or(address: string, operand: string | number): PointerOperationResult {
  return operate(PointerOperation.Or, address, operand);
}

/**
 * 指针按位异或
 */
export function xor(address: string, operand: string | number): PointerOperationResult {
  return operate(PointerOperation.Xor, address, operand);
}

/**
 * 指针左移
 */
export function shl(address: string, operand: string | number): PointerOperationResult {
  return operate(PointerOperation.ShiftLeft, address, operand);
}

/**
 * 指针右移
 */
export function shr(address: string, operand: string | number): PointerOperationResult {
  return operate(PointerOperation.ShiftRight, address, operand);
}

/**
 * 指针按位非
 */
export function not(address: string): PointerOperationResult {
  try {
    const pointer = ptr(address);
    const result = pointer.not();
    
    return {
      success: true,
      data: {
        address: result.toString()
      }
    };
  } catch (error: any) {
    return {
      success: false,
      error: `指针按位非操作失败: ${error.message || error}`
    };
  }
}

/**
 * 签名指针（指针认证）
 */
export function sign(address: string, config: PointerAuthConfig): PointerOperationResult {
  try {
    const pointer = ptr(address);
    const { key, data } = config;
    const result = data ? pointer.sign(key, ptr(data)) : pointer.sign(key);
    
    return {
      success: true,
      data: {
        address: result.toString()
      }
    };
  } catch (error: any) {
    return {
      success: false,
      error: `指针签名失败: ${error.message || error}`
    };
  }
}

/**
 * 去除指针签名（指针认证）
 */
export function strip(address: string, key: PointerAuthKey): PointerOperationResult {
  try {
    const pointer = ptr(address);
    const result = pointer.strip(key);
    
    return {
      success: true,
      data: {
        address: result.toString()
      }
    };
  } catch (error: any) {
    return {
      success: false,
      error: `去除指针签名失败: ${error.message || error}`
    };
  }
}

/**
 * 混合指针（指针认证）
 */
export function blend(address: string, smallInteger: number): PointerOperationResult {
  try {
    const pointer = ptr(address);
    const result = pointer.blend(smallInteger);
    
    return {
      success: true,
      data: {
        address: result.toString()
      }
    };
  } catch (error: any) {
    return {
      success: false,
      error: `混合指针失败: ${error.message || error}`
    };
  }
}

/**
 * 比较两个指针
 */
export function compare(address: string, otherAddress: string | number): PointerOperationResult {
  try {
    const pointer = ptr(address);
    const otherPointer = ptr(otherAddress.toString());
    const result = pointer.compare(otherPointer);
    
    return {
      success: true,
      data: {
        result: result
      }
    };
  } catch (error: any) {
    return {
      success: false,
      error: `比较指针失败: ${error.message || error}`
    };
  }
}

/**
 * 检查两个指针是否相等
 */
export function equals(address: string, otherAddress: string | number): PointerOperationResult {
  try {
    const pointer = ptr(address);
    const otherPointer = ptr(otherAddress.toString());
    const result = pointer.equals(otherPointer);
    
    return {
      success: true,
      data: {
        equals: result
      }
    };
  } catch (error: any) {
    return {
      success: false,
      error: `比较指针相等性失败: ${error.message || error}`
    };
  }
}

/**
 * 转换指针为32位有符号整数
 */
export function toInt32(address: string): PointerOperationResult {
  try {
    const pointer = ptr(address);
    const result = pointer.toInt32();
    
    return {
      success: true,
      data: {
        value: result
      }
    };
  } catch (error: any) {
    return {
      success: false,
      error: `转换指针为Int32失败: ${error.message || error}`
    };
  }
}

/**
 * 转换指针为32位无符号整数
 */
export function toUInt32(address: string): PointerOperationResult {
  try {
    const pointer = ptr(address);
    const result = pointer.toUInt32();
    
    return {
      success: true,
      data: {
        value: result
      }
    };
  } catch (error: any) {
    return {
      success: false,
      error: `转换指针为UInt32失败: ${error.message || error}`
    };
  }
}

/**
 * 转换指针为字符串
 */
export function toString(address: string, radix: number = 16): PointerOperationResult {
  try {
    const pointer = ptr(address);
    const result = pointer.toString(radix);
    
    return {
      success: true,
      data: {
        value: result
      }
    };
  } catch (error: any) {
    return {
      success: false,
      error: `转换指针为字符串失败: ${error.message || error}`
    };
  }
}

/**
 * 转换指针为匹配模式
 */
export function toMatchPattern(address: string): PointerOperationResult {
  try {
    const pointer = ptr(address);
    const result = pointer.toMatchPattern();
    
    return {
      success: true,
      data: {
        pattern: result
      }
    };
  } catch (error: any) {
    return {
      success: false,
      error: `转换指针为匹配模式失败: ${error.message || error}`
    };
  }
}

/**
 * 读取内存 - 通用函数
 */
function readMemory(address: string, type: PointerReadType, options?: PointerReadOptions): PointerOperationResult {
  try {
    const pointer = ptr(address);
    let result: any;
    
    switch (type) {
      case PointerReadType.Pointer:
        result = pointer.readPointer();
        result = { address: result.toString() };
        break;
      case PointerReadType.S8:
        result = pointer.readS8();
        break;
      case PointerReadType.U8:
        result = pointer.readU8();
        break;
      case PointerReadType.S16:
        result = pointer.readS16();
        break;
      case PointerReadType.U16:
        result = pointer.readU16();
        break;
      case PointerReadType.S32:
        result = pointer.readS32();
        break;
      case PointerReadType.U32:
        result = pointer.readU32();
        break;
      case PointerReadType.S64:
        result = pointer.readS64();
        result = result.toString();
        break;
      case PointerReadType.U64:
        result = pointer.readU64();
        result = result.toString();
        break;
      case PointerReadType.Short:
        result = pointer.readShort();
        break;
      case PointerReadType.UShort:
        result = pointer.readUShort();
        break;
      case PointerReadType.Int:
        result = pointer.readInt();
        break;
      case PointerReadType.UInt:
        result = pointer.readUInt();
        break;
      case PointerReadType.Long:
        result = pointer.readLong();
        if (result instanceof Int64) {
          result = result.toString();
        }
        break;
      case PointerReadType.ULong:
        result = pointer.readULong();
        if (result instanceof UInt64) {
          result = result.toString();
        }
        break;
      case PointerReadType.Float:
        result = pointer.readFloat();
        break;
      case PointerReadType.Double:
        result = pointer.readDouble();
        break;
      case PointerReadType.ByteArray:
        if (options?.length === undefined) {
          return {
            success: false,
            error: "读取ByteArray时必须指定长度"
          };
        }
        const arrayBuffer = options.volatile 
          ? pointer.readVolatile(options.length) 
          : pointer.readByteArray(options.length);
        
        if (arrayBuffer === null) {
          result = null;
        } else {
          const uint8Array = new Uint8Array(arrayBuffer);
          result = Array.from(uint8Array);
        }
        break;
      case PointerReadType.CString:
        result = pointer.readCString(options?.maxLength);
        break;
      case PointerReadType.Utf8String:
        result = pointer.readUtf8String(options?.maxLength);
        break;
      case PointerReadType.Utf16String:
        result = pointer.readUtf16String(options?.maxLength);
        break;
      case PointerReadType.AnsiString:
        result = pointer.readAnsiString(options?.maxLength);
        break;
      default:
        return {
          success: false,
          error: `不支持的读取类型: ${type}`
        };
    }
    
    return {
      success: true,
      data: {
        value: result
      }
    };
  } catch (error: any) {
    return {
      success: false,
      error: `读取内存失败 (${type}): ${error.message || error}`
    };
  }
}

/**
 * 写入内存 - 通用函数
 */
function writeMemory(address: string, type: PointerWriteType, value: any, options?: PointerWriteOptions): PointerOperationResult {
  try {
    const pointer = ptr(address);
    
    switch (type) {
      case PointerWriteType.Pointer:
        pointer.writePointer(ptr(value));
        break;
      case PointerWriteType.S8:
        pointer.writeS8(value);
        break;
      case PointerWriteType.U8:
        pointer.writeU8(value);
        break;
      case PointerWriteType.S16:
        pointer.writeS16(value);
        break;
      case PointerWriteType.U16:
        pointer.writeU16(value);
        break;
      case PointerWriteType.S32:
        pointer.writeS32(value);
        break;
      case PointerWriteType.U32:
        pointer.writeU32(value);
        break;
      case PointerWriteType.S64:
        pointer.writeS64(value);
        break;
      case PointerWriteType.U64:
        pointer.writeU64(value);
        break;
      case PointerWriteType.Short:
        pointer.writeShort(value);
        break;
      case PointerWriteType.UShort:
        pointer.writeUShort(value);
        break;
      case PointerWriteType.Int:
        pointer.writeInt(value);
        break;
      case PointerWriteType.UInt:
        pointer.writeUInt(value);
        break;
      case PointerWriteType.Long:
        pointer.writeLong(value);
        break;
      case PointerWriteType.ULong:
        pointer.writeULong(value);
        break;
      case PointerWriteType.Float:
        pointer.writeFloat(value);
        break;
      case PointerWriteType.Double:
        pointer.writeDouble(value);
        break;
      case PointerWriteType.ByteArray:
        if (options?.volatile) {
          pointer.writeVolatile(value);
        } else {
          pointer.writeByteArray(value);
        }
        break;
      case PointerWriteType.Utf8String:
        pointer.writeUtf8String(value);
        break;
      case PointerWriteType.Utf16String:
        pointer.writeUtf16String(value);
        break;
      case PointerWriteType.AnsiString:
        pointer.writeAnsiString(value);
        break;
      default:
        return {
          success: false,
          error: `不支持的写入类型: ${type}`
        };
    }
    
    return {
      success: true,
      data: {
        address: pointer.toString()
      }
    };
  } catch (error: any) {
    return {
      success: false,
      error: `写入内存失败 (${type}): ${error.message || error}`
    };
  }
}

// 导出各种读取函数
export function readPointer(address: string): PointerOperationResult {
  return readMemory(address, PointerReadType.Pointer);
}

export function readS8(address: string): PointerOperationResult {
  return readMemory(address, PointerReadType.S8);
}

export function readU8(address: string): PointerOperationResult {
  return readMemory(address, PointerReadType.U8);
}

export function readS16(address: string): PointerOperationResult {
  return readMemory(address, PointerReadType.S16);
}

export function readU16(address: string): PointerOperationResult {
  return readMemory(address, PointerReadType.U16);
}

export function readS32(address: string): PointerOperationResult {
  return readMemory(address, PointerReadType.S32);
}

export function readU32(address: string): PointerOperationResult {
  return readMemory(address, PointerReadType.U32);
}

export function readS64(address: string): PointerOperationResult {
  return readMemory(address, PointerReadType.S64);
}

export function readU64(address: string): PointerOperationResult {
  return readMemory(address, PointerReadType.U64);
}

export function readShort(address: string): PointerOperationResult {
  return readMemory(address, PointerReadType.Short);
}

export function readUShort(address: string): PointerOperationResult {
  return readMemory(address, PointerReadType.UShort);
}

export function readInt(address: string): PointerOperationResult {
  return readMemory(address, PointerReadType.Int);
}

export function readUInt(address: string): PointerOperationResult {
  return readMemory(address, PointerReadType.UInt);
}

export function readLong(address: string): PointerOperationResult {
  return readMemory(address, PointerReadType.Long);
}

export function readULong(address: string): PointerOperationResult {
  return readMemory(address, PointerReadType.ULong);
}

export function readFloat(address: string): PointerOperationResult {
  return readMemory(address, PointerReadType.Float);
}

export function readDouble(address: string): PointerOperationResult {
  return readMemory(address, PointerReadType.Double);
}

export function readByteArray(address: string, length: number, volatile?: boolean): PointerOperationResult {
  return readMemory(address, PointerReadType.ByteArray, { length, volatile });
}

export function readCString(address: string, maxLength?: number): PointerOperationResult {
  return readMemory(address, PointerReadType.CString, { maxLength });
}

export function readUtf8String(address: string, maxLength?: number): PointerOperationResult {
  return readMemory(address, PointerReadType.Utf8String, { maxLength });
}

export function readUtf16String(address: string, maxLength?: number): PointerOperationResult {
  return readMemory(address, PointerReadType.Utf16String, { maxLength });
}

export function readAnsiString(address: string, maxLength?: number): PointerOperationResult {
  return readMemory(address, PointerReadType.AnsiString, { maxLength });
}

// 导出各种写入函数
export function writePointer(address: string, value: string): PointerOperationResult {
  return writeMemory(address, PointerWriteType.Pointer, value);
}

export function writeS8(address: string, value: number): PointerOperationResult {
  return writeMemory(address, PointerWriteType.S8, value);
}

export function writeU8(address: string, value: number): PointerOperationResult {
  return writeMemory(address, PointerWriteType.U8, value);
}

export function writeS16(address: string, value: number): PointerOperationResult {
  return writeMemory(address, PointerWriteType.S16, value);
}

export function writeU16(address: string, value: number): PointerOperationResult {
  return writeMemory(address, PointerWriteType.U16, value);
}

export function writeS32(address: string, value: number): PointerOperationResult {
  return writeMemory(address, PointerWriteType.S32, value);
}

export function writeU32(address: string, value: number): PointerOperationResult {
  return writeMemory(address, PointerWriteType.U32, value);
}

export function writeS64(address: string, value: string | number): PointerOperationResult {
  return writeMemory(address, PointerWriteType.S64, value);
}

export function writeU64(address: string, value: string | number): PointerOperationResult {
  return writeMemory(address, PointerWriteType.U64, value);
}

export function writeShort(address: string, value: number): PointerOperationResult {
  return writeMemory(address, PointerWriteType.Short, value);
}

export function writeUShort(address: string, value: number): PointerOperationResult {
  return writeMemory(address, PointerWriteType.UShort, value);
}

export function writeInt(address: string, value: number): PointerOperationResult {
  return writeMemory(address, PointerWriteType.Int, value);
}

export function writeUInt(address: string, value: number): PointerOperationResult {
  return writeMemory(address, PointerWriteType.UInt, value);
}

export function writeLong(address: string, value: string | number): PointerOperationResult {
  return writeMemory(address, PointerWriteType.Long, value);
}

export function writeULong(address: string, value: string | number): PointerOperationResult {
  return writeMemory(address, PointerWriteType.ULong, value);
}

export function writeFloat(address: string, value: number): PointerOperationResult {
  return writeMemory(address, PointerWriteType.Float, value);
}

export function writeDouble(address: string, value: number): PointerOperationResult {
  return writeMemory(address, PointerWriteType.Double, value);
}

export function writeByteArray(address: string, value: number[] | ArrayBuffer, volatile?: boolean): PointerOperationResult {
  return writeMemory(address, PointerWriteType.ByteArray, value, { volatile });
}

export function writeUtf8String(address: string, value: string): PointerOperationResult {
  return writeMemory(address, PointerWriteType.Utf8String, value);
}

export function writeUtf16String(address: string, value: string): PointerOperationResult {
  return writeMemory(address, PointerWriteType.Utf16String, value);
}

export function writeAnsiString(address: string, value: string): PointerOperationResult {
  return writeMemory(address, PointerWriteType.AnsiString, value);
}

/**
 * 批量指针操作
 */
export function batchOperate(request: BatchOperationRequest): PointerOperationResult {
  try {
    const { operations, addresses } = request;
    if (operations.length !== addresses.length - 1) {
      return {
        success: false,
        error: "操作数量必须比地址数量少1"
      };
    }
    
    let pointer = ptr(addresses[0]);
    const results = [];
    
    for (let i = 0; i < operations.length; i++) {
      const operation = operations[i];
      const operand = addresses[i + 1];
      
      switch (operation) {
        case PointerOperation.Add:
          pointer = pointer.add(operand);
          break;
        case PointerOperation.Subtract:
          pointer = pointer.sub(operand);
          break;
        case PointerOperation.And:
          pointer = pointer.and(operand);
          break;
        case PointerOperation.Or:
          pointer = pointer.or(operand);
          break;
        case PointerOperation.Xor:
          pointer = pointer.xor(operand);
          break;
        case PointerOperation.ShiftLeft:
          pointer = pointer.shl(operand);
          break;
        case PointerOperation.ShiftRight:
          pointer = pointer.shr(operand);
          break;
        default:
          return {
            success: false,
            error: `不支持的操作: ${operation}`
          };
      }
      
      results.push({
        success: true,
        data: { address: pointer.toString() }
      });
    }
    
    return {
      success: true,
      data: {
        finalAddress: pointer.toString(),
        steps: results
      }
    };
  } catch (error: any) {
    return {
      success: false,
      error: `批量指针操作失败: ${error.message || error}`
    };
  }
} 