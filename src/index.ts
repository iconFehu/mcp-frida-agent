/**
 * MCP-Frida-Agent 主入口
 * 提供高级内存分析和指针操作能力
 */

import * as MemoryRPC from './core/memory-rpc.js';
import * as ProcessRPC from './core/process-rpc.js';
import * as SocketRPC from './core/socket-rpc.js';
import * as StalkerRPC from './core/stalker-rpc.js';
import * as NativePointerRPC from './core/nativepointer-rpc.js';

// 导入Kernel API函数
import {
  getInfo as kernelGetInfo,
  enumerateModules as kernelEnumerateModules,
  enumerateRanges as kernelEnumerateRanges,
  enumerateModuleRanges as kernelEnumerateModuleRanges,
  alloc as kernelAlloc,
  protect as kernelProtect,
  scan as kernelScan,
  scanSync as kernelScanSync,
  readS8 as kernelReadS8,
  readU8 as kernelReadU8,
  readS16 as kernelReadS16,
  readU16 as kernelReadU16,
  readS32 as kernelReadS32,
  readU32 as kernelReadU32,
  readFloat as kernelReadFloat,
  readDouble as kernelReadDouble,
  readByteArray as kernelReadByteArray,
  readCString as kernelReadCString,
  readUtf8String as kernelReadUtf8String,
  readUtf16String as kernelReadUtf16String,
  writeS8 as kernelWriteS8,
  writeU8 as kernelWriteU8,
  writeS16 as kernelWriteS16,
  writeU16 as kernelWriteU16,
  writeS32 as kernelWriteS32,
  writeU32 as kernelWriteU32,
  writeFloat as kernelWriteFloat,
  writeDouble as kernelWriteDouble,
  writeByteArray as kernelWriteByteArray,
  writeUtf8String as kernelWriteUtf8String,
  writeUtf16String as kernelWriteUtf16String
} from './core/kernel-rpc.js';

import {
  attach as interceptorAttach,
  detach as interceptorDetach,
  detachAll as interceptorDetachAll,
  replace as interceptorReplace,
  revert as interceptorRevert,
  flush as interceptorFlush,
  getBreakpointKind as interceptorGetBreakpointKind,
  setBreakpointKind as interceptorSetBreakpointKind
} from './core/interceptor-rpc.js';

// 声明全局变量以避免TypeScript错误
declare const rpc: {
  exports: Record<string, any>;
};

// 导出RPC函数
rpc.exports = {
  // NativePointer操作
  nativePointerCreate: NativePointerRPC.create,
  nativePointerIsNull: NativePointerRPC.isNull,
  nativePointerOperate: NativePointerRPC.operate,
  nativePointerAdd: NativePointerRPC.add,
  nativePointerSub: NativePointerRPC.sub,
  nativePointerAnd: NativePointerRPC.and,
  nativePointerOr: NativePointerRPC.or,
  nativePointerXor: NativePointerRPC.xor,
  nativePointerShl: NativePointerRPC.shl,
  nativePointerShr: NativePointerRPC.shr,
  nativePointerNot: NativePointerRPC.not,
  nativePointerSign: NativePointerRPC.sign, 
  nativePointerStrip: NativePointerRPC.strip,
  nativePointerBlend: NativePointerRPC.blend,
  nativePointerCompare: NativePointerRPC.compare,
  nativePointerEquals: NativePointerRPC.equals,
  nativePointerToInt32: NativePointerRPC.toInt32,
  nativePointerToUInt32: NativePointerRPC.toUInt32,
  nativePointerToString: NativePointerRPC.toString,
  nativePointerToMatchPattern: NativePointerRPC.toMatchPattern,
  
  // 内存读取操作
  nativePointerReadPointer: NativePointerRPC.readPointer,
  nativePointerReadS8: NativePointerRPC.readS8,
  nativePointerReadU8: NativePointerRPC.readU8,
  nativePointerReadS16: NativePointerRPC.readS16,
  nativePointerReadU16: NativePointerRPC.readU16,
  nativePointerReadS32: NativePointerRPC.readS32,
  nativePointerReadU32: NativePointerRPC.readU32,
  nativePointerReadS64: NativePointerRPC.readS64,
  nativePointerReadU64: NativePointerRPC.readU64,
  nativePointerReadShort: NativePointerRPC.readShort,
  nativePointerReadUShort: NativePointerRPC.readUShort,
  nativePointerReadInt: NativePointerRPC.readInt,
  nativePointerReadUInt: NativePointerRPC.readUInt,
  nativePointerReadLong: NativePointerRPC.readLong,
  nativePointerReadULong: NativePointerRPC.readULong,
  nativePointerReadFloat: NativePointerRPC.readFloat,
  nativePointerReadDouble: NativePointerRPC.readDouble,
  nativePointerReadByteArray: NativePointerRPC.readByteArray,
  nativePointerReadCString: NativePointerRPC.readCString,
  nativePointerReadUtf8String: NativePointerRPC.readUtf8String,
  nativePointerReadUtf16String: NativePointerRPC.readUtf16String,
  nativePointerReadAnsiString: NativePointerRPC.readAnsiString,
  
  // 内存写入操作
  nativePointerWritePointer: NativePointerRPC.writePointer,
  nativePointerWriteS8: NativePointerRPC.writeS8,
  nativePointerWriteU8: NativePointerRPC.writeU8,
  nativePointerWriteS16: NativePointerRPC.writeS16,
  nativePointerWriteU16: NativePointerRPC.writeU16,
  nativePointerWriteS32: NativePointerRPC.writeS32,
  nativePointerWriteU32: NativePointerRPC.writeU32,
  nativePointerWriteS64: NativePointerRPC.writeS64,
  nativePointerWriteU64: NativePointerRPC.writeU64,
  nativePointerWriteShort: NativePointerRPC.writeShort,
  nativePointerWriteUShort: NativePointerRPC.writeUShort,
  nativePointerWriteInt: NativePointerRPC.writeInt,
  nativePointerWriteUInt: NativePointerRPC.writeUInt,
  nativePointerWriteLong: NativePointerRPC.writeLong,
  nativePointerWriteULong: NativePointerRPC.writeULong,
  nativePointerWriteFloat: NativePointerRPC.writeFloat,
  nativePointerWriteDouble: NativePointerRPC.writeDouble,
  nativePointerWriteByteArray: NativePointerRPC.writeByteArray,
  nativePointerWriteUtf8String: NativePointerRPC.writeUtf8String,
  nativePointerWriteUtf16String: NativePointerRPC.writeUtf16String,
  nativePointerWriteAnsiString: NativePointerRPC.writeAnsiString,
  
  // 批量操作
  nativePointerBatchOperate: NativePointerRPC.batchOperate,
  
  // 内存操作API
  memoryScan: MemoryRPC.scan,
  memoryScanSync: MemoryRPC.scanSync,
  memoryAlloc: MemoryRPC.alloc,
  memoryAllocUtf8String: MemoryRPC.allocUtf8String,
  memoryAllocUtf16String: MemoryRPC.allocUtf16String,
  memoryAllocAnsiString: MemoryRPC.allocAnsiString,
  memoryCopy: MemoryRPC.copy,
  memoryDup: MemoryRPC.dup,
  memoryProtect: MemoryRPC.protect,
  memoryQueryProtection: MemoryRPC.queryProtection,
  memoryPatchCode: MemoryRPC.patchCode,
  
  // 进程操作API
  processGetInfo: ProcessRPC.getProcessInfo,
  processGetDirs: ProcessRPC.getProcessDirs,
  processIsDebuggerAttached: ProcessRPC.isDebuggerAttached,
  processGetCurrentThreadId: ProcessRPC.getCurrentThreadId,
  processEnumerateThreads: ProcessRPC.enumerateThreads,
  processFindModuleByAddress: ProcessRPC.findModuleByAddress,
  processFindModuleByName: ProcessRPC.findModuleByName,
  processEnumerateModules: ProcessRPC.enumerateModules,
  processFindRangeByAddress: ProcessRPC.findRangeByAddress,
  processEnumerateRanges: ProcessRPC.enumerateRanges,
  processEnumerateMallocRanges: ProcessRPC.enumerateMallocRanges,
  
  // Socket操作API
  socketListen: SocketRPC.listen,
  socketConnect: SocketRPC.connect,
  socketGetType: SocketRPC.getSocketType,
  socketGetLocalAddress: SocketRPC.getLocalAddress,
  socketGetPeerAddress: SocketRPC.getPeerAddress,
  socketCloseConnection: SocketRPC.closeConnection,
  socketCloseListener: SocketRPC.closeListener,
  socketSend: SocketRPC.send,
  socketReceive: SocketRPC.receive,
  
  // Stalker操作API
  stalkerFollow: StalkerRPC.follow,
  stalkerUnfollow: StalkerRPC.unfollow,
  stalkerExclude: StalkerRPC.exclude,
  stalkerParse: StalkerRPC.parse,
  stalkerFlush: StalkerRPC.flush,
  stalkerGarbageCollect: StalkerRPC.garbageCollect,
  stalkerInvalidate: StalkerRPC.invalidate,
  stalkerAddCallProbe: StalkerRPC.addCallProbe,
  stalkerRemoveCallProbe: StalkerRPC.removeCallProbe,
  stalkerGetThreadEvents: StalkerRPC.getThreadEvents,
  stalkerClearThreadEvents: StalkerRPC.clearThreadEvents,
  stalkerSetConfig: StalkerRPC.setConfig,
  stalkerGetConfig: StalkerRPC.getConfig,

  // Kernel API 导出
  kernelGetInfo,
  kernelEnumerateModules,
  kernelEnumerateRanges,
  kernelEnumerateModuleRanges,
  kernelAlloc,
  kernelProtect,
  kernelScan,
  kernelScanSync,
  kernelReadS8,
  kernelReadU8,
  kernelReadS16,
  kernelReadU16,
  kernelReadS32,
  kernelReadU32,
  kernelReadFloat,
  kernelReadDouble,
  kernelReadByteArray,
  kernelReadCString,
  kernelReadUtf8String,
  kernelReadUtf16String,
  kernelWriteS8,
  kernelWriteU8,
  kernelWriteS16,
  kernelWriteU16,
  kernelWriteS32,
  kernelWriteU32,
  kernelWriteFloat,
  kernelWriteDouble,
  kernelWriteByteArray,
  kernelWriteUtf8String,
  kernelWriteUtf16String,

  // Interceptor API
  interceptorAttach,
  interceptorDetach,
  interceptorDetachAll,
  interceptorReplace,
  interceptorRevert,
  interceptorFlush,
  interceptorGetBreakpointKind,
  interceptorSetBreakpointKind,
};

console.log("[MCP-Frida-Agent] 代理已加载，提供指针操作、内存管理、进程操作、网络通信和执行跟踪RPC能力");
