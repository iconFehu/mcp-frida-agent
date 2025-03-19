/**
 * NativePointer RPC API 测试 - ESM版本
 */

import { expect } from 'chai';
import * as frida from 'frida';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe('NativePointer RPC API Tests', function() {
  this.timeout(10000); // 增加超时时间为10秒
  
  let session;
  let script;
  let api;
  let targetProcess;
  let testAddress;
  let allocatedAddress;
  
  before(async function() {
    console.log('正在初始化测试环境...');
    
    try {
      // 附加到notepad进程作为测试目标
    //   console.log('启动notepad进程...');
    //   targetProcess = await frida.spawn('Notepad.exe');
      console.log('附加到notepad进程...');
      session = await frida.attach('Notepad.exe');
      
      // 加载测试脚本
      const source = await fs.promises.readFile(
        path.join(__dirname, '../dist/_agent.js'),
        'utf8'
      );
      
      console.log('创建脚本...');
      script = await session.createScript(source);
      await script.load();
      api = script.exports;
      console.log('脚本加载完成');
      
      // 分配一个测试内存区域
      console.log('分配测试内存...');
      const allocResult = await api.memoryAlloc(1024);
      expect(allocResult.success).to.be.true;
      console.log(allocResult);
      allocatedAddress = allocResult.address;
      
      // 创建一个指针指向分配的内存
      testAddress = allocatedAddress;
      console.log(`测试地址: ${testAddress}`);
    } catch (error) {
      console.error('初始化测试环境失败:', error);
      throw error;
    }
  });
  
  after(async function() {
    console.log('清理测试环境...');
    if (script) {
      await script.unload();
    }
    if (session) {
      await session.detach();
    }
    if (targetProcess) {
      await frida.kill(targetProcess);
    }
  });
  
  describe('基本指针操作测试', function() {
    it('应该能够创建指针', async function() {
      const result = await api.nativePointerCreate(testAddress);
      expect(result.success).to.be.true;
      expect(result.data.address).to.equal(testAddress);
    });
    
    it('应该能够检查指针是否为null', async function() {
      const result = await api.nativePointerIsNull(testAddress);
      expect(result.success).to.be.true;
      expect(result.data.isNull).to.be.false;
      
      const nullResult = await api.nativePointerIsNull('0x0');
      expect(nullResult.success).to.be.true;
      expect(nullResult.data.isNull).to.be.true;
    });
    
    it('应该能够正确执行指针加法', async function() {
      const result = await api.nativePointerAdd(testAddress, 8);
      expect(result.success).to.be.true;
      
      const address = parseInt(testAddress, 16);
      const expected = '0x' + (address + 8).toString(16);
      expect(result.data.address.toLowerCase()).to.equal(expected.toLowerCase());
    });
  });
  
  describe('内存读写测试', function() {
    it('应该能够写入并读取U8值', async function() {
      const value = 123;
      const address = parseInt(allocatedAddress, 16) + 100;
      
      // 写
      const writeResult = await api.nativePointerWriteU8(address, value);
      expect(writeResult.success).to.be.true;
      
      // 读
      const readResult = await api.nativePointerReadU8(address);
      expect(readResult.success).to.be.true;
      expect(readResult.data.value).to.equal(value);
    });
    
    it('应该能够写入并读取字符串', async function() {
      const value = 'Hello, Frida!';
      const address = parseInt(allocatedAddress, 16) + 300;
      
      // 写UTF8
      const writeResult = await api.nativePointerWriteUtf8String(address, value);
      console.log(writeResult);
      expect(writeResult.success).to.be.true;
      
      // 读UTF8
      const readResult = await api.nativePointerReadUtf8String(address, value.length);
      console.log(readResult);
      expect(readResult.success).to.be.true;
      expect(readResult.data.value).to.equal(value);
    });
  });
}); 