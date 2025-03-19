const frida = require('frida');
const { expect } = require('chai');

describe('Kernel API Tests', function() {
  let session;
  let script;
  
  // 在所有测试前设置环境
  before(async function() {
    // 连接到目标进程
    const target = await frida.spawn('PlantsVsZombies.exe');
    session = await frida.attach(target);
    
    // 加载脚本
    const fs = await import('fs');
    const source = fs.readFileSync('./dist/index.js', 'utf8');
    script = await session.createScript(source);
    await script.load();
  });
  
  // 在所有测试后清理环境
  after(async function() {
    await script.unload();
    await session.detach();
  });
  
  // 测试内核API可用性
  it('should check kernel API availability', async function() {
    const result = await script.exports.kernelGetInfo();
    expect(result).to.have.property('success');
    if (result.success) {
      expect(result.data).to.have.property('available');
      expect(result.data).to.have.property('base');
      expect(result.data).to.have.property('pageSize');
    }
  });
  
  // 测试枚举内核模块
  it('should enumerate kernel modules', async function() {
    const result = await script.exports.kernelEnumerateModules();
    expect(result).to.have.property('success');
    if (result.success) {
      expect(result.data).to.have.property('modules');
      expect(result.data.modules).to.be.an('array');
      if (result.data.modules.length > 0) {
        const module = result.data.modules[0];
        expect(module).to.have.property('name');
        expect(module).to.have.property('base');
        expect(module).to.have.property('size');
      }
    }
  });
  
  // 测试枚举内存范围
  it('should enumerate memory ranges', async function() {
    const result = await script.exports.kernelEnumerateRanges('r-x');
    expect(result).to.have.property('success');
    if (result.success) {
      expect(result.data).to.have.property('ranges');
      expect(result.data.ranges).to.be.an('array');
      if (result.data.ranges.length > 0) {
        const range = result.data.ranges[0];
        expect(range).to.have.property('base');
        expect(range).to.have.property('size');
        expect(range).to.have.property('protection');
      }
    }
  });
  
  // 测试内存分配和保护
  it('should allocate and protect kernel memory', async function() {
    // 分配内存
    const allocResult = await script.exports.kernelAlloc(0x1000);
    expect(allocResult).to.have.property('success');
    if (allocResult.success) {
      expect(allocResult.data).to.have.property('address');
      
      // 修改内存保护
      const protectResult = await script.exports.kernelProtect(
        allocResult.data.address,
        0x1000,
        'rw-'
      );
      expect(protectResult).to.have.property('success');
    }
  });
  
  // 测试内存读写
  it('should read and write kernel memory', async function() {
    // 分配内存
    const allocResult = await script.exports.kernelAlloc(0x1000);
    if (!allocResult.success) {
      this.skip();
      return;
    }
    
    const address = allocResult.data.address;
    
    // 写入测试数据
    const testValue = 42;
    const writeResult = await script.exports.kernelWriteU32(address, testValue);
    expect(writeResult).to.have.property('success', true);
    
    // 读取并验证数据
    const readResult = await script.exports.kernelReadU32(address);
    expect(readResult).to.have.property('success', true);
    if (readResult.success) {
      expect(readResult.data.value).to.equal(testValue);
    }
  });
  
  // 测试内存扫描
  it('should scan kernel memory', async function() {
    // 分配内存并写入测试数据
    const allocResult = await script.exports.kernelAlloc(0x1000);
    if (!allocResult.success) {
      this.skip();
      return;
    }
    
    const address = allocResult.data.address;
    const testPattern = '2A 00 00 00'; // 42的十六进制表示
    
    // 写入测试数据
    await script.exports.kernelWriteU32(address, 42);
    
    // 执行同步扫描
    const scanResult = await script.exports.kernelScanSync(address, 0x1000, testPattern);
    expect(scanResult).to.have.property('success', true);
    if (scanResult.success) {
      expect(scanResult.data.matches).to.be.an('array');
      expect(scanResult.data.matches.length).to.be.greaterThan(0);
    }
  });
  
  // 测试字符串操作
  it('should handle string operations', async function() {
    // 分配内存
    const allocResult = await script.exports.kernelAlloc(0x1000);
    if (!allocResult.success) {
      this.skip();
      return;
    }
    
    const address = allocResult.data.address;
    const testString = 'Hello, Kernel!';
    
    // 写入UTF-8字符串
    const writeResult = await script.exports.kernelWriteUtf8String(address, testString);
    expect(writeResult).to.have.property('success', true);
    
    // 读取并验证UTF-8字符串
    const readResult = await script.exports.kernelReadUtf8String(address, testString.length);
    expect(readResult).to.have.property('success', true);
    if (readResult.success) {
      expect(readResult.data.value).to.equal(testString);
    }
  });
}); 