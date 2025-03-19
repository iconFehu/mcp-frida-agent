/**
 * 进程RPC功能测试脚本
 */

import frida from 'frida';

async function main() {
  try {
    console.log("开始测试进程RPC功能...");
    
    // 附加到一个进程（这里以Windows计算器为例）
    console.log("尝试附加到计算器进程...");
    const session = await frida.attach("PlantsVsZombies.exe");
    console.log("成功附加到计算器进程");
    
    // 创建脚本
    console.log("加载Agent脚本...");
    const fs = await import('fs');
    const script = await session.createScript(fs.readFileSync('./dist/_agent.js', 'utf8'));
    
    // 加载脚本
    await script.load();
    const api = script.exports;
    
    // 测试获取进程信息
    console.log("\n测试获取进程信息：");
    const infoResult = await api.processGetInfo();
    console.log(infoResult);
    
    // 测试获取进程目录
    console.log("\n测试获取进程目录：");
    const dirsResult = await api.processGetDirs();
    console.log(dirsResult);
    
    // 测试获取调试器状态
    console.log("\n测试获取调试器状态：");
    const debuggerResult = await api.processIsDebuggerAttached();
    console.log(debuggerResult);
    
    // 测试获取当前线程ID
    console.log("\n测试获取当前线程ID：");
    const threadIdResult = await api.processGetCurrentThreadId();
    console.log(threadIdResult);
    
    // 测试枚举线程
    console.log("\n测试枚举线程：");
    const threadsResult = await api.processEnumerateThreads();
    console.log(threadsResult);
    
    // 测试枚举模块
    console.log("\n测试枚举模块：");
    const modulesResult = await api.processEnumerateModules();
    console.log(modulesResult);
    
    if (modulesResult.success && modulesResult.data.length > 0) {
      const firstModule = modulesResult.data[0];
      
      // 测试通过名称查找模块
      console.log("\n测试通过名称查找模块：");
      const moduleByNameResult = await api.processFindModuleByName(firstModule.name);
      console.log(moduleByNameResult);
      
      // 测试通过地址查找模块
      console.log("\n测试通过地址查找模块：");
      const moduleByAddrResult = await api.processFindModuleByAddress(firstModule.base);
      console.log(moduleByAddrResult);
      
      // 测试通过地址查找内存范围
      console.log("\n测试通过地址查找内存范围：");
      const rangeByAddrResult = await api.processFindRangeByAddress(firstModule.base);
      console.log(rangeByAddrResult);
    }
    
    // 测试枚举内存范围
    console.log("\n测试枚举内存范围：");
    const rangesResult = await api.processEnumerateRanges("r--");
    console.log(rangesResult);
    
    // 测试枚举堆内存范围
    console.log("\n测试枚举堆内存范围：");
    const mallocRangesResult = await api.processEnumerateMallocRanges();
    console.log(mallocRangesResult);
    
    console.log("\n测试完成，断开连接...");
    await session.detach();
    
  } catch (error) {
    console.error("测试过程中出错:", error);
  }
}

main()
  .then(() => console.log("测试脚本执行完毕"))
  .catch(error => console.error("脚本执行失败:", error)); 