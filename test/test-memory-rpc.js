/**
 * 内存RPC功能测试脚本
 */

import frida from 'frida';

async function main() {
  try {
    console.log("开始测试内存RPC功能...");
    
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
    
    // 测试内存分配
    console.log("\n测试内存分配：");
    const allocResult = await api.memoryAlloc(1024);
    console.log(allocResult);
    
    if (allocResult.success) {
      const allocatedPtr = allocResult.address;
      
      // 测试内存保护
      console.log("\n测试修改内存保护属性：");
      const protectResult = await api.memoryProtect(allocatedPtr, 1024, "rwx");
      console.log(protectResult);
      
      // 测试查询内存保护
      console.log("\n测试查询内存保护属性：");
      const queryResult = await api.memoryQueryProtection(allocatedPtr);
      console.log(queryResult);
      
      // 测试分配UTF8字符串
      console.log("\n测试分配UTF8字符串：");
      const stringResult = await api.memoryAllocUtf8String("测试字符串");
      console.log(stringResult);
      
      if (stringResult.success) {
        const stringPtr = stringResult.address;
        
        // 测试内存扫描
        console.log("\n测试内存扫描：");
        try {
          // 注意：在真实场景中应提供正确的大小和模式
          const scanResult = await api.memoryScanSync(allocatedPtr, 1024, "AB CD EF");
          console.log(scanResult);
        } catch (error) {
          console.log("内存扫描失败（在测试环境中可能是正常的）:", error);
        }
        
        // 测试内存复制
        console.log("\n测试内存复制：");
        const copyResult = await api.memoryCopy(allocatedPtr, stringPtr, 16);
        console.log(copyResult);
        
        // 测试内存复制（dup）
        console.log("\n测试内存复制（dup）：");
        const dupResult = await api.memoryDup(stringPtr, 16);
        console.log(dupResult);
      }
    }
    
    console.log("\n测试完成，断开连接...");
    await session.detach();
    
  } catch (error) {
    console.error("测试过程中出错:", error);
  }
}

main()
  .then(() => console.log("测试脚本执行完毕"))
  .catch(error => console.error("脚本执行失败:", error)); 