/**
 * 指针RPC功能测试脚本
 */

import frida from 'frida';

async function main() {
  try {
    console.log("开始测试指针RPC功能...");
    
    // 附加到一个进程（这里以Windows计算器为例）
    console.log("尝试附加到计算器进程...");
    const session = await frida.attach("CalculatorApp.exe");
    console.log("成功附加到计算器进程");
    
    // 创建脚本
    console.log("加载Agent脚本...");
    const fs = await import('fs');
    const script = await session.createScript(fs.readFileSync('./dist/_agent.js', 'utf8'));
    
    // 加载脚本
    await script.load();
    const api = script.exports;
    
    // 测试创建指针
    console.log("\n测试创建指针：");
    const result = await api.createPointer("0x1000");
    console.log(result);
    
    if (result.success) {
      const pointerStr = result.pointer;
      
      // 测试指针加法
      console.log("\n测试指针加法：");
      const addResult = await api.pointerAdd(pointerStr, 16);
      console.log(addResult);
      
      // 测试读取内存
      console.log("\n测试读取内存：");
      try {
        const readResult = await api.pointerReadU32(pointerStr);
        console.log(readResult);
      } catch (error) {
        console.log("读取内存失败（这在测试环境中是正常的）:", error);
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
