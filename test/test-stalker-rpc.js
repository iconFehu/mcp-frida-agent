/**
 * Stalker RPC功能测试脚本
 */

import frida from 'frida';

async function main() {
  try {
    console.log("开始测试Stalker RPC功能...");
    
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
    
    // 添加消息监听器
    script.message.connect((message) => {
      if (message.type === 'send') {
        const payload = message.payload;
        if (payload.type === 'probe-triggered') {
          console.log('收到探针消息:', payload.data);
        }
      } else if (message.type === 'error') {
        console.error('脚本错误:', message.stack);
      }
    });
    
    // 获取当前线程ID
    const threadId = await api.processGetCurrentThreadId();
    console.log("\n当前线程ID:", threadId);
    
    // 设置Stalker配置
    console.log("\n设置Stalker配置：");
    const configResult = await api.stalkerSetConfig({
      trustThreshold: 0,
      queueCapacity: 32768,
      queueDrainInterval: 100
    });
    console.log(configResult);
    
    // 开始跟踪线程
    console.log("\n开始跟踪线程：");
    const followResult = await api.stalkerFollow(threadId.data.threadId, {
      events: {
        call: true,
        ret: true,
        exec: false,
        block: false,
        compile: false
      },
      // 收到事件批次时的回调
      onReceive: (events) => {
        console.log("收到事件批次，长度:", events.byteLength);
      }
    });
    console.log(followResult);
    
    if (followResult.success) {
      // 等待一段时间收集事件
      console.log("\n等待收集事件...");
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // 获取线程事件
      console.log("\n获取线程事件：");
      const eventsResult = await api.stalkerGetThreadEvents(threadId.data.threadId);
      console.log("收集到的事件数量:", eventsResult.data.events.length);
      console.log("前5个事件:", eventsResult.data.events.slice(0, 5));
      
      // 清空事件
      console.log("\n清空线程事件：");
      const clearResult = await api.stalkerClearThreadEvents(threadId.data.threadId);
      console.log(clearResult);
      
      // 添加调用探针
      console.log("\n添加调用探针：");
      
      // 添加多个常用函数地址的探针以提高触发几率
      const probeAddresses = [
        "0x40D120", // 游戏主要函数
        "0x45E600", // 可能是更频繁调用的函数
        "0x452270", // 其他可能的函数地址
        "0x4290E0"  // 再添加一个候选
      ];
      
      // 添加多个探针
      const probeResults = [];
      for (const addr of probeAddresses) {
        console.log(`添加探针到地址: ${addr}`);
        const result = await api.stalkerAddCallProbe(addr, function() {
          send({type: 'probe-triggered', data: `Probe triggered at ${addr}`});
        });
        probeResults.push({ address: addr, result });
      }
      
      // 显示所有探针添加结果
      console.log("\n探针添加结果:", probeResults.map(p => `${p.address}: ${p.result.success}`));
      
      // 所有成功添加的探针ID
      const probeIds = probeResults
        .filter(p => p.result.success)
        .map(p => p.result.data.probeId);
        
      if (probeIds.length > 0) {
        // 等待探针触发，增加到15秒
        console.log("\n等待探针触发...");
        await new Promise(resolve => setTimeout(resolve, 15000));
        
        // 移除所有探针
        console.log("\n移除探针：");
        for (const id of probeIds) {
          console.log(`移除探针 ${id}`);
          const removeResult = await api.stalkerRemoveCallProbe(id);
          console.log(removeResult);
        }
      }
      
      // 停止跟踪
      console.log("\n停止跟踪线程：");
      const unfollowResult = await api.stalkerUnfollow(threadId.data.threadId);
      console.log(unfollowResult);
    }
    
    // 执行垃圾回收
    console.log("\n执行垃圾回收：");
    const gcResult = await api.stalkerGarbageCollect();
    console.log(gcResult);
    
    console.log("\n测试完成，断开连接...");
    await session.detach();
    
  } catch (error) {
    console.error("测试过程中出错:", error);
  }
}

main()
  .then(() => console.log("测试脚本执行完毕"))
  .catch(error => console.error("脚本执行失败:", error)); 