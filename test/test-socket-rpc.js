/**
 * Socket RPC功能测试脚本
 */

import frida from 'frida';

async function main() {
  try {
    console.log("开始测试Socket RPC功能...");
    
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
    
    // 测试创建TCP监听器
    console.log("\n测试创建TCP监听器：");
    const listenerResult = await api.socketListen({
      type: 'tcp',
      port: 8888
    });
    console.log(listenerResult);
    
    if (listenerResult.success) {
      const listenerId = listenerResult.data.id;
      
      // 测试TCP连接
      console.log("\n测试TCP连接：");
      const connectResult = await api.socketConnect({
        type: 'tcp',
        host: '127.0.0.1',
        port: 8888
      });
      console.log(connectResult);
      
      if (connectResult.success) {
        const connectionId = connectResult.data.id;
        
        // 测试发送数据
        console.log("\n测试发送数据：");
        const sendResult = await api.socketSend(connectionId, "Hello World!");
        console.log(sendResult);
        
        // 测试接收数据
        console.log("\n测试接收数据：");
        const receiveResult = await api.socketReceive(connectionId, 12);
        console.log(receiveResult);
        
        // 测试获取连接信息
        console.log("\n测试获取连接信息：");
        const localAddrResult = await api.socketGetLocalAddress(connectionId);
        console.log("本地地址:", localAddrResult);
        
        const peerAddrResult = await api.socketGetPeerAddress(connectionId);
        console.log("对端地址:", peerAddrResult);
        
        const typeResult = await api.socketGetType(connectionId);
        console.log("Socket类型:", typeResult);
        
        // 关闭连接
        console.log("\n测试关闭连接：");
        const closeConnResult = await api.socketCloseConnection(connectionId);
        console.log(closeConnResult);
      }
      
      // 关闭监听器
      console.log("\n测试关闭监听器：");
      const closeListenerResult = await api.socketCloseListener(listenerId);
      console.log(closeListenerResult);
    }
    
    // 测试Unix域套接字
    if (process.platform !== 'win32') {
      console.log("\n测试Unix域套接字：");
      
      const unixListenerResult = await api.socketListen({
        type: 'unix',
        path: '/tmp/test.sock'
      });
      console.log(unixListenerResult);
      
      if (unixListenerResult.success) {
        const unixListenerId = unixListenerResult.data.id;
        
        const unixConnectResult = await api.socketConnect({
          type: 'unix',
          path: '/tmp/test.sock'
        });
        console.log(unixConnectResult);
        
        if (unixConnectResult.success) {
          const unixConnectionId = unixConnectResult.data.id;
          
          // 关闭Unix连接
          await api.socketCloseConnection(unixConnectionId);
        }
        
        // 关闭Unix监听器
        await api.socketCloseListener(unixListenerId);
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