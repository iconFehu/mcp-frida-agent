const frida = await import('frida');
const { expect } = await import('chai');

describe('Interceptor RPC API Tests', () => {
  let session;
  let script;
  let api;
  let targetProcess;
  let targetFunction;
  
  before(async () => {
    // 附加到notepad进程作为测试目标
    targetProcess = await frida.spawn('PlantsVsZombies.exe');
    session = await frida.attach(targetProcess);
    
    // 加载脚本
    const fs = await import('fs');
    const source = fs.readFileSync('./dist/index.js', 'utf8');
    script = await session.createScript(source);
    await script.load();
    api = script.exports;
    
    // 获取一个测试函数地址
    const modules = await session.enumerateModules();
    const notepadModule = modules.find(m => m.name.toLowerCase() === 'PlantsVsZombies.exe');
    targetFunction = notepadModule.base.add(0x1000).toString(); // 示例偏移
  });
  
  after(async () => {
    if (script) {
      await script.unload();
    }
    if (session) {
      await session.detach();
    }
    await frida.kill(targetProcess);
  });
  
  describe('基本功能测试', () => {
    let listenerId;
    
    it('应该能够附加拦截器', async () => {
      const result = await api.interceptorAttach(targetFunction, {
        onEnter: true,
        onLeave: true,
        collectContext: true,
        argCount: 4,
        collectReturnValue: true
      });
      
      expect(result.success).to.be.true;
      expect(result.data.id).to.be.a('string');
      listenerId = result.data.id;
    });
    
    it('应该能够接收拦截事件', (done) => {
      let enterCount = 0;
      let leaveCount = 0;
      
      script.message.connect((message) => {
        if (message.type === 'send') {
          const event = message.payload;
          
          if (event.type === 'Enter') {
            enterCount++;
            expect(event.context).to.have.property('returnAddress');
            expect(event.context).to.have.property('threadId');
            expect(event.context).to.have.property('depth');
            expect(event.context.args).to.be.an('array');
          }
          
          if (event.type === 'Leave') {
            leaveCount++;
            expect(event.context).to.have.property('returnValue');
          }
          
          if (enterCount > 0 && leaveCount > 0) {
            done();
          }
        }
      });
      
      // 触发目标函数
      // 注意：在实际测试中需要一个可靠的方式来触发目标函数
    });
    
    it('应该能够分离拦截器', async () => {
      const result = await api.interceptorDetach(listenerId);
      expect(result.success).to.be.true;
    });
    
    it('应该能够分离所有拦截器', async () => {
      const result = await api.interceptorDetachAll();
      expect(result.success).to.be.true;
    });
  });
  
  describe('函数替换测试', () => {
    const replacementCode = `
      var replacement = Memory.alloc(Process.pageSize);
      Memory.patchCode(replacement, Process.pageSize, code => {
        var cw = new X86Writer(code);
        cw.putRet();
        cw.flush();
      });
      send(replacement.toString());
    `;
    
    let replacementAddress;
    
    before(async () => {
      const tempScript = await session.createScript(replacementCode);
      await tempScript.load();
      
      await new Promise(resolve => {
        tempScript.message.connect((message) => {
          if (message.type === 'send') {
            replacementAddress = message.payload;
            resolve();
          }
        });
      });
      
      await tempScript.unload();
    });
    
    it('应该能够替换函数', async () => {
      const result = await api.interceptorReplace(targetFunction, replacementAddress, {
        mode: 'Normal',
        saveOriginal: true
      });
      
      expect(result.success).to.be.true;
    });
    
    it('应该能够快速替换函数', async () => {
      const result = await api.interceptorReplace(targetFunction, replacementAddress, {
        mode: 'Fast',
        saveOriginal: true
      });
      
      expect(result.success).to.be.true;
      expect(result.data).to.have.property('originalAddress');
    });
    
    it('应该能够恢复替换的函数', async () => {
      const result = await api.interceptorRevert(targetFunction);
      expect(result.success).to.be.true;
    });
    
    it('应该能够刷新内存变更', async () => {
      const result = await api.interceptorFlush();
      expect(result.success).to.be.true;
    });
  });
  
  describe('断点类型测试', () => {
    it('应该能够获取断点类型', async () => {
      const result = await api.interceptorGetBreakpointKind();
      
      if (result.success) {
        expect(result.data).to.have.property('kind');
        expect(['soft', 'hard']).to.include(result.data.kind);
      } else {
        expect(result.error).to.equal('断点类型只在裸机后端可用');
      }
    });
    
    it('应该能够设置断点类型', async () => {
      const result = await api.interceptorSetBreakpointKind('soft');
      
      if (result.success) {
        expect(result.success).to.be.true;
      } else {
        expect(result.error).to.equal('断点类型只在裸机后端可用');
      }
    });
  });
}); 