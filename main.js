const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

let mainWindow;
let fridaProcess = null;
let adbProcess = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false
    },
    show: false, // 초기에 숨김
    autoHideMenuBar: true, // 메뉴바 자동 숨김
    titleBarStyle: 'default',
    title: 'MCOSpy Frida Manager'
  });

  // 메뉴 완전 제거
  mainWindow.setMenuBarVisibility(false);

  mainWindow.loadFile('index.html');

  // 창이 준비되면 표시
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  // 개발 모드에서만 DevTools 열기
  if (process.argv.includes('--dev')) {
    mainWindow.webContents.openDevTools();
  }
}

app.whenReady().then(() => {
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  // macOS가 아닌 경우 앱 종료
  if (process.platform !== 'darwin') {
    // 모든 프로세스 종료
    if (fridaProcess) {
      fridaProcess.kill();
    }
    if (adbProcess) {
      adbProcess.kill();
    }
    app.quit();
  }
});

// ADB 연결 상태 확인
ipcMain.handle('check-adb-connection', async () => {
  return new Promise((resolve) => {
    const adb = spawn('adb', ['devices']);
    let output = '';
    
    adb.stdout.on('data', (data) => {
      output += data.toString();
    });

    adb.on('close', (code) => {
      const devices = output.split('\n').filter(line => 
        line.includes('\tdevice') && !line.includes('List of devices')
      );
      resolve({
        connected: devices.length > 0,
        devices: devices.map(line => line.split('\t')[0])
      });
    });

    adb.on('error', (error) => {
      resolve({ connected: false, error: error.message });
    });
  });
});

// BlueStacks ADB 연결
ipcMain.handle('connect-bluestacks', async (event, address) => {
  const adbAddress = address || '127.0.0.1:5555';
  
  return new Promise((resolve) => {
    const adb = spawn('adb', ['connect', adbAddress]);
    let output = '';
    let error = '';

    adb.stdout.on('data', (data) => {
      output += data.toString();
    });

    adb.stderr.on('data', (data) => {
      error += data.toString();
    });

    adb.on('close', (code) => {
      resolve({
        success: code === 0,
        output: output,
        error: error,
        address: adbAddress
      });
    });

    adb.on('error', (error) => {
      resolve({ success: false, error: error.message, address: adbAddress });
    });
  });
});

// Frida 서버 상태 확인
ipcMain.handle('check-frida-server', async () => {
  return new Promise((resolve) => {
    const adb = spawn('adb', ['shell', 'ps | grep frida-server']);
    let output = '';

    adb.stdout.on('data', (data) => {
      output += data.toString();
    });

    adb.on('close', (code) => {
      resolve({
        running: output.includes('frida-server'),
        output: output
      });
    });

    adb.on('error', (error) => {
      resolve({ running: false, error: error.message });
    });
  });
});

// Frida 서버 시작
ipcMain.handle('start-frida-server', async () => {
  return new Promise((resolve) => {
    // 먼저 frida-server가 이미 실행중인지 확인
    const checkProcess = spawn('adb', ['shell', 'ps | grep frida-server']);
    let checkOutput = '';

    checkProcess.stdout.on('data', (data) => {
      checkOutput += data.toString();
    });

    checkProcess.on('close', (code) => {
      if (checkOutput.includes('frida-server')) {
        resolve({ success: true, message: 'Frida server is already running' });
        return;
      }

      // Frida 서버 시작 - 수정된 명령어
      const fridaCmd = spawn('adb', ['shell', 'su -c "cd /data/local/tmp && ./frida-server &"']);
      let output = '';
      let error = '';

      fridaCmd.stdout.on('data', (data) => {
        output += data.toString();
      });

      fridaCmd.stderr.on('data', (data) => {
        error += data.toString();
      });

      fridaCmd.on('close', (code) => {
        // 짧은 대기 후 다시 확인
        setTimeout(() => {
          const verifyProcess = spawn('adb', ['shell', 'ps | grep frida-server']);
          let verifyOutput = '';

          verifyProcess.stdout.on('data', (data) => {
            verifyOutput += data.toString();
          });

          verifyProcess.on('close', () => {
            resolve({
              success: verifyOutput.includes('frida-server'),
              output: output,
              error: error,
              verification: verifyOutput,
              command: 'su -c "cd /data/local/tmp && ./frida-server &"'
            });
          });
        }, 2000);
      });

      fridaCmd.on('error', (error) => {
        resolve({ success: false, error: error.message });
      });
    });
  });
});

// Frida 서버 권한 확인
ipcMain.handle('check-frida-permissions', async () => {
  return new Promise((resolve) => {
    const adb = spawn('adb', ['shell', 'ls -la /data/local/tmp/frida-server']);
    let output = '';
    let error = '';

    adb.stdout.on('data', (data) => {
      output += data.toString();
    });

    adb.stderr.on('data', (data) => {
      error += data.toString();
    });

    adb.on('close', (code) => {
      resolve({
        success: code === 0,
        output: output,
        error: error,
        hasExecutePermission: output.includes('rwx') || output.includes('r-x')
      });
    });

    adb.on('error', (error) => {
      resolve({ success: false, error: error.message });
    });
  });
});

// Frida 서버 업로드
ipcMain.handle('upload-frida-server', async () => {
  return new Promise(async (resolve) => {
    try {
      // 파일 선택 대화상자 표시
      const result = await dialog.showOpenDialog(mainWindow, {
        title: 'Frida 서버 파일 선택',
        filters: [
          { name: 'Frida Server', extensions: ['*'] },
          { name: '모든 파일', extensions: ['*'] }
        ],
        properties: ['openFile']
      });

      // 사용자가 취소했을 경우
      if (result.canceled || result.filePaths.length === 0) {
        resolve({ 
          success: false, 
          error: '파일 선택이 취소되었습니다.' 
        });
        return;
      }

      const selectedFilePath = result.filePaths[0];
      const fileName = path.basename(selectedFilePath);
      
      // 선택된 파일을 ADB로 업로드
      const adb = spawn('adb', ['push', selectedFilePath, '/data/local/tmp/frida-server']);
      let output = '';
      let error = '';

      adb.stdout.on('data', (data) => {
        output += data.toString();
      });

      adb.stderr.on('data', (data) => {
        error += data.toString();
      });

      adb.on('close', (code) => {
        if (code === 0) {
          // 업로드 성공 시 실행 권한 부여
          const chmod = spawn('adb', ['shell', 'chmod', '755', '/data/local/tmp/frida-server']);
          let chmodOutput = '';
          let chmodError = '';

          chmod.stdout.on('data', (data) => {
            chmodOutput += data.toString();
          });

          chmod.stderr.on('data', (data) => {
            chmodError += data.toString();
          });

          chmod.on('close', (chmodCode) => {
            resolve({
              success: chmodCode === 0,
              output: `파일 업로드 성공!\n원본 파일: ${selectedFilePath}\n업로드 경로: /data/local/tmp/frida-server\n\n${output}\n권한 설정: ${chmodOutput}`,
              error: chmodError,
              uploadPath: '/data/local/tmp/frida-server',
              originalFile: selectedFilePath
            });
          });

          chmod.on('error', (error) => {
            resolve({ 
              success: false, 
              error: `권한 설정 실패: ${error.message}`,
              output: output
            });
          });
        } else {
          resolve({
            success: false,
            output: output,
            error: error || '파일 업로드에 실패했습니다.'
          });
        }
      });

      adb.on('error', (error) => {
        resolve({ success: false, error: `ADB 오류: ${error.message}` });
      });

    } catch (error) {
      resolve({ success: false, error: `파일 선택 오류: ${error.message}` });
    }
  });
});

// 앱 실행 (Frida 스크립트 포함)
ipcMain.handle('run-app-with-frida', async (event, scriptPath) => {
  return new Promise((resolve) => {
    // 기존 frida 프로세스가 있다면 종료
    if (fridaProcess) {
      fridaProcess.kill();
    }

    // 단순하게 bypass.js 사용
    const scriptName = 'bypass.js';
    
    console.log(`Starting Frida with: frida -Uf com.gameparadiso.milkchoco -l ${scriptName}`);
    
    const fridaCmd = spawn('frida', [
      '-Uf', 
      'com.gameparadiso.milkchoco', 
      '-l', 
      scriptName
    ], {
      cwd: __dirname,
      shell: true
    });

    let output = '';
    let error = '';

    fridaCmd.stdout.on('data', (data) => {
      const message = data.toString();
      output += message;
      console.log(`Frida stdout: ${message}`);
      if (mainWindow && mainWindow.webContents) {
        mainWindow.webContents.send('frida-output', message);
      }
    });

    fridaCmd.stderr.on('data', (data) => {
      const message = data.toString();
      error += message;
      console.log(`Frida stderr: ${message}`);
      if (mainWindow && mainWindow.webContents) {
        mainWindow.webContents.send('frida-error', message);
      }
    });

    fridaCmd.on('close', (code) => {
      console.log(`Frida process closed with code: ${code}`);
      fridaProcess = null;
      if (mainWindow && mainWindow.webContents) {
        mainWindow.webContents.send('frida-closed', code);
      }
    });

    fridaCmd.on('error', (error) => {
      console.log(`Frida process error: ${error.message}`);
      fridaProcess = null;
      resolve({ success: false, error: error.message });
      return;
    });

    fridaProcess = fridaCmd;
    
    // 즉시 성공 응답 (프로세스가 시작됨)
    resolve({ 
      success: true, 
      message: 'Frida process started',
      pid: fridaCmd.pid
    });
  });
});

// Frida 프로세스 중지
ipcMain.handle('stop-frida-process', async () => {
  if (fridaProcess) {
    fridaProcess.kill();
    fridaProcess = null;
    return { success: true, message: 'Frida process stopped' };
  }
  return { success: false, message: 'No Frida process running' };
});

// 앱 종료 시 모든 프로세스 정리
app.on('before-quit', () => {
  if (fridaProcess) {
    fridaProcess.kill();
  }
  if (adbProcess) {
    adbProcess.kill();
  }
});

// Frida 설치 확인
ipcMain.handle('check-frida-installation', async () => {
  return new Promise((resolve) => {
    const fridaCheck = spawn('frida', ['--version'], { shell: true });
    let output = '';
    let error = '';

    fridaCheck.stdout.on('data', (data) => {
      output += data.toString();
    });

    fridaCheck.stderr.on('data', (data) => {
      error += data.toString();
    });

    fridaCheck.on('close', (code) => {
      resolve({
        success: code === 0,
        output: output.trim(),
        error: error.trim(),
        installed: code === 0
      });
    });

    fridaCheck.on('error', (error) => {
      resolve({ 
        success: false, 
        error: error.message, 
        installed: false 
      });
    });
  });
});
