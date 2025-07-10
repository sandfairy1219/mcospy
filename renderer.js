const { ipcRenderer } = require('electron');
const fs = require('fs');
const path = require('path');

// DOM 요소들
const elements = {
    // ADB 관련
    adbAddress: document.getElementById('adb-address'),
    adbStatus: document.getElementById('adb-status'),
    adbIndicator: document.getElementById('adb-indicator'),
    adbOutput: document.getElementById('adb-output'),
    checkAdbBtn: document.getElementById('check-adb'),
    connectBluestacksBtn: document.getElementById('connect-bluestacks'),
    resetAddressBtn: document.getElementById('reset-address'),
    
    // Frida 서버 관련
    fridaServerStatus: document.getElementById('frida-server-status'),
    fridaServerIndicator: document.getElementById('frida-server-indicator'),
    fridaServerOutput: document.getElementById('frida-server-output'),
    checkFridaServerBtn: document.getElementById('check-frida-server'),
    startFridaServerBtn: document.getElementById('start-frida-server'),
    uploadFridaServerBtn: document.getElementById('upload-frida-server'),
    checkPermissionsBtn: document.getElementById('check-permissions'),
    
    // 앱 실행 관련
    cookieValue: document.getElementById('cookie-value'),
    getCookieBtn: document.getElementById('get-cookie'),
    startAgentBtn: document.getElementById('start-agent'),
    checkFridaBtn: document.getElementById('check-frida'),
    clearCookieBtn: document.getElementById('clear-cookie'),
    stopAppBtn: document.getElementById('stop-app'),
    appStatus: document.getElementById('app-status'),
    appIndicator: document.getElementById('app-indicator'),
    appOutput: document.getElementById('app-output'),
    
    // 로그 관련
    logs: document.getElementById('logs'),
    clearLogsBtn: document.getElementById('clear-logs'),
    saveLogsBtn: document.getElementById('save-logs')
};

// 유틸리티 함수들
function updateStatus(statusElement, indicatorElement, message, status) {
    statusElement.textContent = message;
    indicatorElement.className = `indicator ${status}`;
}

function addLog(message, type = 'info') {
    const timestamp = new Date().toLocaleTimeString();
    const logElement = document.createElement('div');
    logElement.className = `log-${type}`;
    logElement.textContent = `[${timestamp}] ${message}`;
    elements.logs.appendChild(logElement);
    elements.logs.scrollTop = elements.logs.scrollHeight;
}

function updateOutput(outputElement, content) {
    outputElement.textContent = content;
    outputElement.style.display = content ? 'block' : 'none';
}

function setButtonLoading(button, loading) {
    if (loading) {
        button.classList.add('loading');
        button.disabled = true;
    } else {
        button.classList.remove('loading');
        button.disabled = false;
    }
}

// 이벤트 리스너 설정
function setupEventListeners() {
    // ADB 관련 이벤트
    elements.checkAdbBtn.addEventListener('click', checkAdbConnection);
    elements.connectBluestacksBtn.addEventListener('click', connectBluestacks);
    elements.resetAddressBtn.addEventListener('click', resetAddress);
    
    // Frida 서버 관련 이벤트
    elements.checkFridaServerBtn.addEventListener('click', checkFridaServer);
    elements.startFridaServerBtn.addEventListener('click', startFridaServer);
    elements.uploadFridaServerBtn.addEventListener('click', uploadFridaServer);
    elements.checkPermissionsBtn.addEventListener('click', checkFridaPermissions);
    
    // 앱 실행 관련 이벤트
    elements.getCookieBtn.addEventListener('click', getCookie);
    elements.startAgentBtn.addEventListener('click', startAgent);
    elements.checkFridaBtn.addEventListener('click', checkFridaInstallation);
    elements.clearCookieBtn.addEventListener('click', clearCookie);
    elements.stopAppBtn.addEventListener('click', stopApp);
    
    // 로그 관련 이벤트
    elements.clearLogsBtn.addEventListener('click', clearLogs);
    elements.saveLogsBtn.addEventListener('click', saveLogs);
}

// ADB 연결 상태 확인
async function checkAdbConnection() {
    setButtonLoading(elements.checkAdbBtn, true);
    addLog('ADB 연결 상태 확인 중...', 'info');
    
    try {
        const result = await ipcRenderer.invoke('check-adb-connection');
        
        if (result.connected) {
            updateStatus(elements.adbStatus, elements.adbIndicator, 
                `연결됨 (${result.devices.length}개 장치)`, 'connected');
            updateOutput(elements.adbOutput, `연결된 장치:\n${result.devices.join('\n')}`);
            addLog(`ADB 연결 성공: ${result.devices.length}개 장치 발견`, 'success');
        } else {
            updateStatus(elements.adbStatus, elements.adbIndicator, '연결 안됨', 'disconnected');
            updateOutput(elements.adbOutput, result.error || '연결된 장치가 없습니다.');
            addLog('ADB 연결 실패: 연결된 장치가 없습니다.', 'error');
        }
    } catch (error) {
        updateStatus(elements.adbStatus, elements.adbIndicator, '오류 발생', 'disconnected');
        updateOutput(elements.adbOutput, `오류: ${error.message}`);
        addLog(`ADB 확인 오류: ${error.message}`, 'error');
    } finally {
        setButtonLoading(elements.checkAdbBtn, false);
    }
}

// BlueStacks 연결
async function connectBluestacks() {
    setButtonLoading(elements.connectBluestacksBtn, true);
    const adbAddress = elements.adbAddress.value.trim() || '127.0.0.1:5555';
    addLog(`ADB 연결 시도 중... (${adbAddress})`, 'info');
    
    try {
        const result = await ipcRenderer.invoke('connect-bluestacks', adbAddress);
        
        if (result.success) {
            updateStatus(elements.adbStatus, elements.adbIndicator, `${adbAddress} 연결됨`, 'connected');
            updateOutput(elements.adbOutput, result.output);
            addLog(`ADB 연결 성공: ${adbAddress}`, 'success');
            
            // 연결 후 상태 재확인
            setTimeout(checkAdbConnection, 1000);
        } else {
            updateStatus(elements.adbStatus, elements.adbIndicator, '연결 실패', 'disconnected');
            updateOutput(elements.adbOutput, result.error || '연결에 실패했습니다.');
            addLog(`ADB 연결 실패: ${result.error}`, 'error');
        }
    } catch (error) {
        updateStatus(elements.adbStatus, elements.adbIndicator, '오류 발생', 'disconnected');
        updateOutput(elements.adbOutput, `오류: ${error.message}`);
        addLog(`ADB 연결 오류: ${error.message}`, 'error');
    } finally {
        setButtonLoading(elements.connectBluestacksBtn, false);
    }
}

// ADB 주소 초기화
function resetAddress() {
    elements.adbAddress.value = '127.0.0.1:5555';
    addLog('ADB 주소가 기본값으로 초기화되었습니다.', 'info');
}

// Frida 서버 상태 확인
async function checkFridaServer() {
    setButtonLoading(elements.checkFridaServerBtn, true);
    addLog('Frida 서버 상태 확인 중...', 'info');
    
    try {
        const result = await ipcRenderer.invoke('check-frida-server');
        
        if (result.running) {
            updateStatus(elements.fridaServerStatus, elements.fridaServerIndicator, 
                'Frida 서버 실행 중', 'connected');
            updateOutput(elements.fridaServerOutput, result.output);
            addLog('Frida 서버가 실행 중입니다', 'success');
        } else {
            updateStatus(elements.fridaServerStatus, elements.fridaServerIndicator, 
                'Frida 서버 중지됨', 'disconnected');
            updateOutput(elements.fridaServerOutput, result.error || 'Frida 서버가 실행되지 않고 있습니다.');
            addLog('Frida 서버가 중지되어 있습니다', 'warning');
        }
    } catch (error) {
        updateStatus(elements.fridaServerStatus, elements.fridaServerIndicator, '오류 발생', 'disconnected');
        updateOutput(elements.fridaServerOutput, `오류: ${error.message}`);
        addLog(`Frida 서버 확인 오류: ${error.message}`, 'error');
    } finally {
        setButtonLoading(elements.checkFridaServerBtn, false);
    }
}

// Frida 서버 시작
async function startFridaServer() {
    setButtonLoading(elements.startFridaServerBtn, true);
    addLog('Frida 서버 시작 중...', 'info');
    
    try {
        const result = await ipcRenderer.invoke('start-frida-server');
        
        if (result.success) {
            updateStatus(elements.fridaServerStatus, elements.fridaServerIndicator, 
                'Frida 서버 시작됨', 'connected');
            updateOutput(elements.fridaServerOutput, 
                `${result.output}\n\n검증 결과:\n${result.verification || ''}`);
            addLog(result.message || 'Frida 서버 시작 성공', 'success');
            
            // 서버 시작 후 상태 재확인
            setTimeout(checkFridaServer, 2000);
        } else {
            updateStatus(elements.fridaServerStatus, elements.fridaServerIndicator, 
                '시작 실패', 'disconnected');
            updateOutput(elements.fridaServerOutput, result.error || '서버 시작에 실패했습니다.');
            addLog(`Frida 서버 시작 실패: ${result.error}`, 'error');
        }
    } catch (error) {
        updateStatus(elements.fridaServerStatus, elements.fridaServerIndicator, '오류 발생', 'disconnected');
        updateOutput(elements.fridaServerOutput, `오류: ${error.message}`);
        addLog(`Frida 서버 시작 오류: ${error.message}`, 'error');
    } finally {
        setButtonLoading(elements.startFridaServerBtn, false);
    }
}

// Frida 서버 업로드
async function uploadFridaServer() {
    setButtonLoading(elements.uploadFridaServerBtn, true);
    addLog('파일 선택 대화상자를 여는 중...', 'info');
    
    try {
        const result = await ipcRenderer.invoke('upload-frida-server');
        
        if (result.success) {
            updateStatus(elements.fridaServerStatus, elements.fridaServerIndicator, 
                'Frida 서버 업로드 완료', 'connected');
            updateOutput(elements.fridaServerOutput, result.output);
            addLog(`Frida 서버 업로드 성공: ${result.originalFile}`, 'success');
            
            // 업로드 후 상태 재확인
            setTimeout(checkFridaServer, 2000);
        } else {
            // 사용자가 취소한 경우와 실제 오류를 구분
            if (result.error && result.error.includes('취소')) {
                updateStatus(elements.fridaServerStatus, elements.fridaServerIndicator, 
                    '업로드 취소됨', 'disconnected');
                updateOutput(elements.fridaServerOutput, '파일 선택이 취소되었습니다.');
                addLog('파일 선택이 취소되었습니다.', 'warning');
            } else {
                updateStatus(elements.fridaServerStatus, elements.fridaServerIndicator, 
                    '업로드 실패', 'disconnected');
                updateOutput(elements.fridaServerOutput, 
                    `서버 업로드 실패\n\n오류: ${result.error || '알 수 없는 오류'}\n\nADB 연결 및 권한을 확인해주세요.`);
                addLog(`Frida 서버 업로드 실패: ${result.error}`, 'error');
            }
        }
    } catch (error) {
        updateStatus(elements.fridaServerStatus, elements.fridaServerIndicator, '오류 발생', 'disconnected');
        updateOutput(elements.fridaServerOutput, `오류: ${error.message}`);
        addLog(`Frida 서버 업로드 오류: ${error.message}`, 'error');
    } finally {
        setButtonLoading(elements.uploadFridaServerBtn, false);
    }
}

// Frida 서버 권한 확인
async function checkFridaPermissions() {
    setButtonLoading(elements.checkPermissionsBtn, true);
    addLog('Frida 서버 권한 확인 중...', 'info');
    
    try {
        const result = await ipcRenderer.invoke('check-frida-permissions');
        
        if (result.success) {
            const permissionStatus = result.hasExecutePermission ? '실행 권한 있음' : '실행 권한 없음';
            updateOutput(elements.fridaServerOutput, 
                `권한 확인 결과:\n${result.output}\n\n상태: ${permissionStatus}`);
            
            if (result.hasExecutePermission) {
                addLog('Frida 서버에 실행 권한이 있습니다', 'success');
            } else {
                addLog('Frida 서버에 실행 권한이 없습니다. chmod +x 명령이 필요합니다.', 'warning');
            }
        } else {
            updateOutput(elements.fridaServerOutput, 
                `권한 확인 실패:\n${result.error || '파일을 찾을 수 없거나 접근할 수 없습니다.'}`);
            addLog(`권한 확인 실패: ${result.error}`, 'error');
        }
    } catch (error) {
        updateOutput(elements.fridaServerOutput, `오류: ${error.message}`);
        addLog(`권한 확인 오류: ${error.message}`, 'error');
    } finally {
        setButtonLoading(elements.checkPermissionsBtn, false);
    }
}

// 쿠키 가져오기 (1단계)
async function getCookie() {
    setButtonLoading(elements.getCookieBtn, true);
    
    // 먼저 쿠키 추출 모드로 스크립트 복원
    restoreCookieScript();
    
    // 파일 시스템 동기화를 위한 짧은 대기
    await new Promise(resolve => setTimeout(resolve, 500));
    
    addLog('1단계: 쿠키 가져오기 시작...', 'info');
    updateStatus(elements.appStatus, elements.appIndicator, '쿠키 추출 중...', 'running');
    
    try {
        const result = await ipcRenderer.invoke('run-app-with-frida');
        
        if (result.success) {
            updateStatus(elements.appStatus, elements.appIndicator, 
                `쿠키 추출 중... (PID: ${result.pid})`, 'running');
            addLog(`쿠키 추출 시작: ${result.message}`, 'success');
            
            // 버튼 상태 변경
            elements.getCookieBtn.disabled = true;
            elements.stopAppBtn.disabled = false;
        } else {
            updateStatus(elements.appStatus, elements.appIndicator, '쿠키 추출 실패', 'disconnected');
            updateOutput(elements.appOutput, result.error || '쿠키 추출에 실패했습니다.');
            addLog(`쿠키 추출 실패: ${result.error}`, 'error');
        }
    } catch (error) {
        updateStatus(elements.appStatus, elements.appIndicator, '오류 발생', 'disconnected');
        updateOutput(elements.appOutput, `오류: ${error.message}`);
        addLog(`쿠키 추출 오류: ${error.message}`, 'error');
    } finally {
        setButtonLoading(elements.getCookieBtn, false);
    }
}

// Agent 시작 (2단계)
async function startAgent() {
    setButtonLoading(elements.startAgentBtn, true);
    const cookieValue = elements.cookieValue.value.trim();
    
    if (!cookieValue) {
        addLog('쿠키 값이 필요합니다. 먼저 쿠키 가져오기를 실행하세요.', 'error');
        setButtonLoading(elements.startAgentBtn, false);
        return;
    }
    
    addLog('2단계: Agent 시작...', 'info');
    updateStatus(elements.appStatus, elements.appIndicator, 'Agent 시작 중...', 'running');
    
    try {
        // Agent 실행용 스크립트 생성
        const agentScript = createAgentScript(cookieValue);
        
        const result = await ipcRenderer.invoke('run-app-with-frida');
        
        if (result.success) {
            updateStatus(elements.appStatus, elements.appIndicator, 
                `Agent 실행 중... (PID: ${result.pid})`, 'connected');
            addLog(`Agent 시작 성공: ${result.message}`, 'success');
            
            // 버튼 상태 변경
            elements.startAgentBtn.disabled = true;
            elements.stopAppBtn.disabled = false;
        } else {
            updateStatus(elements.appStatus, elements.appIndicator, 'Agent 시작 실패', 'disconnected');
            updateOutput(elements.appOutput, result.error || 'Agent 시작에 실패했습니다.');
            addLog(`Agent 시작 실패: ${result.error}`, 'error');
        }
    } catch (error) {
        updateStatus(elements.appStatus, elements.appIndicator, '오류 발생', 'disconnected');
        updateOutput(elements.appOutput, `오류: ${error.message}`);
        addLog(`Agent 시작 오류: ${error.message}`, 'error');
    } finally {
        setButtonLoading(elements.startAgentBtn, false);
    }
}

// 쿠키 지우기
function clearCookie() {
    elements.cookieValue.value = '';
    elements.startAgentBtn.disabled = true;
    
    // 앱 상태 초기화
    updateStatus(elements.appStatus, elements.appIndicator, '대기 중', 'disconnected');
    
    // 스크립트를 쿠키 추출 모드로 복원
    restoreCookieScript();
    
    addLog('쿠키 값이 지워지고 스크립트가 쿠키 추출 모드로 복원되었습니다.', 'info');
}

// Agent 실행용 스크립트 생성
function createAgentScript(cookieValue) {
    try {
        let scriptContent = fs.readFileSync(path.join(__dirname, 'bypass.js'), 'utf8');
        
        // 주석 해제 (XigncodeClientSystem 부분)
        scriptContent = scriptContent.replace(
            /\/\*\s*([\s\S]*?)\s*\*\//g,
            '$1'
        );
        
        // return result;를 쿠키 값으로 변경
        scriptContent = scriptContent.replace(
            /return result;/g,
            `return "${cookieValue}";`
        );
        
        // bypass.js를 직접 덮어쓰기
        fs.writeFileSync(path.join(__dirname, 'bypass.js'), scriptContent);
        
        addLog(`Agent 스크립트 생성됨 (주석 해제 + 쿠키: ${cookieValue})`, 'info');
        return true;
    } catch (error) {
        addLog(`Agent 스크립트 생성 실패: ${error.message}`, 'error');
        throw new Error(`Agent 스크립트 생성 실패: ${error.message}`);
    }
}

// Frida 설치 확인
async function checkFridaInstallation() {
    setButtonLoading(elements.checkFridaBtn, true);
    addLog('Frida 설치 상태 확인 중...', 'info');
    
    try {
        const result = await ipcRenderer.invoke('check-frida-installation');
        
        if (result.success && result.installed) {
            addLog(`Frida 설치 확인됨: ${result.output}`, 'success');
            updateOutput(elements.appOutput, `Frida 버전: ${result.output}`);
        } else {
            addLog('Frida가 설치되지 않았거나 PATH에 없습니다.', 'error');
            updateOutput(elements.appOutput, 
                `Frida 설치 오류:\n${result.error || '명령을 찾을 수 없습니다.'}\n\n해결 방법:\n1. Python 설치\n2. pip install frida-tools\n3. 시스템 PATH 확인`);
        }
    } catch (error) {
        addLog(`Frida 확인 오류: ${error.message}`, 'error');
        updateOutput(elements.appOutput, `오류: ${error.message}`);
    } finally {
        setButtonLoading(elements.checkFridaBtn, false);
    }
}

// 앱 중지
async function stopApp() {
    setButtonLoading(elements.stopAppBtn, true);
    addLog('앱 중지 중...', 'info');
    
    try {
        const result = await ipcRenderer.invoke('stop-frida-process');
        
        if (result.success) {
            updateStatus(elements.appStatus, elements.appIndicator, '앱 중지됨', 'disconnected');
            addLog(result.message, 'success');
            
            // 버튼 상태 복원
            elements.getCookieBtn.disabled = false;
            elements.startAgentBtn.disabled = elements.cookieValue.value.trim() === '';
            elements.stopAppBtn.disabled = true;
        } else {
            addLog(`앱 중지 실패: ${result.message}`, 'error');
        }
    } catch (error) {
        addLog(`앱 중지 오류: ${error.message}`, 'error');
    } finally {
        setButtonLoading(elements.stopAppBtn, false);
    }
}

// 로그 지우기
function clearLogs() {
    elements.logs.innerHTML = '';
    addLog('로그가 지워졌습니다.', 'info');
}

// 로그 저장
function saveLogs() {
    const logs = elements.logs.textContent;
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `frida-manager-logs-${timestamp}.txt`;
    
    try {
        fs.writeFileSync(filename, logs);
        addLog(`로그가 저장되었습니다: ${filename}`, 'success');
    } catch (error) {
        addLog(`로그 저장 실패: ${error.message}`, 'error');
    }
}

// IPC 이벤트 리스너 설정
function setupIpcListeners() {
    // Frida 출력 실시간 수신
    ipcRenderer.on('frida-output', (event, data) => {
        updateOutput(elements.appOutput, elements.appOutput.textContent + data);
        addLog(`[Frida] ${data.trim()}`, 'info');
        
        // 쿠키 값 추출 (쿠키 추출 모드에서)
        const cookieMatch = data.match(/Cocos2dxActivity\.getCookie result=(.+)/);
        if (cookieMatch && cookieMatch[1]) {
            const cookieValue = cookieMatch[1].trim();
            if (cookieValue && cookieValue !== '') {
                elements.cookieValue.value = cookieValue;
                elements.startAgentBtn.disabled = false;
                
                // 쿠키 추출 성공 시 indicator를 connected로 변경
                updateStatus(elements.appStatus, elements.appIndicator, 
                    '쿠키 추출 성공', 'connected');
                
                addLog(`쿠키 값 추출됨: ${cookieValue}`, 'success');
                addLog('쿠키 추출 완료! 이제 Agent를 시작할 수 있습니다.', 'success');
            }
        }
        
        // Agent 실행 중 Xigncode 우회 성공 감지
        if (data.includes('Cocos2dxActivity.getCookie result=') && 
            elements.appStatus.textContent.includes('Agent 실행 중')) {
            updateStatus(elements.appStatus, elements.appIndicator, 
                'Xigncode 우회성공!', 'connected');
            addLog('Xigncode 우회 성공! Agent가 정상적으로 작동 중입니다.', 'success');
        }
    });
    
    // Frida 에러 실시간 수신
    ipcRenderer.on('frida-error', (event, data) => {
        updateOutput(elements.appOutput, elements.appOutput.textContent + data);
        addLog(`[Frida Error] ${data.trim()}`, 'error');
    });
    
    // Frida 프로세스 종료 알림
    ipcRenderer.on('frida-closed', (event, exitCode) => {
        updateStatus(elements.appStatus, elements.appIndicator, 
            `앱 종료됨 (코드: ${exitCode})`, 'disconnected');
        addLog(`Frida 프로세스 종료: 종료 코드 ${exitCode}`, 'warning');
        
        // 버튼 상태 복원
        elements.getCookieBtn.disabled = false;
        elements.startAgentBtn.disabled = elements.cookieValue.value.trim() === '';
        elements.stopAppBtn.disabled = true;
    });
}

// 쿠키 가져오기 완료 후 스크립트 복원
function restoreCookieScript() {
    try {
        const originalScript = `// MCOSpy Frida Bypass Script
Java.perform(() => {
  // 쿠키 가져오기 시에는 아래 부분 주석 처리
  /*
  let XigncodeClientSystem = Java.use(
    "com.wellbia.xigncode.XigncodeClientSystem"
  );
  XigncodeClientSystem["initialize"].implementation = function (
    activity,
    str,
    str2,
    str3,
    callback
  ) {
    console.log(
      \`XigncodeClientSystem.initialize is called: activity=\${activity}, str=\${str}, str2=\${str2}, str3=\${str3}, callback=\${callback}\`
    );
    return 0;
  };
  */
  let Cocos2dxActivity = Java.use("org.cocos2dx.lib.Cocos2dxActivity");
  Cocos2dxActivity["getCookie"].implementation = function (str) {
    console.log(\`Cocos2dxActivity.getCookie is called: str=\${str}\`);
    let result = this["getCookie"](str);
    console.log(\`Cocos2dxActivity.getCookie result=\${result}\`);
    return result;
  };
});`;
        
        fs.writeFileSync(path.join(__dirname, 'bypass.js'), originalScript);
        addLog('쿠키 추출 모드로 스크립트 복원됨', 'info');
    } catch (error) {
        addLog(`스크립트 복원 실패: ${error.message}`, 'error');
    }
}

// 초기화
function initialize() {
    // 초기 상태 설정
    elements.stopAppBtn.disabled = true;
    elements.startAgentBtn.disabled = true;
    
    // 초기 상태 표시
    updateStatus(elements.appStatus, elements.appIndicator, '대기 중', 'disconnected');
    
    // 이벤트 리스너 설정
    setupEventListeners();
    setupIpcListeners();
    
    // 초기 상태 확인
    addLog('MCOSpy Frida Manager 시작됨', 'success');
    addLog('bypass.js 파일 사용 (현재 디렉토리)', 'info');
    checkAdbConnection();
    checkFridaServer();
}

// DOM 로드 완료 후 초기화
document.addEventListener('DOMContentLoaded', initialize);
