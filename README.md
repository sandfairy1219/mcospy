# MCOSpy Frida Manager

BlueStacks에서 ADB 연결 및 Frida 서버 관리를 위한 일렉트론 데스크톱 애플리케이션입니다.

## 주요 기능

### 🔧 ADB 연결 관리
- BlueStacks ADB 연결 상태 확인
- 자동 BlueStacks 연결 (127.0.0.1:5555)
- 연결된 디바이스 목록 표시

### 🚀 Frida 서버 관리
- Frida 서버 상태 확인
- Frida 서버 시작/중지
- 실시간 서버 상태 모니터링

### 🎮 앱 실행 및 스크립트 관리
- com.gameparadiso.milkchoco 앱 자동 실행
- 커스텀 Frida 스크립트 로드
- 실시간 로그 출력
- 프로세스 관리

## 설치 및 실행

### 사전 요구사항
- Node.js (14 이상)
- ADB (Android Debug Bridge)
- Frida (Python 패키지)
- BlueStacks (실행 중)

### 설치 방법

1. 프로젝트 의존성 설치:
```bash
npm install
```

2. 개발 모드 실행:
```bash
npm run dev
```

3. 프로덕션 빌드:
```bash
npm run build
```

## 사용 방법

### 1. BlueStacks 준비
1. BlueStacks를 실행합니다
2. 설정 → 고급 → Android 디버그 브리지 활성화
3. 포트를 5555로 설정

### 2. Frida 서버 설정
1. 디바이스에 맞는 frida-server를 다운로드
2. `/data/local/tmp/frida-server`에 업로드
3. 실행 권한 부여: `chmod +x /data/local/tmp/frida-server`

### 3. 앱 사용
1. "BlueStacks 연결" 버튼 클릭
2. "서버 시작" 버튼으로 Frida 서버 실행
3. bypass.js 스크립트 경로 설정 (선택사항)
4. "앱 실행" 버튼으로 타겟 앱 실행

## 스크립트 커스터마이징

`bypass.js` 파일을 수정하여 다양한 보안 우회 기능을 추가할 수 있습니다:

- 루트 탐지 우회
- 에뮬레이터 탐지 우회
- SSL Pinning 우회
- 디버깅 탐지 우회
- Frida 탐지 우회
- 게임 특화 후킹

## 디렉토리 구조

```
mcospy/
├── main.js          # 메인 프로세스
├── renderer.js      # 렌더러 프로세스
├── index.html       # UI 레이아웃
├── styles.css       # 스타일시트
├── bypass.js        # Frida 스크립트
├── package.json     # 프로젝트 설정
└── README.md        # 이 파일
```

## 주의사항

⚠️ **법적 고지사항**: 이 도구는 교육 및 연구 목적으로만 사용해야 합니다. 불법적인 목적으로 사용하지 마세요.

⚠️ **보안 고려사항**: 
- 신뢰할 수 없는 스크립트를 실행하지 마세요
- 개인 정보가 포함된 로그를 공유하지 마세요
- 정기적으로 도구를 업데이트하세요

## 문제 해결

### 자주 발생하는 문제

1. **ADB 연결 실패**
   - BlueStacks가 실행 중인지 확인
   - ADB 디버그 브리지가 활성화되어 있는지 확인
   - 포트 5555가 사용 중인지 확인

2. **Frida 서버 시작 실패**
   - Root 권한이 있는지 확인
   - frida-server 파일이 올바른 위치에 있는지 확인
   - 실행 권한이 부여되었는지 확인

3. **앱 실행 실패**
   - 타겟 앱이 설치되어 있는지 확인
   - Frida 서버가 실행 중인지 확인
   - 스크립트 경로가 올바른지 확인

## 라이센스

MIT License

## 기여하기

1. 이 저장소를 Fork합니다
2. 새로운 기능 브랜치를 생성합니다
3. 변경사항을 커밋합니다
4. 브랜치에 Push합니다
5. Pull Request를 생성합니다

## 연락처

문의사항이나 버그 리포트는 GitHub Issues를 통해 제출해주세요.
