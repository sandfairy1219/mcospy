// MCOSpy Frida Bypass Script
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
      `XigncodeClientSystem.initialize is called: activity=${activity}, str=${str}, str2=${str2}, str3=${str3}, callback=${callback}`
    );
    return 0;
  };
  */
  let Cocos2dxActivity = Java.use("org.cocos2dx.lib.Cocos2dxActivity");
  Cocos2dxActivity["getCookie"].implementation = function (str) {
    console.log(`Cocos2dxActivity.getCookie is called: str=${str}`);
    let result = this["getCookie"](str);
    console.log(`Cocos2dxActivity.getCookie result=${result}`);
    return result;
  };
});