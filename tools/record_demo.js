// 데모 녹화 — Grafana 대시보드(dashboard 모듈)를 헤드리스 Chrome 으로 녹화한다 (playwright-core, 설치된 Chrome 사용).
//   npm i playwright-core@1.49.1
//   node tools/record_demo.js <출력 폴더> <초>        예: node tools/record_demo.js reports/video 720
// 녹화하는 동안 다른 창에서 `docker compose run --rm traffic demo`. 결과 .webm → ffmpeg 로 배속 · 변환 (README "영상").
// Chrome 위치는 CHROME_PATH 로 바꾼다 (기본: Windows · macOS · Linux 흔한 위치 중 있는 것).
const fs = require('fs');
const { chromium } = require('playwright-core');
const OUT = process.argv[2] || 'reports/video';
const SEC = +(process.argv[3] || 720);
const URL = process.env.LAB_GRAFANA || 'http://localhost:3000/d/api-defense-lab?orgId=1&refresh=5s&from=now-15m&to=now&kiosk';
const CHROME = process.env.CHROME_PATH || [
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser',
].find((p) => fs.existsSync(p));
(async () => {
  const b = await chromium.launch({ executablePath: CHROME, headless: true });
  const ctx = await b.newContext({ viewport: { width: 1600, height: 1000 }, recordVideo: { dir: OUT, size: { width: 1600, height: 1000 } } });
  const p = await ctx.newPage();
  await p.goto(URL, { waitUntil: 'load' });
  const t0 = Date.now();
  console.log(`녹화 시작 ${new Date().toISOString()} · ${SEC}초 · ${URL}`);
  while (Date.now() - t0 < SEC * 1000) {
    const el = Math.floor((Date.now() - t0) / 1000);
    // 아래쪽 표(ML 창 · 룰 경보)도 보이게 1분마다 잠깐 내렸다 올린다
    if (el % 60 === 30) { await p.mouse.wheel(0, 700); await p.waitForTimeout(8000); await p.mouse.wheel(0, -700); }
    await p.waitForTimeout(1000);
  }
  await ctx.close(); await b.close();
  console.log(`녹화 끝 → ${OUT}`);
})();
