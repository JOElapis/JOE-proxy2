const express = require('express');
const path = require('node:path');
const dns = require('node:dns').promises;
const net = require('node:net');
const ipaddr = require('ipaddr.js');
const { timingSafeEqual } = require('node:crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const ACCESS_KEY = process.env.PROXY_ACCESS_KEY || '';
const allowedDomains = (process.env.ALLOWED_DOMAINS || 'youtube.com,unityroom.com,crazygames.com')
  .split(',')
  .map((domain) => domain.trim().toLowerCase().replace(/^\.+|\.+$/g, ''))
  .filter(Boolean);
const COOKIE_NAME = 'proxy_access';
const MAX_RESPONSE_BYTES = 64 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 30_000;

app.disable('x-powered-by');
app.set('trust proxy', 1);

function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && timingSafeEqual(left, right);
}

function readCookie(req, name) {
  for (const pair of (req.headers.cookie || '').split(';')) {
    const [key, ...value] = pair.trim().split('=');
    if (key === name) {
      try { return decodeURIComponent(value.join('=')); } catch { return ''; }
    }
  }
  return '';
}

function authorized(req) {
  return Boolean(ACCESS_KEY) && safeEqual(readCookie(req, COOKIE_NAME), ACCESS_KEY);
}

function requireAuth(req, res, next) {
  if (!authorized(req)) return res.status(401).json({ error: '認証が必要です。/proxy?key=アクセスキー からアクセスしてください。' });
  next();
}

function hostnameAllowed(hostname) {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  return allowedDomains.some((domain) => host === domain || host.endsWith(`.${domain}`));
}

function isPublicAddress(address) {
  if (!net.isIP(address)) return false;
  return ipaddr.parse(address).range() === 'unicast';
}

async function validateTarget(rawUrl) {
  if (typeof rawUrl !== 'string' || rawUrl.length > 4096) throw new Error('URLが無効です。');
  const url = new URL(rawUrl);
  if (url.protocol !== 'https:' || url.username || url.password) throw new Error('HTTPSのURLのみ利用できます。');
  if (!hostnameAllowed(url.hostname)) throw new Error('このドメインは許可されていません。');
  const addresses = await dns.lookup(url.hostname, { all: true, verbatim: true });
  if (!addresses.length || addresses.some(({ address }) => !isPublicAddress(address))) throw new Error('接続先アドレスが許可されていません。');
  return url;
}

function rewriteHtml(html, pageUrl) {
  const rewrite = (value) => {
    if (!value || value.startsWith('#') || /^(?:data|blob|javascript|mailto|tel):/i.test(value)) return value;
    try {
      const target = new URL(value, pageUrl);
      if (target.protocol !== 'https:' || !hostnameAllowed(target.hostname)) return value;
      return `/api/proxy?url=${encodeURIComponent(target.href)}`;
    } catch { return value; }
  };
  return html.replace(/\b(src|href|action|poster)=(['"])(.*?)\2/gi,
    (_match, attr, quote, value) => `${attr}=${quote}${rewrite(value)}${quote}`);
}

app.get('/', (_req, res) => res.redirect('/proxy'));

app.get('/proxy', (req, res) => {
  if (!ACCESS_KEY) return res.status(503).send('Renderの環境変数 PROXY_ACCESS_KEY が未設定です。');
  if (typeof req.query.key === 'string' && safeEqual(req.query.key, ACCESS_KEY)) {
    res.cookie(COOKIE_NAME, ACCESS_KEY, {
      httpOnly: true,
      secure: req.secure,
      sameSite: 'lax',
      maxAge: 12 * 60 * 60 * 1000,
      path: '/',
    });
    return res.redirect(303, '/proxy');
  }
  if (!authorized(req)) return res.status(401).send('アクセスキーが必要です。管理者から受け取ったキーをURLの ?key= に付けてください。');
  res.setHeader('Cache-Control', 'no-store');
  res.sendFile(path.join(__dirname, 'public', 'proxy.html'));
});

app.get('/api/proxy', requireAuth, async (req, res) => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    let target = await validateTarget(req.query.url);
    let upstream;
    for (let redirects = 0; redirects <= 5; redirects += 1) {
      upstream = await fetch(target, {
        redirect: 'manual',
        signal: controller.signal,
        headers: {
          'user-agent': 'Mozilla/5.0 (compatible; ProxyOnly/1.0)',
          accept: req.headers.accept || '*/*',
          ...(req.headers.range ? { range: req.headers.range } : {}),
        },
      });
      if (![301, 302, 303, 307, 308].includes(upstream.status)) break;
      const location = upstream.headers.get('location');
      if (!location || redirects === 5) throw new Error('リダイレクトが多すぎます。');
      target = await validateTarget(new URL(location, target).href);
    }

    const contentType = upstream.headers.get('content-type') || 'application/octet-stream';
    const declaredLength = Number(upstream.headers.get('content-length') || 0);
    if (declaredLength > MAX_RESPONSE_BYTES) return res.status(413).send('レスポンスがサイズ上限を超えています。');
    const body = Buffer.from(await upstream.arrayBuffer());
    if (body.length > MAX_RESPONSE_BYTES) return res.status(413).send('レスポンスがサイズ上限を超えています。');

    res.status(upstream.status);
    res.setHeader('Content-Type', contentType);
    res.setHeader('Cache-Control', 'no-store');
    for (const header of ['content-range', 'accept-ranges']) {
      const value = upstream.headers.get(header);
      if (value) res.setHeader(header, value);
    }
    if (contentType.toLowerCase().includes('text/html')) res.send(rewriteHtml(body.toString('utf8'), target.href));
    else res.send(body);
  } catch (error) {
    console.error('Proxy request failed:', error.message);
    if (!res.headersSent) res.status(400).json({ error: error.name === 'AbortError' ? '接続がタイムアウトしました。' : error.message });
  } finally {
    clearTimeout(timer);
  }
});

app.post('/logout', requireAuth, (_req, res) => {
  res.clearCookie(COOKIE_NAME, { httpOnly: true, secure: true, sameSite: 'lax', path: '/' });
  res.redirect('/proxy');
});

app.use((_req, res) => res.status(404).send('Not found'));

app.listen(PORT, () => {
  console.log(`Proxy app listening on port ${PORT}`);
  console.log(`Allowed domains: ${allowedDomains.join(', ')}`);
  if (!ACCESS_KEY) console.warn('Set PROXY_ACCESS_KEY in Render environment variables.');
});
