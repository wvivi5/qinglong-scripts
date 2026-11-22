/* SPDX-License-Identifier: GPL-3.0-only
 * Rewards QingLong bridge, modified implementation 2026-10-26.
 * Protocol reference: ScriptCat #3947 / #3956, geoi6sam1 & Soul233.
 */
'use strict';

const http = require('node:http');
const path = require('node:path');
const net = require('node:net');
const { createHash, timingSafeEqual } = require('node:crypto');

const BODY_LIMIT = 512 * 1024;
const BODY_TIMEOUT = 10_000;
const RESPONSE_TIMEOUT = 35_000;
const REPLAY_TTL = 10 * 60_000;
const MAX_REPLAYS = 256;
const MAX_ROUTE_REQUESTS = 8;

class RequestError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function isLoopback(host) {
  const address = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
  return address === 'localhost' || address === '::1' ||
    (net.isIP(address) === 4 && address.split('.')[0] === '127');
}

function configuration(env) {
  const key = env.REWARDS_SYNC_KEY;
  if (typeof key !== 'string' || key.length < 32 || key.length > 1024 || !/^[\x21-\x7e]+$/.test(key)) {
    throw new Error('REWARDS_SYNC_KEY 必须为 32 至 1024 个不含空白的 ASCII 字符。');
  }
  const host = env.REWARDS_SYNC_HOST || '127.0.0.1';
  if (host !== 'localhost' && net.isIP(host) === 0) {
    throw new Error('REWARDS_SYNC_HOST 必须是 localhost 或 IP 字面量。');
  }
  if (!isLoopback(host) && env.REWARDS_ALLOW_HTTP !== '1') {
    throw new Error('非回环 HTTP 监听需要显式设置 REWARDS_ALLOW_HTTP=1。');
  }
  const portText = env.REWARDS_SYNC_PORT || '8787';
  if (!/^\d{1,5}$/.test(portText) || Number(portText) < 1 || Number(portText) > 65535) {
    throw new Error('REWARDS_SYNC_PORT 必须在 1 至 65535 之间。');
  }
  return {
    host,
    port: Number(portText),
    keyDigest: createHash('sha256').update(key).digest(),
    dataDir: path.resolve(env.REWARDS_DATA_DIR || path.join(__dirname, '.rewards-data')),
  };
}

function reply(res, status, body) {
  if (res.destroyed || res.writableEnded) return;
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    Connection: 'close',
  });
  res.end(JSON.stringify(body));
}

function authorized(req, expected) {
  const header = req.headers.authorization;
  const match = typeof header === 'string' && /^Bearer ([\x21-\x7e]{32,1024})$/.exec(header);
  const supplied = createHash('sha256').update(match ? match[1] : '').digest();
  return timingSafeEqual(supplied, expected) && Boolean(match);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    const timer = setTimeout(() => finish(new RequestError(408, '请求体接收超时。')), BODY_TIMEOUT);
    timer.unref();
    function cleanup() {
      clearTimeout(timer);
      req.removeListener('data', onData);
      req.removeListener('end', onEnd);
      req.removeListener('error', onError);
      req.removeListener('aborted', onAbort);
    }
    function finish(error, value) {
      cleanup();
      if (error) {
        req.resume();
        reject(error);
      } else {
        resolve(value);
      }
    }
    function onData(chunk) {
      size += chunk.length;
      if (size > BODY_LIMIT) return finish(new RequestError(413, '请求体超过 64KB。'));
      chunks.push(chunk);
    }
    function onEnd() {
      try {
        const text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
        const body = JSON.parse(text);
        if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error();
        finish(null, body);
      } catch {
        finish(new RequestError(400, '请求体必须是有效 JSON 对象。'));
      }
    }
    function onError() { finish(new RequestError(400, '请求体读取失败。')); }
    function onAbort() { finish(new RequestError(400, '请求已中断。')); }
    req.on('data', onData);
    req.once('end', onEnd);
    req.once('error', onError);
    req.once('aborted', onAbort);
  });
}

function validateCookies(body) {
  if (!Array.isArray(body.cookies) || body.cookies.length === 0 || body.cookies.length > 300) {
    throw new RequestError(400, 'cookies 必须是含 1 至 300 项的有效数组。');
  }
  if (typeof body.userAgent !== 'string' || body.userAgent.length === 0 ||
      body.userAgent.length > 2048 || /[\x00-\x1f\x7f]/.test(body.userAgent)) {
    throw new RequestError(400, 'userAgent 无效。');
  }
  const unique = new Map();
  let skippedCount = 0;
  for (const cookie of body.cookies) {
    if (!cookie || typeof cookie !== 'object' || Array.isArray(cookie) ||
        typeof cookie.name !== 'string' || cookie.name.length > 256 ||
        !/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(cookie.name) ||
        typeof cookie.value !== 'string' || cookie.value.length > 8192 ||
        /[\x00-\x1f\x7f;]/.test(cookie.value) ||
        typeof cookie.domain !== 'string' || cookie.domain.length > 253 ||
        typeof cookie.path !== 'string' || !cookie.path.startsWith('/') ||
        cookie.path.length > 2048 || /[\x00-\x1f\x7f;]/.test(cookie.path)) {
      skippedCount += 1; if (skippedCount <= 3) console.log('[cookie] skip: ' + String(cookie && cookie.name).slice(0, 32) + ' reason=format'); continue;
    }
    const domain = cookie.domain.toLowerCase();
    const hostname = domain.startsWith('.') ? domain.slice(1) : domain;
    if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*bing\.com$/.test(hostname)) {
      skippedCount += 1; if (skippedCount <= 3) console.log('[cookie] skip: ' + String(cookie && cookie.name).slice(0, 32) + ' domain=' + String(cookie && cookie.domain).slice(0, 40)); continue;
    }
    for (const field of ['secure', 'httpOnly', 'hostOnly']) {
      if (cookie[field] !== undefined && typeof cookie[field] !== 'boolean') {
        throw new RequestError(400, 'Cookie 属性无效。');
      }
    }
    if (cookie.expirationDate !== undefined &&
        (typeof cookie.expirationDate !== 'number' || !Number.isFinite(cookie.expirationDate) ||
         (cookie.expirationDate !== -1 && cookie.expirationDate < 0))) {
      throw new RequestError(400, 'Cookie 有效期无效。');
    }
    const normalized = {
      name: cookie.name,
      value: cookie.value,
      domain,
      path: cookie.path,
      secure: cookie.secure ?? false,
      httpOnly: cookie.httpOnly ?? false,
      hostOnly: cookie.hostOnly ?? !domain.startsWith('.'),
    };
    if (cookie.expirationDate !== undefined) normalized.expirationDate = cookie.expirationDate;
    unique.set(JSON.stringify([domain, cookie.path, cookie.name]), normalized);
  }
  if (skippedCount) console.log('[cookie] skipped total=' + skippedCount + ' kept=' + unique.size);
  if (unique.size === 0) {
    throw new RequestError(400, '没有通过校验的 Cookie（共 ' + body.cookies.length + ' 条，全部被过滤）。');
  }
  return { cookies: [...unique.values()], userAgent: body.userAgent };
}

function validateCode(body) {
  if (typeof body.code !== 'string' || body.code.length < 1 || body.code.length > 4096 ||
      /[\x00-\x20\x7f]/.test(body.code)) {
    throw new RequestError(400, 'OAuth code 无效。');
  }
  return body.code;
}

function routeQueue() {
  let tail = Promise.resolve();
  let count = 0;
  return function enqueue(operation) {
    if (count >= MAX_ROUTE_REQUESTS) {
      return Promise.reject(new RequestError(429, '同步队列繁忙，请稍后重试。'));
    }
    count += 1;
    const result = tail.then(operation);
    tail = result.catch(() => {}).finally(() => { count -= 1; });
    return result;
  };
}

function createSyncServer(options = {}) {
  const config = configuration(options.env || process.env);
  const common = options.common || require('./rewards-common.js');
  if (typeof common.updateCredentials !== 'function' || typeof common.exchangeCode !== 'function') {
    throw new Error('rewards-common.js 缺少必要的凭据接口。');
  }
  const cookiesQueue = routeQueue();
  const oauthQueue = routeQueue();
  const successfulCodes = new Map();

  async function handler(req, res) {
    const t0 = Date.now();
    console.log('[req] ' + req.method + ' ' + req.url
      + ' ua=' + String(req.headers['user-agent'] || '-').slice(0, 40)
      + ' len=' + String(req.headers['content-length'] || '-')
      + ' origin=' + String(req.headers['origin'] || '-')
      + ' ct=' + String(req.headers['content-type'] || '-').slice(0, 40));
    res.once('close', () => {
      console.log('[req] done ' + req.method + ' ' + req.url
        + ' -> ' + res.statusCode + ' in ' + (Date.now() - t0) + 'ms');
    });
    const timer = setTimeout(() => {
      reply(res, 504, { ok: false, error: '请求处理超时，请稍后检查同步状态。' });
    }, RESPONSE_TIMEOUT);
    timer.unref();
    res.once('close', () => clearTimeout(timer));
    try {
      if (req.url === '/health' && req.method === 'GET') {
        reply(res, 200, { ok: true });
        return;
      }
      if (!['/sync/cookies', '/sync/oauth'].includes(req.url)) {
        throw new RequestError(404, '接口不存在。');
      }
      if (req.method !== 'POST') throw new RequestError(405, '此接口仅支持 POST。');
      if (!authorized(req, config.keyDigest)) throw new RequestError(401, '认证失败。');
      if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(req.headers['content-type'] || '') ||
          (req.headers['content-encoding'] && req.headers['content-encoding'] !== 'identity')) {
        throw new RequestError(415, '仅支持 UTF-8 JSON 请求体。');
      }
      const contentLength = req.headers['content-length'];
      if (contentLength !== undefined && (!/^\d+$/.test(contentLength) || Number(contentLength) > BODY_LIMIT)) {
        throw new RequestError(413, '请求体超过 64KB。');
      }
      const body = await readBody(req);
      if (req.url === '/sync/cookies') {
        const validated = validateCookies(body);
        await cookiesQueue(async () => {
          if (res.destroyed || res.writableEnded) throw new RequestError(408, '请求已结束。');
          await common.updateCredentials((current) => ({
            ...current,
            ...validated,
            updatedAt: new Date().toISOString(),
          }));
        });
      } else {
        const code = validateCode(body);
        const digest = createHash('sha256').update(code).digest('hex');
        await oauthQueue(async () => {
          if (res.destroyed || res.writableEnded) throw new RequestError(408, '请求已结束。');
          const now = Date.now();
          for (const [hash, expires] of successfulCodes) {
            if (expires <= now) successfulCodes.delete(hash);
          }
          if (successfulCodes.has(digest)) throw new RequestError(409, '此授权已成功处理，请勿重复提交。');
          await common.withLock('oauth', async () => {
          const tokens = await common.exchangeCode(code);
          if (!tokens || typeof tokens.access_token !== 'string' || !tokens.access_token ||
              typeof tokens.refresh_token !== 'string' || !tokens.refresh_token ||
              typeof tokens.expires_at !== 'number' || !Number.isFinite(tokens.expires_at) || tokens.expires_at <= 0) {
            throw new Error('令牌交换结果无效。');
          }
          await common.updateCredentials((current) => ({
            ...current,
            app: {
              access_token: tokens.access_token,
              refresh_token: tokens.refresh_token,
              expires_at: tokens.expires_at,
              session: require('node:crypto').randomUUID(),
            },
            updatedAt: new Date().toISOString(),
          }));
          }, 45000);
          if (successfulCodes.size >= MAX_REPLAYS) successfulCodes.delete(successfulCodes.keys().next().value);
          successfulCodes.set(digest, Date.now() + REPLAY_TTL);
        });
      }
      reply(res, 200, { ok: true });
    } catch (error) {
      const known = error instanceof RequestError;
      reply(res, known ? error.status : 502, {
        ok: false,
        error: known ? error.message : '同步处理失败，请检查服务端配置或重新授权。',
      });
      if (!known) console.error('[rewards-sync] 同步处理失败；上游细节已隐藏。');
      else console.log('[req] reject ' + req.url + ' -> ' + error.status + ' ' + error.message);
    } finally {
      clearTimeout(timer);
      if (!req.complete) req.resume();
    }
  }

  const server = http.createServer({
    maxHeaderSize: 8192,
    headersTimeout: 10_000,
    requestTimeout: 15_000,
    connectionsCheckingInterval: 1000,
  }, (req, res) => { void handler(req, res); });
  server.maxConnections = 64;
  server.maxRequestsPerSocket = 1;
  server.setTimeout(RESPONSE_TIMEOUT + 1000, (socket) => socket.destroy());
  server.on('clientError', (_error, socket) => {
    if (socket.writable) {
      socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n{"ok":false,"error":"请求格式无效。"}');
    } else {
      socket.destroy();
    }
  });
  return { server, config };
}

function startServer(options = {}) {
  const { server, config } = createSyncServer(options);
  let shuttingDown = false;
  function shutdown() {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log('[rewards-sync] 正在关闭同步服务。');
    server.close(() => {
      clearTimeout(forceClose);
      process.removeListener('SIGINT', shutdown);
      process.removeListener('SIGTERM', shutdown);
    });
    server.closeIdleConnections();
    const forceClose = setTimeout(() => server.closeAllConnections(), 5000);
    forceClose.unref();
  }
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
  server.once('close', () => {
    process.removeListener('SIGINT', shutdown);
    process.removeListener('SIGTERM', shutdown);
  });
  server.on('error', () => {
    console.error('[rewards-sync] 服务监听失败，请检查绑定地址和端口。');
    process.exitCode = 1;
    process.removeListener('SIGINT', shutdown);
    process.removeListener('SIGTERM', shutdown);
  });
  server.listen(config.port, config.host, () => {
    const host = net.isIP(config.host) === 6 ? `[${config.host}]` : config.host;
    console.log(`[rewards-sync] 监听 http://${host}:${config.port}`);
    console.log(`[rewards-sync] 凭据目标目录：${JSON.stringify(config.dataDir)}`);
  });
  return server;
}

module.exports = { createSyncServer, startServer };

if (require.main === module) {
  try {
    startServer();
  } catch {
    console.error('[rewards-sync] 启动失败：请检查密钥、监听配置及 rewards-common.js 接口。');
    process.exitCode = 1;
  }
}
