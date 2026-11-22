// ==UserScript==
// @name         Microsoft Rewards 青龙桥接助手
// @namespace    rewards-qinglong-bridge-local
// @version      1.1.1
// @description  用户配置桥接地址后同步 Bing Cookie，并完成独立的 Rewards App 授权。
// @license      GPL-3.0
// @author       QingLong adapter; protocol reference: geoi6sam1 & Soul233
// Modified implementation 2026-10-26; references ScriptCat #3947 / #3956.
// @storageName  rewards-qinglong-bridge-7f4d67b9-v1
// @match        https://www.bing.com/*
// @match        https://cn.bing.com/*
// @match        https://rewards.bing.com/*
// @match        https://login.live.com/oauth20_desktop.srf*
// @noframes
// @run-at       document-start
// @grant        GM_cookie
// @grant        GM_xmlhttpRequest
// @grant        GM_getValue
// @grant        GM_setValue
// @grant        GM.setValue
// @grant        GM_registerMenuCommand
// @grant        GM_openInTab
// @grant        GM_notification
// @connect      bing.com
// @connect      *.bing.com
// @connect      login.live.com
// @connect      127.0.0.1
// @connect      localhost
// @connect      n200b.gerd.netlib.re
// @connect      gerd.netlib.re
// @connect      *.netlib.re
// @connect      *
// ==/UserScript==

(function () {
  'use strict';

  const STORAGE = 'rewards-ql-bridge-7f4d67b9:';
  const CLIENT_ID = '0000000040170455';
  const SCOPE = 'service::prod.rewardsplatform.microsoft.com::MBI_SSL';
  const REDIRECT_URI = 'https://login.live.com/oauth20_desktop.srf';
  const USERINFO_URL = 'https://rewards.bing.com/api/getuserinfo?type=1';
  const INTERVAL = 15 * 60_000;
  const PENDING_TTL = 10 * 60_000;
  const BODY_LIMIT = 512 * 1024;
  let cookieBusy = false;
  let oauthBusy = false;
  let retryAuthorization = null;
  let lastAutomaticError = '';
  let lastAutomaticErrorAt = 0;

  class HelperError extends Error {}
  function failure(message) { return new HelperError(message); }
  function safeMessage(error) {
    return error instanceof HelperError ? error.message : '操作失败，请检查助手权限及桥接服务配置。';
  }
  function notify(text) {
    try {
      GM_notification({ title: 'Rewards 青龙桥接助手', text, timeout: 7000 });
    } catch {
      console.warn('[Rewards 桥接助手] 通知不可用。');
    }
  }
  function reportAutomatic(error) {
    const text = safeMessage(error);
    const now = Date.now();
    if (text !== lastAutomaticError || now - lastAutomaticErrorAt >= INTERVAL) {
      console.warn(`[Rewards 桥接助手] ${text}`);
      lastAutomaticError = text;
      lastAutomaticErrorAt = now;
    }
  }
  async function getStored(name, fallback) {
    return await GM_getValue(STORAGE + name, fallback);
  }
  async function setStored(name, value) {
    await GM.setValue(STORAGE + name, value);
  }
  async function sha256(value) {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
    return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
  }
  function randomState() {
    return Array.from(crypto.getRandomValues(new Uint8Array(32)),
      (byte) => byte.toString(16).padStart(2, '0')).join('');
  }
  function validKey(key) {
    return typeof key === 'string' && /^[\x21-\x7e]{32,1024}$/.test(key);
  }
  function ipv4(host) {
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(host)) return null;
    const parts = host.split('.').map(Number);
    return parts.every((part) => part >= 0 && part <= 255) ? parts : null;
  }
  function isLoopback(host) {
    const parts = ipv4(host);
    return host === 'localhost' || host === '[::1]' || Boolean(parts && parts[0] === 127);
  }
  function isPrivate(host) {
    const parts = ipv4(host);
    if (parts) {
      return parts[0] === 10 || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
        (parts[0] === 192 && parts[1] === 168);
    }
    return /^\[f[cd][0-9a-f]{2}:/i.test(host);
  }
  function parseBase(input) {
    if (typeof input !== 'string' || input.length > 2048 ||
        !/^https?:\/\/[^/?#]+\/?$/i.test(input) || /[\s\\\x00-\x1f\x7f]/.test(input)) {
      throw failure('桥接地址须为完整的 HTTPS 地址或允许的 HTTP 地址。');
    }
    let url;
    try { url = new URL(input); } catch { throw failure('桥接地址或端口无效。'); }
    if (!['http:', 'https:'].includes(url.protocol) || !url.hostname ||
        url.username || url.password || url.pathname !== '/' || url.search || url.hash ||
        (url.port && (!/^\d+$/.test(url.port) || Number(url.port) < 1 || Number(url.port) > 65535))) {
      throw failure('地址只能包含协议、主机和有效端口，不能包含账号、路径、查询或片段。');
    }
    if (url.protocol === 'http:' && !isLoopback(url.hostname) && !isPrivate(url.hostname)) {
      throw failure('HTTP 仅允许回环地址或明确确认过的私网 IP；其他地址请使用 HTTPS。');
    }
    return url;
  }
  async function configuration() {
    const stored = await getStored('config', null);
    if (!stored) return null;
    const url = parseBase(stored.baseUrl);
    if (!validKey(stored.key)) throw failure('专用同步密钥无效，请重新配置。');
    if (url.protocol === 'http:' && !isLoopback(url.hostname) && stored.httpApprovedOrigin !== url.origin) {
      throw failure('私网 HTTP 尚未明确确认，请从菜单重新配置。');
    }
    return { baseUrl: url.origin, key: stored.key, httpApprovedOrigin: stored.httpApprovedOrigin || '' };
  }
  async function configSignature(config) {
    return await sha256(JSON.stringify([config.baseUrl, config.key]));
  }
  async function ensureSameConfiguration(config) {
    const current = await configuration();
    if (!current || current.baseUrl !== config.baseUrl || current.key !== config.key) {
      throw failure('桥接配置已改变，请重新执行操作。');
    }
  }
  async function configure() {
    const old = await getStored('config', null);
    const input = window.prompt('输入桥接服务地址（仅协议、主机和端口）。例如 http://127.0.0.1:8787',
      old && typeof old.baseUrl === 'string' ? old.baseUrl : 'http://127.0.0.1:8787');
    if (input === null) return;
    const url = parseBase(input.trim());
    let approvedOrigin = '';
    if (url.protocol === 'http:' && !isLoopback(url.hostname)) {
      const approved = window.confirm(
        `将通过明文 HTTP 向私网服务 ${url.origin} 发送 Bing Cookie、OAuth code 和专用同步密钥。\n` +
        '请确认该地址属于你控制的可信内网，且服务端已设置 REWARDS_ALLOW_HTTP=1。\n是否明确允许？');
      if (!approved) return;
      approvedOrigin = url.origin;
    }
    const keyInput = window.prompt('输入 REWARDS_SYNC_KEY 专用同步密钥（32 至 1024 个非空白 ASCII 字符）。不要填写青龙管理密钥。');
    if (keyInput === null) return;
    if (!validKey(keyInput)) throw failure('专用同步密钥必须为 32 至 1024 个不含空白的 ASCII 字符。');
    await setStored('config', { baseUrl: url.origin, key: keyInput, httpApprovedOrigin: approvedOrigin });
    await setStored('fingerprint', null);
    await setStored('pending', null);
    retryAuthorization = null;
    notify('桥接配置已保存。其他域名需要在 ScriptCat 中授予连接权限。');
    void synchronizeCookies(false).catch(reportAutomatic);
  }

  function request(details) {
    return new Promise((resolve, reject) => {
      try {
        GM_xmlhttpRequest({
          ...details,
          timeout: 20_000,
          redirect: 'error',
          onload(response) {
            try {
              // 禁止重定向将带密钥的请求转发给另一个地址。
              if (response.finalUrl && new URL(response.finalUrl).href !== new URL(details.url).href) {
                reject(failure('请求发生重定向，已拒绝接受结果，请检查服务地址。'));
                return;
              }
              resolve(response);
            } catch {
              reject(failure('响应地址无效。'));
            }
          },
          onerror() { reject(failure('网络请求失败，请检查桥接服务及 ScriptCat 连接权限。')); },
          ontimeout() { reject(failure('请求超时，请稍后重试。')); },
          onabort() { reject(failure('请求已中止。')); },
        });
      } catch {
        reject(failure('无法发起请求，请检查 ScriptCat 权限。'));
      }
    });
  }
  function responseJson(response, maxLength) {
    try {
      if (typeof response.responseText !== 'string' || response.responseText.length > maxLength) throw new Error();
      const data = JSON.parse(response.responseText);
      if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error();
      return data;
    } catch {
      throw failure('服务返回了无效数据，请检查服务地址和登录状态。');
    }
  }
  async function post(config, route, body) {
    if (!['/sync/cookies', '/sync/oauth'].includes(route)) throw failure('同步接口无效。');
    await ensureSameConfiguration(config);
    const data = JSON.stringify(body);
    if (new TextEncoder().encode(data).length > BODY_LIMIT) throw failure('同步数据超过 512KB，未发送。');
    const response = await request({
      method: 'POST',
      url: config.baseUrl + route,
      anonymous: true,
      headers: { 'Content-Type': 'application/json; charset=utf-8', Authorization: `Bearer ${config.key}` },
      data,
    });
    if (response.status === 401) throw failure('桥接认证失败，请核对专用同步密钥。');
    if (response.status === 409) throw failure('该授权已被服务成功处理，请使用新的授权或确认服务端状态。');
    if (response.status === 429) throw failure('桥接服务繁忙，请稍后重试。');
    if (response.status < 200 || response.status >= 300) throw failure('桥接同步失败，请检查服务端配置或重新授权。');
    if (responseJson(response, 4096).ok !== true) throw failure('桥接服务未确认同步成功。');
  }

  function bingDomain(domain) {
    return typeof domain === 'string' &&
      /^\.?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*bing\.com$/i.test(domain);
  }
  // 兼容层：ScriptCat 的 GM_cookie 是函数，Tampermonkey/Violentmonkey 是对象
  function gmCookieList(options, cb) {
    try {
      if (typeof GM_cookie === 'function') return GM_cookie('list', options, cb);
    } catch (_) {}
    try {
      const api = (typeof GM_cookie !== 'undefined' && GM_cookie)
        || (typeof GM !== 'undefined' && GM && GM.cookie);
      if (api && typeof api.list === 'function') return api.list(options, cb);
    } catch (_) {}
    throw new Error('NO_COOKIE_API');
  }
  function listCookies(options) {
    return new Promise((resolve, reject) => {
      let settled = false;
      const timer = setTimeout(() => finish(null, true), 10_000);
      function finish(cookies, failed) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (failed || !Array.isArray(cookies)) {
          reject(failure('无法读取 Cookie，请确认脚本管理器（ScriptCat/Tampermonkey）已授予 Cookie 权限。'));
        } else {
          resolve(cookies);
        }
      }
      try {
        gmCookieList(options, (cookies, error) => finish(cookies, Boolean(error)));
      } catch {
        finish(null, true);
      }
    });
  }
  function readDocumentCookies() {
    try {
      const raw = String(document.cookie || '');
      if (!raw) return [];
      const host = location.hostname.toLowerCase();
      return raw.split(';').map(function (seg) {
        const i = seg.indexOf('=');
        if (i <= 0) return null;
        return {
          name: seg.slice(0, i).trim(),
          value: seg.slice(i + 1).trim(),
          domain: host,
          path: '/',
          secure: true,
          httpOnly: false,
          hostOnly: true,
        };
      }).filter(Boolean);
    } catch (e) {
      return [];
    }
  }
  async function cookieStats() {
    const out = {};
    const tries = [
      ['domain', { domain: 'bing.com' }],
      ['www', { url: 'https://www.bing.com/' }],
      ['cn', { url: 'https://cn.bing.com/' }],
      ['rewards', { url: 'https://rewards.bing.com/' }],
    ];
    for (const pair of tries) {
      try {
        const list = await new Promise(function (resolve, reject) {
          try {
            gmCookieList(pair[1], function (cookies, error) {
              if (error) reject(error); else resolve(cookies);
            });
          } catch (e) { reject(e); }
        });
        out[pair[0]] = Array.isArray(list) ? list.length : -1;
      } catch (e) {
        out[pair[0]] = 'ERR:' + String(e && e.message ? e.message : e).slice(0, 20);
      }
    }
    out['doc'] = readDocumentCookies().length;
    console.log('[cookieStats]', JSON.stringify(out));
    return out;
  }
  async function collectCookies() {
    // 域查询与 URL 查询合并，兼顾 HttpOnly、hostOnly 和不同子域的 Cookie。
    const results = await Promise.allSettled([
      listCookies({ domain: 'bing.com' }),
      listCookies({ url: 'https://www.bing.com/' }),
      listCookies({ url: 'https://cn.bing.com/' }),
      listCookies({ url: 'https://rewards.bing.com/' }),
    ]);
    const available = results.filter((result) => result.status === 'fulfilled');
    if (!available.length ||
        (!(results[0].status === 'fulfilled' && results[0].value.length > 0) &&
         results.slice(1).some((result) => result.status !== 'fulfilled'))) {
      throw failure('无法完整读取 Bing Cookie，请检查脚本管理器的 Cookie 权限。');
    }
    const unique = new Map();
    for (const result of available) {
      for (const cookie of result.value) {
        if (!cookie || !bingDomain(cookie.domain)) continue;
        if (cookie.expirationDate !== undefined && cookie.expirationDate !== -1 &&
            cookie.expirationDate <= Date.now() / 1000) continue;
        if (typeof cookie.name !== 'string' || typeof cookie.value !== 'string' ||
            typeof cookie.path !== 'string' || !cookie.path.startsWith('/')) {
          throw failure('浏览器返回了不完整的 Cookie，未执行同步。');
        }
        const normalized = {
          name: cookie.name,
          value: cookie.value,
          domain: cookie.domain.toLowerCase(),
          path: cookie.path,
          secure: Boolean(cookie.secure),
          httpOnly: Boolean(cookie.httpOnly),
          hostOnly: typeof cookie.hostOnly === 'boolean' ? cookie.hostOnly : !cookie.domain.startsWith('.'),
        };
        if (typeof cookie.expirationDate === 'number' && Number.isFinite(cookie.expirationDate)) {
          normalized.expirationDate = cookie.expirationDate;
        }
        unique.set(JSON.stringify([normalized.domain, normalized.path, normalized.name]), normalized);
      }
    }
    const cookies = [...unique.values()].sort((a, b) => {
      const left = JSON.stringify([a.domain, a.path, a.name]);
      const right = JSON.stringify([b.domain, b.path, b.name]);
      return left < right ? -1 : left > right ? 1 : 0;
    });
    if (!cookies.length) {
      const fallback = readDocumentCookies();
      console.warn('[collect] GM_cookie 为空，document.cookie 兜底数量=' + fallback.length);
      if (fallback.length) return fallback;
      const st = await cookieStats();
      throw failure('读不到任何 Cookie（GM:' + JSON.stringify(st) + '）');
    }
    return cookies;
  }
  function buildCookieHeader(jar) {
    if (!Array.isArray(jar)) return '';
    const seen = new Map();
    for (const c of jar) {
      if (!c || typeof c.name !== 'string' || typeof c.value !== 'string') continue;
      if (!seen.has(c.name)) seen.set(c.name, c.value);
    }
    return [...seen.entries()].map((p) => p[0] + '=' + p[1]).join('; ');
  }
  function rewardsGet(url) {
    return new Promise((resolve, reject) => {
      try {
        GM_xmlhttpRequest({
          method: 'GET',
          url,
          timeout: 25_000,
          anonymous: false,
          headers: { Accept: 'application/json, text/plain, */*' },
          onload: (r) => resolve(r),
          onerror: () => reject(failure('Rewards 请求在网络层失败（扩展未放行或连接被拒）。')),
          ontimeout: () => reject(failure('Rewards 请求超时。')),
        });
      } catch (e) {
        reject(failure('无法发起 Rewards 请求。'));
      }
    });
  }
  async function verifyDashboardEx(jar) {
    const r = await rewardsGet(USERINFO_URL);
    const body = String(r.responseText || '');
    const isHtml = /^\s*</.test(body);
    console.log('[verify] status=' + r.status + ' len=' + body.length
      + ' html=' + isHtml + ' finalUrl=' + (r.finalUrl || '?'));
    if (r.status !== 200) {
      throw failure('Rewards 返回 HTTP ' + r.status + '，请确认浏览器已登录 Bing。');
    }
    if (isHtml) {
      throw failure('Rewards 返回了网页而不是数据，说明请求未携带登录 Cookie。');
    }
    let d;
    try { d = JSON.parse(body); } catch (_) {
      throw failure('Rewards 返回内容不是 JSON。');
    }
    if (!d || typeof d !== 'object') throw failure('Rewards 响应格式异常。');
    if (!d.dashboard || typeof d.dashboard !== 'object' || Array.isArray(d.dashboard)) {
      const keys = Object.keys(d).slice(0, 8).join('|') || '(空)';
      throw failure('未检测到 dashboard（响应字段: ' + keys + '）。');
    }
    return d;
  }
  async function synchronizeCookies(manual) {
    if (cookieBusy) {
      if (manual) notify('Cookie 同步正在进行，请稍后重试。');
      return;
    }
    cookieBusy = true;
    try {
      const config = await configuration();
      if (!config) {
        if (manual) notify('请先从菜单配置桥接地址和专用同步密钥。');
        return;
      }
      const cookies = await collectCookies();
      let verifyWarn = '';
      try {
        await verifyDashboardEx(cookies);
      } catch (e) {
        verifyWarn = safeMessage(e);
        console.warn('[sync] 登录校验未通过，仍先上传 Cookie：' + verifyWarn);
      }
      const userAgent = navigator.userAgent;
      const signature = await configSignature(config);
      const fingerprint = await sha256(JSON.stringify({ cookies, userAgent }));
      const previous = await getStored('fingerprint', null);
      if (!manual && previous && previous.destination === signature && previous.value === fingerprint &&
          Date.now() - Number(previous.syncedAt || 0) < 60 * 60_000) return;
      await post(config, '/sync/cookies', { cookies, userAgent });
      await ensureSameConfiguration(config);
      await setStored('fingerprint', { destination: signature, value: fingerprint, syncedAt: Date.now() });
      if (manual) {
        notify(verifyWarn
          ? ('Cookie 已上传，但登录校验未通过：' + verifyWarn)
          : 'Bing Cookie 已同步，登录有效。');
      }
    } finally {
      cookieBusy = false;
    }
  }

  async function beginAuthorization() {
    const config = await configuration();
    if (!config) throw failure('请先从菜单配置桥接地址和专用同步密钥。');
    if (oauthBusy) throw failure('授权同步正在进行，请稍后重试。');
    const state = randomState();
    await setStored('pending', { state, createdAt: Date.now(), destination: await configSignature(config) });
    retryAuthorization = null;
    const url = new URL('https://login.live.com/oauth20_authorize.srf');
    url.searchParams.set('client_id', CLIENT_ID);
    url.searchParams.set('scope', SCOPE);
    url.searchParams.set('redirect_uri', REDIRECT_URI);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('state', state);
    try {
      GM_openInTab(url.href, { active: true, insert: true, setParent: true });
    } catch {
      await setStored('pending', null);
      throw failure('无法打开授权页面，请检查 ScriptCat 的 GM_openInTab 权限。');
    }
  }
  function captureCallback() {
    if (location.origin !== 'https://login.live.com' || location.pathname !== '/oauth20_desktop.srf') return null;
    const url = new URL(location.href);
    const params = url.searchParams;
    if (!['code', 'state', 'error', 'error_description'].some((name) => params.has(name))) return null;
    const callback = {
      code: params.get('code'),
      state: params.get('state'),
      invalid: params.getAll('code').length > 1 || params.getAll('state').length > 1 || params.has('error'),
      cleaned: false,
    };
    for (const key of ['code', 'state', 'error', 'error_description']) params.delete(key);
    try {
      history.replaceState(null, '', url.pathname + url.search + url.hash);
      callback.cleaned = true;
    } catch {
      // 地址清理失败时保留内存中的数据，不向日志输出地址或异常。
    }
    return callback;
  }
  function validPending(pending) {
    return pending && typeof pending.state === 'string' && /^[a-f0-9]{64}$/.test(pending.state) &&
      typeof pending.createdAt === 'number' && Number.isFinite(pending.createdAt) &&
      Date.now() >= pending.createdAt && Date.now() - pending.createdAt <= PENDING_TTL;
  }
  async function submitAuthorization() {
    if (oauthBusy) throw failure('授权同步正在进行，请稍后重试。');
    if (!retryAuthorization) throw failure('当前页面没有可重试的授权，请重新发起 App 授权。');
    oauthBusy = true;
    try {
      const captured = retryAuthorization;
      const pending = await getStored('pending', null);
      const config = await configuration();
      if (!config || !validPending(pending) || pending.state !== captured.state ||
          pending.destination !== await configSignature(config)) {
        retryAuthorization = null;
        throw failure('授权已过期或状态不匹配，请重新发起 App 授权。');
      }
      await post(config, '/sync/oauth', { code: captured.code });
      // 成功后才删除 pending；失败时 code 仅留在本页内存，菜单可重试。
      const current = await getStored('pending', null);
      if (current && current.state === captured.state) await setStored('pending', null);
      retryAuthorization = null;
      notify('App 授权已同步，后续令牌刷新由服务端处理。');
    } finally {
      oauthBusy = false;
    }
  }
  async function handleCallback(callback) {
    if (!callback) return;
    if (!callback.cleaned) {
      retryAuthorization = null;
      throw failure('无法清理授权回调地址，请关闭此页并重新发起授权。');
    }
    if (callback.invalid || typeof callback.code !== 'string' || callback.code.length < 1 ||
        callback.code.length > 4096 || /[\x00-\x20\x7f]/.test(callback.code) ||
        typeof callback.state !== 'string' || !/^[a-f0-9]{64}$/.test(callback.state)) {
      throw failure('授权回调无效或授权已取消，请重新发起 App 授权。');
    }
    const pending = await getStored('pending', null);
    const config = await configuration();
    if (!config || !validPending(pending) || pending.state !== callback.state ||
        pending.destination !== await configSignature(config)) {
      throw failure('授权状态不匹配或已超过 10 分钟，已拒绝提交。');
    }
    retryAuthorization = { code: callback.code, state: callback.state };
    try {
      await submitAuthorization();
    } catch (error) {
      notify(`${safeMessage(error)} 若尚未成功，可保持本页打开并使用“重试本页 App 授权同步”菜单；刷新后请重新授权。`);
    } finally {
      callback.code = null;
    }
  }
  function menu(label, action) {
    GM_registerMenuCommand(label, () => {
      Promise.resolve().then(action).catch((error) => notify(safeMessage(error)));
    });
  }

  // 最早捕获并清除敏感查询参数，随后才读取存储、发请求或显示通知。
  const callback = captureCallback();
  menu('配置桥接 URL 和专用同步密钥', configure);
  menu('① 测试桥接连接', async () => {
    const config = await configuration();
    if (!config) throw failure('尚未配置桥接地址或密钥，请先执行配置。');
    const r = await request({ method: 'GET', url: config.baseUrl + '/health' });
    if (r.status !== 200) throw failure('桥接返回 HTTP ' + r.status + '，请检查反代配置。');
    notify('桥接连通：' + String(r.responseText || '').slice(0, 60));
  });
  menu('② 查看当前配置', async () => {
    const c = await getStored('config', null);
    const hasCookieApi = (typeof GM_cookie === 'function')
      || (typeof GM_cookie !== 'undefined' && GM_cookie && typeof GM_cookie.list === 'function')
      || (typeof GM !== 'undefined' && GM && GM.cookie);
    notify('地址:' + (c && c.baseUrl ? c.baseUrl : '未配置')
      + ' 密钥位数:' + (c && c.key ? c.key.length : 0)
      + ' Cookie接口:' + (hasCookieApi ? '可用' : '不可用'));
  });
  menu('③ 诊断 Cookie 读取', async () => {
    const st = await cookieStats();
    const text = Object.keys(st).map(function (k) { return k + '=' + st[k]; }).join(' | ');
    notify(text.slice(0, 200));
  });
  menu('④ 测试 Rewards 登录态', async () => {
    try {
      const jars = await Promise.allSettled([
        listCookies({ url: 'https://rewards.bing.com/' }),
        listCookies({ url: 'https://www.bing.com/' }),
        listCookies({ url: 'https://cn.bing.com/' }),
        listCookies({ domain: 'bing.com' }),
      ]);
      await verifyDashboardEx(null);
      notify('Rewards 登录有效');
    } catch (e) {
      notify('登录态失败: ' + safeMessage(e));
    }
  });
  menu('⑤ 完整同步并显示错误', async () => {
    try {
      await synchronizeCookies(true);
      notify('同步完成');
    } catch (e) {
      notify('失败原因: ' + safeMessage(e));
    }
  });
  menu('⑥ 查看 Rewards API 原始响应', async () => {
    let r;
    try {
      r = await request({ method: 'GET', url: USERINFO_URL, anonymous: false, headers: { Accept: 'application/json' } });
    } catch (e) {
      console.warn('[diag] request threw:', safeMessage(e));
      notify('请求异常: ' + safeMessage(e));
      return;
    }
    const body = String(r.responseText || '');
    console.log('[diag] status=' + r.status + ' finalUrl=' + r.finalUrl + ' len=' + body.length);
    console.log('[diag] head=' + body.slice(0, 400));
    let shape = 'nonJSON';
    try {
      const d = JSON.parse(body);
      shape = 'keys=' + Object.keys(d).slice(0, 10).join('|');
      if (d.dashboard && typeof d.dashboard === 'object') {
        shape += ' DASH_KEYS=' + Object.keys(d.dashboard).slice(0, 8).join('|');
      } else {
        shape += ' NO_DASHBOARD';
      }
    } catch (_) {}
    notify('status=' + r.status + ' len=' + body.length + ' ' + shape);
  });
  menu('⑧ 列出 Cookie 名称（诊断登录态）', async () => {
    const tries = [
      ['domain', { domain: 'bing.com' }],
      ['www', { url: 'https://www.bing.com/' }],
      ['cn', { url: 'https://cn.bing.com/' }],
      ['rewards', { url: 'https://rewards.bing.com/' }],
    ];
    const all = new Set();
    const per = {};
    for (const pair of tries) {
      try {
        const list = await new Promise(function (resolve, reject) {
          try {
            gmCookieList(pair[1], function (cookies, error) {
              if (error) reject(error); else resolve(cookies);
            });
          } catch (e) { reject(e); }
        });
        const names = (Array.isArray(list) ? list : []).map(function (c) { return c && c.name; }).filter(Boolean);
        per[pair[0]] = names.length;
        names.forEach(function (n) { all.add(n); });
      } catch (e) {
        per[pair[0]] = 'ERR';
      }
    }
    const need = ['RPSSecAuth', 'MSPAuth', 'MSPProf', 'NAP', 'MUID', '_U', 'ANON', '_EDGE_S'];
    const have = need.filter(function (n) { return all.has(n); });
    const miss = need.filter(function (n) { return !all.has(n); });
    console.log('[cookies] total=' + all.size + ' per=' + JSON.stringify(per));
    console.log('[cookies] have=' + have.join(','));
    console.log('[cookies] MISSING=' + miss.join(','));
    console.log('[cookies] names=' + [...all].sort().join(','));
    notify('共' + all.size + '个 | 有:' + (have.join(',') || '无')
      + ' | 缺:' + (miss.join(',') || '无'));
  });
  menu('⑨ 全域 Cookie 详查', async () => {
    const targets = ['RPSSecAuth', 'MSPAuth', 'MSPProf', 'NAP'];
    const domains = [
      'https://bing.com/',
      'https://rewards.bing.com/',
      'https://login.live.com/',
      'https://account.microsoft.com/',
      'https://www.microsoft.com/',
    ];
    const found = {};
    for (const d of domains) {
      try {
        const list = await new Promise(function (resolve, reject) {
          try {
            gmCookieList({ url: d }, function (cookies, error) {
              if (error) reject(error); else resolve(cookies);
            });
          } catch (e) { reject(e); }
        });
        if (!Array.isArray(list)) continue;
        for (const c of list) {
          if (!c || !c.name) continue;
          if (targets.indexOf(c.name) < 0) continue;
          const key = c.name;
          if (!found[key]) found[key] = [];
          found[key].push((c.domain || '?') + (c.httpOnly ? '[H]' : '') + (c.secure ? '[S]' : ''));
        }
      } catch (e) {}
    }
    const lines = [];
    for (const t of targets) {
      lines.push(t + '=' + (found[t] ? found[t].join(',') : '不存在'));
    }
    console.log('[allCookie] ' + lines.join(' || '));
    notify(lines.join(' | ').slice(0, 220));
  });
  menu('⑩ 粘贴 Cookie 头导入（含HttpOnly）', async () => {
    const raw = window.prompt('粘贴完整 Cookie 头\n（F12 → Network → 点 rewards.bing.com 的请求 → Request Headers → Cookie 整行的值）');
    if (raw === null) return;
    const text = String(raw).trim().replace(/^Cookie:\s*/i, '');
    if (!text) throw failure('内容为空，未导入。');
    const pairs = text.split(';');
    const cookies = [];
    const seen = new Set();
    for (const seg of pairs) {
      const t = seg.trim();
      if (!t) continue;
      const i = t.indexOf('=');
      if (i <= 0) continue;
      const name = t.slice(0, i).trim();
      const value = t.slice(i + 1).trim();
      if (!name || /[\s;]/.test(name)) continue;
      if (seen.has(name)) continue;
      seen.add(name);
      cookies.push({
        name: name,
        value: value,
        domain: '.bing.com',
        path: '/',
        secure: true,
        httpOnly: false,
        hostOnly: false,
      });
    }
    if (!cookies.length) throw failure('未解析出任何 Cookie，请确认复制的是 Cookie 头。');
    const config = await configuration();
    if (!config) throw failure('请先配置桥接地址与密钥。');
    await post(config, '/sync/cookies', { cookies: cookies, userAgent: navigator.userAgent });
    const names = cookies.map(function (c) { return c.name; });
    const need = ['RPSSecAuth', 'MSPAuth', 'MSPProf', 'NAP'];
    const hit = need.filter(function (n) { return names.indexOf(n) >= 0; });
    console.log('[import] total=' + cookies.length + ' hit=' + hit.join(','));
    notify('已导入 ' + cookies.length + ' 条，含关键项: ' + (hit.join(',') || '无'));
  });
  menu('立即同步 Bing Cookie', () => synchronizeCookies(true));
  menu('首次 / 重新授权 Rewards App', beginAuthorization);
  menu('重试本页 App 授权同步', submitAuthorization);
  void handleCallback(callback).catch((error) => notify(safeMessage(error)));
  if (/^(?:www|cn|rewards)\.bing\.com$/.test(location.hostname)) {
    const automatic = () => { void synchronizeCookies(false).catch(reportAutomatic); };
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', automatic, { once: true });
    } else {
      automatic();
    }
    setInterval(automatic, INTERVAL);
  }
})();
