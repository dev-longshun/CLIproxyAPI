package api

import (
	"bytes"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const managementAPIKeysNavPatchVersionMarker = "cpa-managed-apikey-nav-v8"

const managementAPIKeysNavPatch = `<script>/*cpa-managed-apikey-nav-v8*/(function(){
  var ENTRY_ID = 'cpa-managed-apikey-nav-entry';
  var PANEL_ID = 'cpa-managed-apikey-panel';
  var STYLE_ID = 'cpa-managed-apikey-style-v8';
  var ROUTE_HASH = '#/config?tab=api-keys';
  var HIDDEN_ATTR = 'data-cpa-main-hidden';
  var LEGACY_HIDDEN_ATTR = 'data-cpa-managed-apikey-hidden';
  var APP_BOOTED_ATTR = 'data-cpa-app-booted';
  var TOKEN_CACHE_KEY = 'cpa_management_key_cache';

  function norm(v){ return String(v || '').replace(/\s+/g, '').toLowerCase(); }
  function isObject(v){ return v && typeof v === 'object'; }
  function now(){ return Date.now(); }

  function normalizeToken(raw){
    if (!raw) return '';
    var token = String(raw).trim();
    if (!token) return '';
    if (/^bearer\s+/i.test(token)) token = token.replace(/^bearer\s+/i, '').trim();
    if (!token || token.length < 6 || token.length > 512) return '';
    return token;
  }

  function rememberAuth(raw){
    var token = normalizeToken(raw);
    if (!token) return '';
    window.__CPA_MANAGEMENT_AUTH__ = token;
    try { localStorage.setItem(TOKEN_CACHE_KEY, token); } catch (_) {}
    return token;
  }

  function parseAuthHeaderValue(value){
    if (!value) return '';
    return normalizeToken(value);
  }

  function headersToAuth(headers){
    if (!headers) return '';
    try {
      if (typeof headers.get === 'function') return parseAuthHeaderValue(headers.get('Authorization'));
    } catch (_) {}

    if (Array.isArray(headers)) {
      for (var i = 0; i < headers.length; i++) {
        var item = headers[i];
        if (!item || item.length < 2) continue;
        if (String(item[0]).toLowerCase() === 'authorization') return parseAuthHeaderValue(item[1]);
      }
      return '';
    }

    if (typeof headers === 'object') {
      var keys = Object.keys(headers);
      for (var j = 0; j < keys.length; j++) {
        var k = keys[j];
        if (String(k).toLowerCase() === 'authorization') return parseAuthHeaderValue(headers[k]);
      }
    }
    return '';
  }

  function installAuthSniffer(){
    if (window.__CPA_AUTH_SNIFFER_INSTALLED__) return;
    window.__CPA_AUTH_SNIFFER_INSTALLED__ = true;

    rememberAuth(window.__CPA_MANAGEMENT_AUTH__);
    try { rememberAuth(localStorage.getItem(TOKEN_CACHE_KEY)); } catch (_) {}

    var rawFetch = window.fetch;
    if (typeof rawFetch === 'function') {
      window.fetch = function(input, init){
        var token = '';
        if (init && init.headers) token = headersToAuth(init.headers);
        if (!token && input && typeof input === 'object' && input.headers) token = headersToAuth(input.headers);
        if (token) rememberAuth(token);
        return rawFetch.apply(this, arguments);
      };
    }

    var xhrProto = window.XMLHttpRequest && window.XMLHttpRequest.prototype;
    if (xhrProto && typeof xhrProto.setRequestHeader === 'function') {
      var rawSetRequestHeader = xhrProto.setRequestHeader;
      xhrProto.setRequestHeader = function(name, value){
        if (name && String(name).toLowerCase() === 'authorization') rememberAuth(value);
        return rawSetRequestHeader.apply(this, arguments);
      };
    }
  }

  function addCandidate(map, value, score){
    var token = normalizeToken(value);
    if (!token) return;
    var prev = map.get(token);
    if (!prev || score > prev) map.set(token, score);
  }

  function scanValue(map, value, score){
    if (!value) return;
    if (typeof value === 'string') {
      addCandidate(map, value, score);
      var trimmed = value.trim();
      if (trimmed.length > 2 && trimmed.length < 12000 && (trimmed[0] === '{' || trimmed[0] === '[')) {
        try {
          var parsed = JSON.parse(trimmed);
          scanValue(map, parsed, score - 1);
        } catch (_) {}
      }
      return;
    }
    if (!isObject(value)) return;

    var stack = [value];
    var hops = 0;
    while (stack.length > 0 && hops < 120) {
      hops++;
      var node = stack.pop();
      if (typeof node === 'string') {
        addCandidate(map, node, score - 1);
        continue;
      }
      if (!isObject(node)) continue;
      var keys = Object.keys(node);
      for (var i = 0; i < keys.length; i++) {
        var sub = node[keys[i]];
        if (typeof sub === 'string') addCandidate(map, sub, score - 2);
        else if (isObject(sub)) stack.push(sub);
      }
    }
  }

  function collectTokenCandidates(){
    var map = new Map();
    addCandidate(map, window.__CPA_MANAGEMENT_AUTH__, 1000);
    try { addCandidate(map, localStorage.getItem(TOKEN_CACHE_KEY), 990); } catch (_) {}

    var stores = [];
    try { stores.push(localStorage); } catch (_) {}
    try { stores.push(sessionStorage); } catch (_) {}

    var hints = ['manage', 'token', 'auth', 'password', 'secret', 'key'];
    for (var s = 0; s < stores.length; s++) {
      var storage = stores[s];
      if (!storage) continue;
      for (var idx = 0; idx < storage.length; idx++) {
        var key = '';
        try { key = storage.key(idx) || ''; } catch (_) { key = ''; }
        if (!key) continue;
        var score = 200;
        var keyLower = key.toLowerCase();
        for (var h = 0; h < hints.length; h++) {
          if (keyLower.indexOf(hints[h]) >= 0) score += 100;
        }
        var value = '';
        try { value = storage.getItem(key) || ''; } catch (_) { value = ''; }
        scanValue(map, value, score);
      }
    }

    return Array.from(map.entries())
      .sort(function(a, b){ return b[1] - a[1]; })
      .map(function(item){ return item[0]; })
      .slice(0, 80);
  }

  async function probeToken(token){
    var t = normalizeToken(token);
    if (!t) return false;
    try {
      var resp = await fetch('/v0/management/server-info', {
        method: 'GET',
        headers: { Authorization: 'Bearer ' + t }
      });
      if (!resp.ok) return false;
      rememberAuth(t);
      return true;
    } catch (_) {
      return false;
    }
  }

  async function ensureToken(){
    var direct = normalizeToken(window.__CPA_MANAGEMENT_AUTH__);
    if (direct && await probeToken(direct)) return direct;

    var candidates = collectTokenCandidates();
    for (var i = 0; i < candidates.length; i++) {
      if (await probeToken(candidates[i])) return normalizeToken(window.__CPA_MANAGEMENT_AUTH__);
    }
    return '';
  }

  function isApiKeysRoute(){
    var hash = String(window.location.hash || '');
    if (hash.indexOf('#/config') !== 0) return false;
    return /(?:[?&])tab=api-keys(?:&|$)/i.test(hash);
  }

  function getNavSection(){ return document.querySelector('.nav-section'); }

  function navIconSVG(){
    return '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true" focusable="false"><path d="M15 7a5 5 0 1 0-8.66 3.46L3 13.8V17h3.2l.8-.8V14h2v-2h2.2l1.34-1.34A5 5 0 0 0 15 7Z" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><circle cx="10" cy="7" r="1" fill="currentColor"/></svg>';
  }

  function findOrCreateNavEntry(nav){
    var items = nav.querySelectorAll('.nav-item');
    var firstMatched = null;
    for (var i = 0; i < items.length; i++) {
      var text = norm(items[i].textContent);
      if (text.indexOf('api密钥管理') === -1) continue;
      if (!firstMatched) {
        firstMatched = items[i];
      } else if (items[i].parentElement) {
        items[i].parentElement.removeChild(items[i]);
      }
    }

    var entry = nav.querySelector('#' + ENTRY_ID) || firstMatched;
    if (!entry) {
      var base = nav.querySelector('.nav-item');
      entry = document.createElement('a');
      entry.className = base ? String(base.className).replace(/\bactive\b/g, '').trim() : 'nav-item';
      if (!entry.className) entry.className = 'nav-item';
      nav.appendChild(entry);
    }

    entry.id = ENTRY_ID;
    entry.href = ROUTE_HASH;
    entry.className = String(entry.className || 'nav-item').replace(/\bactive\b/g, '').trim();
    if (!entry.className) entry.className = 'nav-item';
    entry.innerHTML = '<span class="nav-icon">' + navIconSVG() + '</span><span class="nav-label">API 密钥管理</span>';
    entry.onclick = function(e){
      e.preventDefault();
      if (window.location.hash !== ROUTE_HASH) window.location.hash = ROUTE_HASH;
      else scheduleApply();
    };

    if (isApiKeysRoute()) entry.classList.add('active');
    else entry.classList.remove('active');
    return entry;
  }

  function ensureNavEntry(){
    var nav = getNavSection();
    if (!nav) return null;

    var oldFloat = document.getElementById('cpa-managed-apikey-nav-float');
    if (oldFloat && oldFloat.parentElement) oldFloat.parentElement.removeChild(oldFloat);

    var ids = nav.querySelectorAll('#' + ENTRY_ID);
    for (var i = 1; i < ids.length; i++) {
      if (ids[i] && ids[i].parentElement) ids[i].parentElement.removeChild(ids[i]);
    }

    return findOrCreateNavEntry(nav);
  }

  function getMainContent(){
    return document.querySelector('.main-content') || document.querySelector('.content');
  }

  function injectStyle(){
    if (document.getElementById(STYLE_ID)) return;
    var style = document.createElement('style');
    style.id = STYLE_ID;
    style.textContent = [
      '.cpa-ak-page{display:none;width:100%;min-height:calc(100vh - 190px);}',
      '.cpa-ak-wrap{color:var(--text-primary,#e2ecff);padding:12px;font-family:ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;}',
      '.cpa-ak-card{border:1px solid var(--border-color,#2a3a56);background:linear-gradient(180deg,#0b1628 0%,#081222 100%);border-radius:12px;box-shadow:0 10px 30px rgba(0,0,0,.22);}',
      '.cpa-ak-service{padding:14px;margin-bottom:12px;}',
      '.cpa-ak-service-title{margin:0 0 12px;font-size:16px;font-weight:700;color:#dce7fd;}',
      '.cpa-ak-row{display:grid;grid-template-columns:1fr auto;gap:8px;align-items:center;padding:10px 0;border-top:1px dashed rgba(90,110,145,.35);}',
      '.cpa-ak-row:first-of-type{border-top:0;}',
      '.cpa-ak-k{color:var(--text-secondary,#8da0c2);font-size:12px;margin-bottom:3px;}',
      '.cpa-ak-v{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Courier New",monospace;font-size:14px;word-break:break-all;color:var(--text-primary,#e2ecff);}',
      '.cpa-ak-copy{border:1px solid rgba(90,110,145,.35);background:rgba(21,35,62,.78);color:#b5c6e7;border-radius:8px;width:34px;height:32px;cursor:pointer;}',
      '.cpa-ak-status{margin-top:8px;font-size:13px;white-space:pre-wrap;}',
      '.cpa-ak-status.ok{color:#95e3b8;}',
      '.cpa-ak-status.err{color:#ff9f9f;}',
      '.cpa-ak-head{margin:8px 0 10px;display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap;}',
      '.cpa-ak-head h2{margin:0;font-size:30px;font-weight:700;letter-spacing:.3px;color:var(--text-primary,#e2ecff);}',
      '.cpa-ak-actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center;}',
      '.cpa-ak-chip{border:1px solid rgba(90,110,145,.35);background:rgba(22,36,62,.85);color:#c8d5f0;border-radius:10px;padding:8px 12px;font-size:13px;cursor:pointer;}',
      '.cpa-ak-chip.active{border-color:#4e6ea3;color:#ecf2ff;background:rgba(35,64,116,.6);}',
      '.cpa-ak-btn{border:1px solid rgba(90,110,145,.45);background:linear-gradient(180deg,#0f1f37 0%,#0b172a 100%);color:#e2ecff;border-radius:10px;padding:8px 12px;cursor:pointer;font-size:13px;line-height:1;}',
      '.cpa-ak-btn.primary{border-color:#2b6df6;background:linear-gradient(180deg,#1f3e7a 0%,#173463 100%);}',
      '.cpa-ak-btn.success{border-color:#2d8f5a;background:linear-gradient(180deg,#1d4d38 0%,#153728 100%);}',
      '.cpa-ak-create-overlay{position:fixed;inset:0;display:none;align-items:center;justify-content:center;padding:20px;background:rgba(4,9,18,.72);backdrop-filter:blur(2px);z-index:1200;}',
      '.cpa-ak-create-overlay.open{display:flex;}',
      '.cpa-ak-create-dialog{position:relative;width:min(620px,calc(100vw - 28px));padding:18px 18px 14px;border:1px solid var(--border-color,#2a3a56);border-radius:14px;background:linear-gradient(180deg,#0b1628 0%,#081222 100%);box-shadow:0 20px 60px rgba(0,0,0,.45);}',
      '.cpa-ak-create-title{margin:0;font-size:30px;font-weight:700;letter-spacing:.2px;color:var(--text-primary,#e2ecff);}',
      '.cpa-ak-create-desc{margin:6px 0 14px;color:var(--text-secondary,#8da0c2);font-size:13px;}',
      '.cpa-ak-create-close{position:absolute;top:10px;right:10px;width:30px;height:30px;border:1px solid rgba(90,110,145,.45);border-radius:8px;background:rgba(17,29,52,.9);color:#b8c9e8;cursor:pointer;font-size:18px;line-height:1;}',
      '.cpa-ak-form-grid{display:grid;grid-template-columns:1fr;gap:10px;}',
      '.cpa-ak-field{display:flex;flex-direction:column;gap:6px;}',
      '.cpa-ak-field label{color:var(--text-secondary,#8da0c2);font-size:12px;}',
      '.cpa-ak-field input,.cpa-ak-field select{border:1px solid var(--border-color,#2a3a56);background:#091325;color:var(--text-primary,#e2ecff);border-radius:9px;padding:9px 10px;font-size:13px;width:100%;}',
      '.cpa-ak-mode-switch{display:inline-flex;gap:6px;padding:4px;border:1px solid rgba(90,110,145,.35);border-radius:10px;background:rgba(9,18,36,.75);}',
      '.cpa-ak-mode-btn{border:0;border-radius:8px;padding:7px 12px;background:transparent;color:#9fb3d8;font-size:13px;cursor:pointer;}',
      '.cpa-ak-mode-btn.active{background:rgba(35,64,116,.75);color:#eff4ff;}',
      '.cpa-ak-day-quick{display:flex;gap:8px;flex-wrap:wrap;}',
      '.cpa-ak-day-chip{border:1px solid rgba(90,110,145,.4);background:rgba(14,25,44,.75);color:#c8d5f0;border-radius:8px;padding:6px 10px;font-size:13px;cursor:pointer;}',
      '.cpa-ak-day-chip.active{border-color:#4e6ea3;background:rgba(35,64,116,.65);color:#f1f5ff;}',
      '.cpa-ak-day-input-row{margin-top:8px;display:flex;align-items:center;gap:8px;}',
      '.cpa-ak-day-input-row input{max-width:110px;}',
      '.cpa-ak-day-hint{margin-top:6px;color:#8ea4cc;font-size:12px;}',
      '.cpa-ak-create-foot{margin-top:10px;display:flex;justify-content:flex-end;gap:8px;flex-wrap:wrap;}',
      '.cpa-ak-list{display:grid;gap:10px;margin-bottom:8px;}',
      '.cpa-ak-item{border:1px solid var(--border-color,#2a3a56);border-radius:10px;background:linear-gradient(180deg,#091424 0%,#08101d 100%);padding:12px;display:grid;grid-template-columns:1fr auto;gap:10px;align-items:center;}',
      '.cpa-ak-item-main{min-width:0;}',
      '.cpa-ak-item-line{display:flex;align-items:center;gap:8px;flex-wrap:wrap;}',
      '.cpa-ak-item-name{font-size:17px;font-weight:650;letter-spacing:.2px;color:var(--text-primary,#e2ecff);}',
      '.cpa-ak-badge{font-size:11px;line-height:1;border:1px solid rgba(90,110,145,.45);border-radius:999px;padding:4px 8px;color:#b9c8e3;}',
      '.cpa-ak-badge.active{border-color:#2f9861;color:#90e2b3;}',
      '.cpa-ak-badge.pending{border-color:#a67f25;color:#f1cf7f;}',
      '.cpa-ak-badge.disabled{border-color:#5f6d88;color:#b8c3d8;}',
      '.cpa-ak-badge.expired,.cpa-ak-badge.quota_reached{border-color:#9f4f4f;color:#f3abab;}',
      '.cpa-ak-item-key{margin-top:4px;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Courier New",monospace;color:#93abd4;font-size:13px;}',
      '.cpa-ak-item-meta{margin-top:5px;color:var(--text-secondary,#8da0c2);font-size:12px;line-height:1.5;word-break:break-word;}',
      '.cpa-ak-item-usage{margin-top:6px;color:#7f93b9;font-size:12px;line-height:1.4;}',
      '.cpa-ak-item-side{display:flex;gap:8px;align-items:center;justify-content:flex-end;flex-wrap:wrap;}',
      '.cpa-ak-icon-btn{width:32px;height:32px;border:1px solid rgba(90,110,145,.35);border-radius:8px;background:rgba(18,33,58,.8);color:#b3c3e3;cursor:pointer;}',
      '.cpa-ak-icon-btn.copied{border-color:#2f9861;color:#90e2b3;background:rgba(18,65,45,.7);}',
      '.cpa-ak-icon-btn.delete{border-color:#6f3333;color:#d88d8d;background:rgba(69,27,27,.7);}',
      '.cpa-ak-switch{position:relative;display:inline-block;width:44px;height:24px;}',
      '.cpa-ak-switch input{opacity:0;width:0;height:0;}',
      '.cpa-ak-slider{position:absolute;cursor:pointer;inset:0;border-radius:999px;border:1px solid #3b4a65;background:#1a2a45;transition:.2s;}',
      '.cpa-ak-slider:before{content:"";position:absolute;width:18px;height:18px;left:2px;top:2px;border-radius:50%;background:#b9c6de;transition:.2s;}',
      '.cpa-ak-switch input:checked + .cpa-ak-slider{background:#123d7c;border-color:#2b6df6;}',
      '.cpa-ak-switch input:checked + .cpa-ak-slider:before{transform:translateX(19px);background:#e6efff;}',
      '.cpa-ak-empty{border:1px dashed rgba(90,110,145,.45);border-radius:10px;padding:18px;color:var(--text-secondary,#8da0c2);font-size:13px;text-align:center;}',
      '@media (max-width:1024px){.cpa-ak-create-dialog{width:min(620px,calc(100vw - 22px));padding:16px 14px 12px;}}',
      '@media (max-width:820px){.cpa-ak-item{grid-template-columns:1fr;}.cpa-ak-item-side{justify-content:flex-start;}.cpa-ak-head h2{font-size:24px;}}'
    ].join('');
    document.head.appendChild(style);
  }

  function buildPanelSkeleton(panel){
    panel.innerHTML = [
      '<div class="cpa-ak-wrap">',
      '  <div class="cpa-ak-card cpa-ak-service">',
      '    <h3 class="cpa-ak-service-title">服务连接信息</h3>',
      '    <div class="cpa-ak-row">',
      '      <div><div class="cpa-ak-k">API Base URL</div><div class="cpa-ak-v" data-id="baseURL">-</div></div>',
      '      <button class="cpa-ak-copy" data-id="copyBase" title="复制 Base URL">⧉</button>',
      '    </div>',
      '    <div class="cpa-ak-row">',
      '      <div><div class="cpa-ak-k">主 API Key</div><div class="cpa-ak-v" data-id="masterKey">-</div></div>',
      '      <button class="cpa-ak-copy" data-id="copyMaster" title="复制主 API Key">⧉</button>',
      '    </div>',
      '    <div class="cpa-ak-status ok" data-id="ok"></div>',
      '    <div class="cpa-ak-status err" data-id="err"></div>',
      '    <div class="cpa-ak-actions" style="margin-top:8px">',
      '      <button class="cpa-ak-btn" data-id="refresh">刷新</button>',
      '      <button class="cpa-ak-btn" data-id="rediscover">重新识别会话</button>',
      '    </div>',
      '  </div>',
      '',
      '  <div class="cpa-ak-head">',
      '    <h2>API Key 管理</h2>',
      '    <div class="cpa-ak-actions">',
      '      <button class="cpa-ak-chip active" data-id="sortLatest">最新</button>',
      '      <button class="cpa-ak-chip" data-id="sortUsageDesc">费用↓</button>',
      '      <button class="cpa-ak-chip" data-id="sortUsageAsc">费用↑</button>',
      '      <button class="cpa-ak-btn primary" data-id="openCreate">+ 创建 Key</button>',
      '    </div>',
      '  </div>',
      '',
      '  <div class="cpa-ak-create-overlay" data-id="createPanel">',
      '    <div class="cpa-ak-create-dialog" data-id="createDialog" role="dialog" aria-modal="true" aria-label="创建 API Key">',
      '      <button class="cpa-ak-create-close" data-id="closeCreate" title="关闭">×</button>',
      '      <h3 class="cpa-ak-create-title">创建 API Key</h3>',
      '      <div class="cpa-ak-create-desc">为用户创建一个新的 API Key</div>',
      '      <div class="cpa-ak-form-grid">',
      '        <div class="cpa-ak-field">',
      '          <label>备注名称</label>',
      '          <input data-id="createName" placeholder="例如：闭鱼-李搞定" />',
      '        </div>',
      '        <div class="cpa-ak-field">',
      '          <label>限制模式</label>',
      '          <div class="cpa-ak-mode-switch">',
      '            <button type="button" class="cpa-ak-mode-btn" data-id="modeDate">按日期</button>',
      '            <button type="button" class="cpa-ak-mode-btn" data-id="modeQuota">按额度</button>',
      '          </div>',
      '        </div>',
      '        <div class="cpa-ak-field" data-id="datePresetField">',
      '          <label>有效期</label>',
      '          <div class="cpa-ak-day-quick" data-id="createDayQuick">',
      '            <button type="button" class="cpa-ak-day-chip" data-days="1">1 天</button>',
      '            <button type="button" class="cpa-ak-day-chip" data-days="3">3 天</button>',
      '            <button type="button" class="cpa-ak-day-chip" data-days="7">7 天</button>',
      '            <button type="button" class="cpa-ak-day-chip" data-days="never">永不过期</button>',
      '          </div>',
      '          <div class="cpa-ak-day-input-row" data-id="createDayInputRow">',
      '            <input type="number" min="1" step="1" data-id="createDayInput" value="1" />',
      '            <span>天</span>',
      '          </div>',
      '          <div class="cpa-ak-day-hint" data-id="createDayHint">首次使用后 1 天到期</div>',
      '        </div>',
      '        <div class="cpa-ak-field" data-id="quotaField" style="display:none">',
      '          <label>额度上限（请求次数）</label>',
      '          <input type="number" min="1" step="1" data-id="quotaLimit" placeholder="例如：1000" />',
      '        </div>',
      '      </div>',
      '      <div class="cpa-ak-create-foot">',
      '        <button class="cpa-ak-btn" data-id="cancelCreate">取消</button>',
      '        <button class="cpa-ak-btn success" data-id="create">创建</button>',
      '      </div>',
      '    </div>',
      '  </div>',
      '',
      '  <div class="cpa-ak-create-overlay" data-id="editPanel">',
      '    <div class="cpa-ak-create-dialog" data-id="editDialog" role="dialog" aria-modal="true" aria-label="编辑 API Key">',
      '      <button class="cpa-ak-create-close" data-id="closeEdit" title="关闭">×</button>',
      '      <h3 class="cpa-ak-create-title">编辑 API Key</h3>',
      '      <div class="cpa-ak-create-desc">修改备注或续期</div>',
      '      <div class="cpa-ak-form-grid">',
      '        <div class="cpa-ak-field">',
      '          <label>备注名称</label>',
      '          <input data-id="editName" placeholder="请输入备注名称" />',
      '        </div>',
      '        <div class="cpa-ak-field">',
      '          <label>限制方式</label>',
      '          <div class="cpa-ak-mode-switch">',
      '            <button type="button" class="cpa-ak-mode-btn" data-id="editModeDate">按日期</button>',
      '            <button type="button" class="cpa-ak-mode-btn" data-id="editModeQuota">按额度</button>',
      '          </div>',
      '        </div>',
      '        <div class="cpa-ak-field" data-id="editDateField">',
      '          <label>续期时长</label>',
      '          <div class="cpa-ak-day-hint" data-id="editCurrentHint"></div>',
      '          <div class="cpa-ak-day-quick" data-id="editDayQuick">',
      '            <button type="button" class="cpa-ak-day-chip" data-days="1">1 天</button>',
      '            <button type="button" class="cpa-ak-day-chip" data-days="3">3 天</button>',
      '            <button type="button" class="cpa-ak-day-chip" data-days="7">7 天</button>',
      '            <button type="button" class="cpa-ak-day-chip" data-days="never">永不过期</button>',
      '          </div>',
      '          <div class="cpa-ak-day-input-row" data-id="editDayInputRow">',
      '            <input type="number" min="1" step="1" data-id="editDayInput" value="1" />',
      '            <span>天</span>',
      '          </div>',
      '          <div class="cpa-ak-day-hint" data-id="editDayHint">首次使用后 1 天到期</div>',
      '        </div>',
      '        <div class="cpa-ak-field" data-id="editQuotaField" style="display:none">',
      '          <label>额度增加（请求次数）</label>',
      '          <input type="number" min="1" step="1" data-id="editQuotaIncrease" placeholder="例如：1000" />',
      '        </div>',
      '      </div>',
      '      <div class="cpa-ak-create-foot">',
      '        <button class="cpa-ak-btn" data-id="cancelEdit">取消</button>',
      '        <button class="cpa-ak-btn success" data-id="saveEdit">保存</button>',
      '      </div>',
      '    </div>',
      '  </div>',
      '',
      '  <div class="cpa-ak-list" data-id="list"></div>',
      '</div>'
    ].join('');
  }

  function queryByDataId(root, id){
    return root.querySelector('[data-id="' + id + '"]');
  }

  function setupPanelApp(panel){
    if (panel.getAttribute(APP_BOOTED_ATTR) === '1') return;
    panel.setAttribute(APP_BOOTED_ATTR, '1');
    buildPanelSkeleton(panel);

    var refs = {
      baseURL: queryByDataId(panel, 'baseURL'),
      masterKey: queryByDataId(panel, 'masterKey'),
      ok: queryByDataId(panel, 'ok'),
      err: queryByDataId(panel, 'err'),
      refresh: queryByDataId(panel, 'refresh'),
      rediscover: queryByDataId(panel, 'rediscover'),
      copyBase: queryByDataId(panel, 'copyBase'),
      copyMaster: queryByDataId(panel, 'copyMaster'),
      sortLatest: queryByDataId(panel, 'sortLatest'),
      sortUsageDesc: queryByDataId(panel, 'sortUsageDesc'),
      sortUsageAsc: queryByDataId(panel, 'sortUsageAsc'),
      openCreate: queryByDataId(panel, 'openCreate'),
      createPanel: queryByDataId(panel, 'createPanel'),
      createDialog: queryByDataId(panel, 'createDialog'),
      closeCreate: queryByDataId(panel, 'closeCreate'),
      createName: queryByDataId(panel, 'createName'),
      modeDate: queryByDataId(panel, 'modeDate'),
      modeQuota: queryByDataId(panel, 'modeQuota'),
      datePresetField: queryByDataId(panel, 'datePresetField'),
      createDayQuick: queryByDataId(panel, 'createDayQuick'),
      createDayInputRow: queryByDataId(panel, 'createDayInputRow'),
      createDayInput: queryByDataId(panel, 'createDayInput'),
      createDayHint: queryByDataId(panel, 'createDayHint'),
      quotaField: queryByDataId(panel, 'quotaField'),
      quotaLimit: queryByDataId(panel, 'quotaLimit'),
      cancelCreate: queryByDataId(panel, 'cancelCreate'),
      create: queryByDataId(panel, 'create'),
      editPanel: queryByDataId(panel, 'editPanel'),
      editDialog: queryByDataId(panel, 'editDialog'),
      closeEdit: queryByDataId(panel, 'closeEdit'),
      editName: queryByDataId(panel, 'editName'),
      editModeDate: queryByDataId(panel, 'editModeDate'),
      editModeQuota: queryByDataId(panel, 'editModeQuota'),
      editDateField: queryByDataId(panel, 'editDateField'),
      editDayQuick: queryByDataId(panel, 'editDayQuick'),
      editDayInputRow: queryByDataId(panel, 'editDayInputRow'),
      editDayInput: queryByDataId(panel, 'editDayInput'),
      editDayHint: queryByDataId(panel, 'editDayHint'),
      editCurrentHint: queryByDataId(panel, 'editCurrentHint'),
      editQuotaField: queryByDataId(panel, 'editQuotaField'),
      editQuotaIncrease: queryByDataId(panel, 'editQuotaIncrease'),
      cancelEdit: queryByDataId(panel, 'cancelEdit'),
      saveEdit: queryByDataId(panel, 'saveEdit'),
      list: queryByDataId(panel, 'list')
    };

    var state = {
      token: '',
      sort: 'latest',
      createMode: 'date',
      createDurationChoice: '1',
      editMode: 'date',
      editDurationChoice: '1',
      editItem: null,
      items: [],
      serverInfo: null
    };

    function setStatus(ok, err){
      refs.ok.textContent = ok || '';
      refs.err.textContent = err || '';
    }

    function toISO(localValue){
      if (!localValue) return '';
      var d = new Date(localValue);
      if (Number.isNaN(d.getTime())) return '';
      return d.toISOString();
    }

    function formatTime(v){
      if (!v) return '-';
      var d = new Date(v);
      if (Number.isNaN(d.getTime())) return String(v);
      return d.toLocaleString('zh-CN');
    }

    function maskKey(v){
      var s = String(v || '');
      if (!s) return '-';
      if (s.length <= 14) return s;
      return s.slice(0, 8) + '...' + s.slice(-4);
    }

    function statusText(status){
      var map = {
        active: '启用',
        pending: '待激活',
        disabled: '已禁用',
        expired: '已过期',
        quota_reached: '额度耗尽'
      };
      return map[status] || status || '未知';
    }

    function statusClass(status){
      return String(status || '').toLowerCase();
    }

    function updateSortButtons(){
      refs.sortLatest.classList.toggle('active', state.sort === 'latest');
      refs.sortUsageDesc.classList.toggle('active', state.sort === 'usage_desc');
      refs.sortUsageAsc.classList.toggle('active', state.sort === 'usage_asc');
    }

    function sortItems(items){
      var list = items.slice();
      if (state.sort === 'usage_desc') {
        list.sort(function(a, b){ return Number(b.quotaUsed || 0) - Number(a.quotaUsed || 0); });
      } else if (state.sort === 'usage_asc') {
        list.sort(function(a, b){ return Number(a.quotaUsed || 0) - Number(b.quotaUsed || 0); });
      } else {
        list.sort(function(a, b){
          var at = new Date(a.createdAt || 0).getTime();
          var bt = new Date(b.createdAt || 0).getTime();
          return bt - at;
        });
      }
      return list;
    }

    function flashCopiedButton(btn){
      if (!btn) return;
      var original = btn.getAttribute('data-copy-text');
      if (!original) {
        original = btn.textContent || '⧉';
        btn.setAttribute('data-copy-text', original);
      }
      btn.textContent = '✓';
      btn.classList.add('copied');
      clearTimeout(btn.__cpaCopyTimer__);
      btn.__cpaCopyTimer__ = setTimeout(function(){
        btn.classList.remove('copied');
        btn.textContent = original;
      }, 1800);
    }

    async function copy(text, label, button){
      if (!text || text === '-') return;
      try {
        await navigator.clipboard.writeText(String(text));
        flashCopiedButton(button);
      } catch (err) {
        setStatus('', '复制失败：' + (err && err.message ? err.message : String(err)));
      }
    }

    function parseJSON(text){
      if (!text) return {};
      try { return JSON.parse(text); } catch (_) { return { raw: text }; }
    }

    async function ensureStateToken(){
      if (state.token) return state.token;
      var token = await ensureToken();
      if (token) state.token = token;
      return state.token;
    }

    async function request(path, options, retried){
      if (!state.token) await ensureStateToken();
      var headers = Object.assign({}, (options && options.headers) || {});
      headers['Content-Type'] = headers['Content-Type'] || 'application/json';
      if (state.token) headers['Authorization'] = 'Bearer ' + state.token;

      var resp = await fetch(path, Object.assign({}, options || {}, { headers: headers }));
      var text = await resp.text();
      var data = parseJSON(text);
      if (!resp.ok) {
        if (resp.status === 401 && !retried) {
          state.token = '';
          window.__CPA_MANAGEMENT_AUTH__ = '';
          await ensureStateToken();
          if (state.token) return request(path, options, true);
        }
        var message = (data && (data.error || data.message || data.raw)) || ('HTTP ' + resp.status);
        throw new Error(String(message));
      }
      return data;
    }

    function makeIconButton(label, cssClass, text, onClick){
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'cpa-ak-icon-btn' + (cssClass ? ' ' + cssClass : '');
      btn.title = label;
      btn.textContent = text;
      btn.addEventListener('click', onClick);
      return btn;
    }

    function renderList(){
      updateSortButtons();
      refs.list.innerHTML = '';
      var list = sortItems(state.items || []);
      if (!list.length) {
        var empty = document.createElement('div');
        empty.className = 'cpa-ak-empty';
        empty.textContent = '暂无 API Key，点击右上角“创建 Key”开始。';
        refs.list.appendChild(empty);
        return;
      }

      list.forEach(function(item){
        var row = document.createElement('div');
        row.className = 'cpa-ak-item';

        var left = document.createElement('div');
        left.className = 'cpa-ak-item-main';
        var line = document.createElement('div');
        line.className = 'cpa-ak-item-line';
        var name = document.createElement('span');
        name.className = 'cpa-ak-item-name';
        name.textContent = item.name || ('Key #' + item.id);
        var badge = document.createElement('span');
        badge.className = 'cpa-ak-badge ' + statusClass(item.status);
        badge.textContent = statusText(item.status);
        line.appendChild(name);
        line.appendChild(badge);

        var key = document.createElement('div');
        key.className = 'cpa-ak-item-key';
        key.textContent = maskKey(item.key);

        var meta = document.createElement('div');
        meta.className = 'cpa-ak-item-meta';
        meta.textContent = '创建: ' + formatTime(item.createdAt) + '   到期: ' + formatTime(item.expiresAt) + '   时长: ' + (item.durationDays == null ? '-' : String(item.durationDays) + ' 天');

        var usage = document.createElement('div');
        usage.className = 'cpa-ak-item-usage';
        var quotaLimit = item.quotaLimit == null ? '-' : String(item.quotaLimit);
        usage.textContent = '使用: ' + String(item.quotaUsed || 0) + ' 请求   限额: ' + quotaLimit;

        left.appendChild(line);
        left.appendChild(key);
        left.appendChild(meta);
        left.appendChild(usage);

        var right = document.createElement('div');
        right.className = 'cpa-ak-item-side';

        var copyBtn = makeIconButton('复制 Key', '', '⧉', function(){ copy(item.key || '', 'API Key', copyBtn); });

        var toggleWrap = document.createElement('label');
        toggleWrap.className = 'cpa-ak-switch';
        var toggle = document.createElement('input');
        toggle.type = 'checkbox';
        toggle.checked = Boolean(item.enabled);
        var slider = document.createElement('span');
        slider.className = 'cpa-ak-slider';
        toggle.addEventListener('change', async function(){
          try {
            await request('/v0/management/managed-api-keys/' + item.id, {
              method: 'PATCH',
              body: JSON.stringify({ enabled: toggle.checked })
            });
            setStatus('状态已更新', '');
            await refreshAll();
          } catch (err) {
            toggle.checked = !toggle.checked;
            setStatus('', '状态更新失败：' + err.message);
          }
        });
        toggleWrap.appendChild(toggle);
        toggleWrap.appendChild(slider);

        var renewBtn = makeIconButton('编辑/续期', '', '✎', function(){
          openEditDialog(item);
        });

        var deleteBtn = makeIconButton('删除', 'delete', '🗑', async function(){
          if (!window.confirm('确认删除该 Key？')) return;
          try {
            await request('/v0/management/managed-api-keys/' + item.id, { method: 'DELETE' });
            setStatus('删除成功', '');
            await refreshAll();
          } catch (err) {
            setStatus('', '删除失败：' + err.message);
          }
        });

        right.appendChild(copyBtn);
        right.appendChild(toggleWrap);
        right.appendChild(renewBtn);
        right.appendChild(deleteBtn);

        row.appendChild(left);
        row.appendChild(right);
        refs.list.appendChild(row);
      });
    }

    async function loadServerInfo(){
      var data = await request('/v0/management/server-info', { method: 'GET' });
      state.serverInfo = data || {};
      refs.baseURL.textContent = data.baseURL || data['base-url'] || window.location.origin;
      var master = data.masterApiKey || data['master-api-key'] || '';
      refs.masterKey.textContent = master ? maskKey(master) : '-';
    }

    async function loadKeys(){
      var data = await request('/v0/management/managed-api-keys', { method: 'GET' });
      state.items = (data && data.items) || [];
      renderList();
    }

    function parsePositiveDays(raw){
      var value = Number(raw);
      if (!Number.isFinite(value) || value <= 0) return null;
      return value;
    }

    function parsePositiveInt(raw){
      var value = Number(raw);
      if (!Number.isFinite(value) || value <= 0 || Math.floor(value) !== value) return null;
      return value;
    }

    function setDayChoiceActive(group, choice){
      if (!group) return;
      var chips = group.querySelectorAll('[data-days]');
      for (var i = 0; i < chips.length; i++) {
        var selected = chips[i].getAttribute('data-days') === choice;
        chips[i].classList.toggle('active', selected);
      }
    }

    function updateCreateDayHint(){
      var choice = state.createDurationChoice;
      if (choice === 'never') {
        refs.createDayHint.textContent = '永不过期';
        refs.createDayInputRow.style.display = 'none';
        return;
      }
      refs.createDayInputRow.style.display = '';
      var days = parsePositiveDays(refs.createDayInput.value);
      if (!days) days = 1;
      refs.createDayHint.textContent = '首次使用后 ' + days + ' 天到期';
    }

    function setCreateDurationChoice(choice){
      state.createDurationChoice = choice;
      if (choice !== 'never' && choice !== 'custom') {
        refs.createDayInput.value = String(choice);
      }
      setDayChoiceActive(refs.createDayQuick, choice);
      updateCreateDayHint();
    }

    function updateCreateModeUI(){
      var mode = state.createMode || 'date';
      refs.modeDate.classList.toggle('active', mode === 'date');
      refs.modeQuota.classList.toggle('active', mode === 'quota');
      refs.datePresetField.style.display = mode === 'date' ? '' : 'none';
      refs.quotaField.style.display = mode === 'quota' ? '' : 'none';
      updateCreateDayHint();
    }

    function resetCreateForm(){
      refs.createName.value = '';
      refs.quotaLimit.value = '';
      refs.createDayInput.value = '1';
      state.createMode = 'date';
      setCreateDurationChoice('1');
      updateCreateModeUI();
    }

    function setCreateOpen(open){
      refs.createPanel.classList.toggle('open', Boolean(open));
      if (open) {
        resetCreateForm();
        setTimeout(function(){ refs.createName.focus(); }, 0);
      }
    }

    function updateEditDayHint(){
      var choice = state.editDurationChoice;
      if (choice === 'never') {
        refs.editDayHint.textContent = '续期后将改为永不过期';
        refs.editDayInputRow.style.display = 'none';
        return;
      }
      refs.editDayInputRow.style.display = '';
      var days = parsePositiveDays(refs.editDayInput.value);
      if (!days) days = 1;
      refs.editDayHint.textContent = '首次使用后 ' + days + ' 天到期';
    }

    function setEditDurationChoice(choice){
      state.editDurationChoice = choice;
      if (choice !== 'never' && choice !== 'custom') {
        refs.editDayInput.value = String(choice);
      }
      setDayChoiceActive(refs.editDayQuick, choice);
      updateEditDayHint();
    }

    function updateEditModeUI(){
      var mode = state.editMode || 'date';
      refs.editModeDate.classList.toggle('active', mode === 'date');
      refs.editModeQuota.classList.toggle('active', mode === 'quota');
      refs.editDateField.style.display = mode === 'date' ? '' : 'none';
      refs.editQuotaField.style.display = mode === 'quota' ? '' : 'none';
      updateEditDayHint();
    }

    function setEditOpen(open){
      refs.editPanel.classList.toggle('open', Boolean(open));
      if (open) setTimeout(function(){ refs.editName.focus(); }, 0);
    }

    function openEditDialog(item){
      state.editItem = item || null;
      if (!state.editItem) return;
      refs.editName.value = item.name || '';
      refs.editQuotaIncrease.value = '';
      state.editMode = 'date';
      refs.editDayInput.value = '1';
      setEditDurationChoice('1');
      var status = String(item.status || '');
      if (status === 'active' && item.expiresAt) {
        refs.editCurrentHint.textContent = '当前到期：' + formatTime(item.expiresAt) + '，续期将在此基础上累加';
      } else if (status === 'pending' && item.durationDays != null) {
        refs.editCurrentHint.textContent = '当前待激活：首次使用后 ' + item.durationDays + ' 天到期';
      } else {
        refs.editCurrentHint.textContent = '当前状态：' + statusText(status) + '，续期后将变为待激活';
      }
      updateEditModeUI();
      setEditOpen(true);
    }

    async function saveEdit(){
      var item = state.editItem;
      if (!item) return;
      var name = String(refs.editName.value || '').trim();
      if (!name) {
        setStatus('', '备注名称不能为空');
        return;
      }

      try {
        if (name !== String(item.name || '')) {
          await request('/v0/management/managed-api-keys/' + item.id, {
            method: 'PATCH',
            body: JSON.stringify({ name: name })
          });
        }

        if (state.editMode === 'date') {
          if (state.editDurationChoice === 'never') {
            await request('/v0/management/managed-api-keys/' + item.id, {
              method: 'PATCH',
              body: JSON.stringify({ enabled: true, expiresAt: null, durationDays: null })
            });
          } else {
            var days = parsePositiveDays(refs.editDayInput.value);
            if (!days) {
              setStatus('', '续期天数必须大于 0');
              return;
            }
            await request('/v0/management/managed-api-keys/' + item.id + '/renew', {
              method: 'POST',
              body: JSON.stringify({ durationDays: days, resetQuotaUsed: true })
            });
          }
        } else {
          var increase = parsePositiveInt(refs.editQuotaIncrease.value);
          if (!increase) {
            setStatus('', '额度增加必须是正整数');
            return;
          }
          await request('/v0/management/managed-api-keys/' + item.id + '/renew', {
            method: 'POST',
            body: JSON.stringify({ quotaIncrease: increase, resetQuotaUsed: true })
          });
        }

        setEditOpen(false);
        setStatus('保存成功', '');
        await refreshAll();
      } catch (err) {
        setStatus('', '保存失败：' + err.message);
      }
    }

    async function createKey(){
      var name = String(refs.createName.value || '').trim();
      if (!name) {
        setStatus('', '请填写备注名称');
        return;
      }
      var payload = { name: name };
      if (state.createMode === 'date') {
        if (state.createDurationChoice !== 'never') {
          var days = parsePositiveDays(refs.createDayInput.value);
          if (!days) {
            setStatus('', '有效期天数必须大于 0');
            return;
          }
          payload.durationDays = days;
        }
      } else {
        var limit = parsePositiveInt(refs.quotaLimit.value);
        if (!limit) {
          setStatus('', '额度必须是正整数');
          return;
        }
        payload.quotaLimit = limit;
      }
      try {
        await request('/v0/management/managed-api-keys', {
          method: 'POST',
          body: JSON.stringify(payload)
        });
        setCreateOpen(false);
        setStatus('创建成功', '');
        await refreshAll();
      } catch (err) {
        setStatus('', '创建失败：' + err.message);
      }
    }

    async function refreshAll(){
      setStatus('', '');
      await loadServerInfo();
      await loadKeys();
    }

    async function rediscoverToken(){
      state.token = '';
      window.__CPA_MANAGEMENT_AUTH__ = '';
      setStatus('正在识别管理会话...', '');
      var t = await ensureStateToken();
      if (!t) {
        setStatus('', '未检测到管理会话。请先在管理后台任一页面完成登录，然后点击刷新。');
        return;
      }
      setStatus('已识别管理会话', '');
      await refreshAll();
    }

    refs.copyBase.addEventListener('click', function(){ copy(refs.baseURL.textContent || '', 'Base URL', refs.copyBase); });
    refs.copyMaster.addEventListener('click', function(){
      var raw = state.serverInfo ? (state.serverInfo.masterApiKey || state.serverInfo['master-api-key']) : '';
      if (!raw) { setStatus('', '当前没有可复制的主 API Key'); return; }
      copy(raw, '主 API Key', refs.copyMaster);
    });
    refs.refresh.addEventListener('click', function(){
      refreshAll().catch(function(err){ setStatus('', '刷新失败：' + err.message); });
    });
    refs.rediscover.addEventListener('click', function(){
      rediscoverToken().catch(function(err){ setStatus('', '会话识别失败：' + err.message); });
    });
    refs.sortLatest.addEventListener('click', function(){ state.sort = 'latest'; renderList(); });
    refs.sortUsageDesc.addEventListener('click', function(){ state.sort = 'usage_desc'; renderList(); });
    refs.sortUsageAsc.addEventListener('click', function(){ state.sort = 'usage_asc'; renderList(); });
    refs.openCreate.addEventListener('click', function(){ setCreateOpen(true); });
    refs.cancelCreate.addEventListener('click', function(){ setCreateOpen(false); });
    refs.closeCreate.addEventListener('click', function(){ setCreateOpen(false); });
    refs.modeDate.addEventListener('click', function(){ state.createMode = 'date'; updateCreateModeUI(); });
    refs.modeQuota.addEventListener('click', function(){ state.createMode = 'quota'; updateCreateModeUI(); });
    refs.createDayQuick.addEventListener('click', function(event){
      var target = event.target && event.target.closest ? event.target.closest('[data-days]') : null;
      if (!target) return;
      setCreateDurationChoice(target.getAttribute('data-days') || '1');
    });
    refs.createDayInput.addEventListener('input', function(){
      state.createDurationChoice = 'custom';
      setDayChoiceActive(refs.createDayQuick, 'custom');
      updateCreateDayHint();
    });
    refs.createPanel.addEventListener('click', function(event){
      if (event.target === refs.createPanel) setCreateOpen(false);
    });
    refs.editPanel.addEventListener('click', function(event){
      if (event.target === refs.editPanel) setEditOpen(false);
    });
    document.addEventListener('keydown', function(event){
      if (event.key === 'Escape' && refs.createPanel.classList.contains('open')) setCreateOpen(false);
      if (event.key === 'Escape' && refs.editPanel.classList.contains('open')) setEditOpen(false);
    });
    refs.create.addEventListener('click', function(){
      createKey().catch(function(err){ setStatus('', '创建失败：' + err.message); });
    });
    refs.closeEdit.addEventListener('click', function(){ setEditOpen(false); });
    refs.cancelEdit.addEventListener('click', function(){ setEditOpen(false); });
    refs.editModeDate.addEventListener('click', function(){ state.editMode = 'date'; updateEditModeUI(); });
    refs.editModeQuota.addEventListener('click', function(){ state.editMode = 'quota'; updateEditModeUI(); });
    refs.editDayQuick.addEventListener('click', function(event){
      var target = event.target && event.target.closest ? event.target.closest('[data-days]') : null;
      if (!target) return;
      setEditDurationChoice(target.getAttribute('data-days') || '1');
    });
    refs.editDayInput.addEventListener('input', function(){
      state.editDurationChoice = 'custom';
      setDayChoiceActive(refs.editDayQuick, 'custom');
      updateEditDayHint();
    });
    refs.saveEdit.addEventListener('click', function(){
      saveEdit().catch(function(err){ setStatus('', '保存失败：' + err.message); });
    });

    updateCreateModeUI();
    ensureStateToken().then(function(token){
      if (!token) {
        setStatus('', '未检测到管理会话。请先在管理后台任一页面完成登录。');
        renderList();
        return;
      }
      refreshAll().catch(function(err){ setStatus('', '加载失败：' + err.message); });
    });
  }

  function ensurePanel(){
    var main = getMainContent();
    if (!main) return null;
    injectStyle();

    var panel = document.getElementById(PANEL_ID);
    if (!panel) {
      panel = document.createElement('section');
      panel.id = PANEL_ID;
      panel.className = 'cpa-ak-page';
      main.appendChild(panel);
    } else if (panel.parentElement !== main) {
      main.appendChild(panel);
    }

    // Replace old iframe implementation if exists.
    if (panel.querySelector('iframe')) {
      panel.innerHTML = '';
      panel.removeAttribute(APP_BOOTED_ATTR);
    }

    setupPanelApp(panel);
    return panel;
  }

  function hideMainChildren(main, panel){
    if (!main) return;
    var children = main.children;
    for (var i = 0; i < children.length; i++) {
      var node = children[i];
      if (node === panel) continue;
      if (node.getAttribute(HIDDEN_ATTR) === '1') continue;
      node.setAttribute(HIDDEN_ATTR, '1');
      node.setAttribute('data-cpa-prev-display', node.style.display || '');
      node.style.display = 'none';
    }
  }

  function restoreMainChildren(main, panel){
    if (!main) return;
    var children = main.children;
    for (var i = 0; i < children.length; i++) {
      var node = children[i];
      if (node === panel) continue;
      if (node.getAttribute(HIDDEN_ATTR) !== '1') continue;
      var prev = node.getAttribute('data-cpa-prev-display') || '';
      node.style.display = prev;
      node.removeAttribute(HIDDEN_ATTR);
      node.removeAttribute('data-cpa-prev-display');
    }
  }

  function blockCandidates(node){
    var out = [];
    var cur = node;
    for (var i = 0; i < 8 && cur; i++) {
      out.push(cur);
      cur = cur.parentElement;
    }
    return out;
  }

  function shouldHideApiKeysBlock(text){
    if (!text) return false;
    if (text.indexOf('api密钥列表(api-keys)') !== -1) return true;
    if ((text.indexOf('api密钥列表') !== -1 || text.indexOf('apikey列表') !== -1) &&
      (text.indexOf('添加api密钥') !== -1 || text.indexOf('api key') !== -1 || text.indexOf('apikey') !== -1)) {
      return true;
    }
    if (text.indexOf('api-keys') !== -1 && (text.indexOf('添加') !== -1 || text.indexOf('编辑') !== -1 || text.indexOf('删除') !== -1)) {
      return true;
    }
    return false;
  }

  function hideLegacyApiKeysBlock(){
    var hash = String(window.location.hash || '');
    if (hash.indexOf('#/config') !== 0) return;

    var nodes = document.querySelectorAll('label,div,span,p,strong,h2,h3,h4');
    for (var i = 0; i < nodes.length; i++) {
      var node = nodes[i];
      var text = norm(node.textContent);
      if (!text) continue;
      if (text.indexOf('api密钥列表(api-keys)') === -1 && text.indexOf('apikey列表(api-keys)') === -1) continue;
      var cands = blockCandidates(node);
      for (var j = 0; j < cands.length; j++) {
        var t = norm(cands[j].textContent);
        if (!shouldHideApiKeysBlock(t)) continue;
        cands[j].style.display = 'none';
        cands[j].setAttribute(LEGACY_HIDDEN_ATTR, '1');
        break;
      }
    }
  }

  function restoreLegacyHiddenNodes(){
    var nodes = document.querySelectorAll('[' + LEGACY_HIDDEN_ATTR + '="1"]');
    for (var i = 0; i < nodes.length; i++) {
      nodes[i].style.display = '';
      nodes[i].removeAttribute(LEGACY_HIDDEN_ATTR);
    }
  }

  function apply(){
    installAuthSniffer();
    ensureNavEntry();
    restoreLegacyHiddenNodes();

    var main = getMainContent();
    if (!main) return;
    var panel = ensurePanel();
    if (!panel) return;

    if (isApiKeysRoute()) {
      hideMainChildren(main, panel);
      panel.style.display = 'block';
    } else {
      panel.style.display = 'none';
      restoreMainChildren(main, panel);
    }
  }

  function applyWithGuard(){
    try {
      apply();
    } catch (err) {
      try {
        var main = getMainContent();
        var panel = document.getElementById(PANEL_ID);
        restoreMainChildren(main, panel);
      } catch (_) {}
      if (window.console && typeof window.console.error === 'function') {
        window.console.error('[CPA managed api keys] patch apply failed', err);
      }
    }
  }

  function shouldRepairState(){
    var nav = getNavSection();
    if (nav && !document.getElementById(ENTRY_ID)) return true;
    if (!isApiKeysRoute()) return false;

    var main = getMainContent();
    if (!main) return true;

    var panel = document.getElementById(PANEL_ID);
    if (!panel) return true;
    if (panel.parentElement !== main) return true;
    if (window.getComputedStyle(panel).display === 'none') return true;
    return false;
  }

  var scheduled = false;
  var lastAt = 0;
  function scheduleApply(){
    if (scheduled) return;
    var elapsed = now() - lastAt;
    if (elapsed < 16) {
      scheduled = true;
      setTimeout(function(){ scheduled = false; applyWithGuard(); lastAt = now(); }, 16 - elapsed);
      return;
    }
    scheduled = true;
    requestAnimationFrame(function(){
      scheduled = false;
      applyWithGuard();
      lastAt = now();
    });
  }

  applyWithGuard();
  var lastHashSeen = String(window.location.hash || '');
  window.addEventListener('hashchange', function(){
    lastHashSeen = String(window.location.hash || '');
    scheduleApply();
  });
  window.addEventListener('popstate', function(){
    lastHashSeen = String(window.location.hash || '');
    scheduleApply();
  });

  var bootstrapAttempts = 0;
  var bootstrapTimer = setInterval(function(){
    bootstrapAttempts++;
    scheduleApply();
    if ((getNavSection() && getMainContent()) || bootstrapAttempts >= 40) {
      clearInterval(bootstrapTimer);
    }
  }, 250);

  var watchdogTimer = setInterval(function(){
    if (shouldRepairState()) scheduleApply();
  }, 1200);

  var hashPollTimer = setInterval(function(){
    var curHash = String(window.location.hash || '');
    if (curHash !== lastHashSeen) {
      lastHashSeen = curHash;
      scheduleApply();
    }
  }, 180);

  setTimeout(scheduleApply, 800);
  setTimeout(scheduleApply, 1800);
})();</script>`

const managedAPIKeysPageHTML = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>API 密钥管理</title>
  <style>
    :root {
      --bg: #070f1d;
      --bg-2: #0a1426;
      --panel: #0b1628;
      --line: #2a3a56;
      --line-soft: #1f2d44;
      --text: #e2ecff;
      --muted: #8da0c2;
      --brand: #2b6df6;
      --brand-2: #1f4fb2;
      --ok: #31b66b;
      --warn: #d7a12f;
      --danger: #d45959;
      --disabled: #7483a0;
      --chip-bg: rgba(22, 36, 62, 0.85);
      --shadow: 0 10px 30px rgba(0, 0, 0, 0.26);
      --font: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      font-family: var(--font);
      color: var(--text);
      background:
        radial-gradient(1200px 520px at 0% -10%, rgba(44, 103, 223, 0.20), transparent 60%),
        linear-gradient(180deg, #081224 0%, #060d1a 100%);
      min-height: 100vh;
    }

    body.embedded {
      background: transparent;
      min-height: auto;
    }

    .wrap {
      width: min(1180px, calc(100% - 24px));
      margin: 12px auto;
      padding-bottom: 12px;
    }

    body.embedded .wrap {
      width: calc(100% - 16px);
      margin: 8px auto;
      padding-bottom: 0;
    }

    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      margin-bottom: 12px;
    }

    .title {
      margin: 0;
      font-size: 28px;
      line-height: 1.15;
      font-weight: 700;
      letter-spacing: 0.2px;
    }

    .subtitle {
      margin: 6px 0 0;
      color: var(--muted);
      font-size: 13px;
    }

    body.embedded .topbar {
      display: none;
    }

    .btn {
      border: 1px solid var(--line);
      background: linear-gradient(180deg, #0f1f37 0%, #0b172a 100%);
      color: var(--text);
      border-radius: 10px;
      padding: 8px 12px;
      font-size: 13px;
      line-height: 1;
      cursor: pointer;
      transition: all .18s ease;
    }

    .btn:hover { border-color: #4e6ea3; }
    .btn:disabled { opacity: .5; cursor: not-allowed; }

    .btn.primary {
      border-color: var(--brand);
      background: linear-gradient(180deg, #1f3e7a 0%, #173463 100%);
    }

    .btn.success {
      border-color: #2d8f5a;
      background: linear-gradient(180deg, #1d4d38 0%, #153728 100%);
    }

    .btn.warn {
      border-color: #8f6d24;
      background: linear-gradient(180deg, #4e3d18 0%, #372b12 100%);
    }

    .btn.danger {
      border-color: #8e4040;
      background: linear-gradient(180deg, #4a2222 0%, #331818 100%);
    }

    .card {
      border: 1px solid var(--line);
      background: linear-gradient(180deg, #0b1628 0%, #081222 100%);
      border-radius: 12px;
      box-shadow: var(--shadow);
    }

    .service-card {
      padding: 14px;
      margin-bottom: 12px;
    }

    .service-title {
      margin: 0 0 12px;
      color: #dce7fd;
      font-size: 16px;
      font-weight: 700;
    }

    .service-row {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 8px;
      align-items: center;
      padding: 10px 0;
      border-top: 1px dashed var(--line-soft);
    }

    .service-row:first-of-type { border-top: 0; }

    .service-k {
      color: var(--muted);
      font-size: 12px;
      margin-bottom: 3px;
    }

    .service-v {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Courier New", monospace;
      font-size: 14px;
      word-break: break-all;
    }

    .copy-ghost {
      border: 1px solid var(--line-soft);
      background: rgba(21, 35, 62, 0.78);
      color: #b5c6e7;
      border-radius: 8px;
      width: 34px;
      height: 32px;
      cursor: pointer;
    }

    .status {
      margin-top: 8px;
      font-size: 13px;
      white-space: pre-wrap;
    }

    .status.ok { color: #95e3b8; }
    .status.err { color: #ff9f9f; }

    .head {
      margin-top: 8px;
      margin-bottom: 10px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      flex-wrap: wrap;
    }

    .head h2 {
      margin: 0;
      font-size: 30px;
      font-weight: 700;
      letter-spacing: 0.3px;
    }

    body.embedded .head h2 {
      font-size: 30px;
      margin-top: 2px;
    }

    .actions {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      align-items: center;
    }

    .chip {
      border: 1px solid var(--line-soft);
      background: var(--chip-bg);
      color: #c8d5f0;
      border-radius: 10px;
      padding: 8px 12px;
      font-size: 13px;
      cursor: pointer;
    }

    .chip.active {
      border-color: #4e6ea3;
      color: #ecf2ff;
      background: rgba(35, 64, 116, 0.6);
    }

    .create-overlay {
      position: fixed;
      inset: 0;
      display: none;
      align-items: center;
      justify-content: center;
      padding: 20px;
      background: rgba(4, 9, 18, 0.72);
      backdrop-filter: blur(2px);
      z-index: 1200;
    }

    .create-overlay.open { display: flex; }

    .create-dialog {
      position: relative;
      width: min(620px, calc(100vw - 28px));
      padding: 18px 18px 14px;
      border: 1px solid var(--line);
      border-radius: 14px;
      background: linear-gradient(180deg, #0b1628 0%, #081222 100%);
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.45);
    }

    .create-title {
      margin: 0;
      font-size: 30px;
      font-weight: 700;
      letter-spacing: 0.2px;
    }

    .create-desc {
      margin: 6px 0 14px;
      color: var(--muted);
      font-size: 13px;
    }

    .create-close {
      position: absolute;
      top: 10px;
      right: 10px;
      width: 30px;
      height: 30px;
      border: 1px solid var(--line-soft);
      border-radius: 8px;
      background: rgba(17, 29, 52, 0.9);
      color: #b8c9e8;
      cursor: pointer;
      font-size: 18px;
      line-height: 1;
    }

    .form-grid {
      display: grid;
      grid-template-columns: 1fr;
      gap: 10px;
    }

    .field {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }

    .field label {
      color: var(--muted);
      font-size: 12px;
    }

    input, select {
      border: 1px solid var(--line);
      background: #091325;
      color: var(--text);
      border-radius: 9px;
      padding: 9px 10px;
      font-size: 13px;
      width: 100%;
    }

    .mode-switch {
      display: inline-flex;
      gap: 6px;
      padding: 4px;
      border: 1px solid var(--line-soft);
      border-radius: 10px;
      background: rgba(9, 18, 36, 0.75);
    }

    .mode-btn {
      border: 0;
      border-radius: 8px;
      padding: 7px 12px;
      background: transparent;
      color: #9fb3d8;
      font-size: 13px;
      cursor: pointer;
    }

    .mode-btn.active {
      background: rgba(35, 64, 116, 0.75);
      color: #eff4ff;
    }

    .create-footer {
      margin-top: 10px;
      display: flex;
      justify-content: flex-end;
      gap: 8px;
      flex-wrap: wrap;
    }

    .list {
      display: grid;
      gap: 10px;
      margin-bottom: 8px;
    }

    .item {
      border: 1px solid var(--line);
      border-radius: 10px;
      background: linear-gradient(180deg, #091424 0%, #08101d 100%);
      padding: 12px;
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 10px;
      align-items: center;
    }

    .item-main {
      min-width: 0;
    }

    .item-line {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }

    .item-name {
      font-size: 17px;
      font-weight: 650;
      letter-spacing: 0.2px;
    }

    .badge {
      font-size: 11px;
      line-height: 1;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 4px 8px;
      color: var(--muted);
    }

    .badge.active { border-color: #2f9861; color: #90e2b3; }
    .badge.pending { border-color: #a67f25; color: #f1cf7f; }
    .badge.disabled { border-color: #5f6d88; color: #b8c3d8; }
    .badge.expired { border-color: #9f4f4f; color: #f3abab; }
    .badge.quota_reached { border-color: #9f4f4f; color: #f3abab; }

    .item-key {
      margin-top: 4px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Courier New", monospace;
      color: #93abd4;
      font-size: 13px;
    }

    .item-meta {
      margin-top: 5px;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.5;
      word-break: break-word;
    }

    .item-usage {
      margin-top: 6px;
      color: #7f93b9;
      font-size: 12px;
      line-height: 1.4;
    }

    .item-side {
      display: flex;
      gap: 8px;
      align-items: center;
      justify-content: flex-end;
      flex-wrap: wrap;
    }

    .icon-btn {
      width: 32px;
      height: 32px;
      border: 1px solid var(--line-soft);
      border-radius: 8px;
      background: rgba(18, 33, 58, 0.8);
      color: #b3c3e3;
      cursor: pointer;
    }

    .icon-btn.delete {
      border-color: #6f3333;
      color: #d88d8d;
      background: rgba(69, 27, 27, 0.7);
    }

    .switch {
      position: relative;
      display: inline-block;
      width: 44px;
      height: 24px;
    }

    .switch input {
      opacity: 0;
      width: 0;
      height: 0;
    }

    .slider {
      position: absolute;
      cursor: pointer;
      inset: 0;
      border-radius: 999px;
      border: 1px solid #3b4a65;
      background: #1a2a45;
      transition: .2s;
    }

    .slider:before {
      content: "";
      position: absolute;
      width: 18px;
      height: 18px;
      left: 2px;
      top: 2px;
      border-radius: 50%;
      background: #b9c6de;
      transition: .2s;
    }

    .switch input:checked + .slider {
      background: #123d7c;
      border-color: #2b6df6;
    }

    .switch input:checked + .slider:before {
      transform: translateX(19px);
      background: #e6efff;
    }

    .empty {
      border: 1px dashed var(--line);
      border-radius: 10px;
      padding: 18px;
      color: var(--muted);
      font-size: 13px;
      text-align: center;
    }

    @media (max-width: 1024px) {
      .create-dialog {
        width: min(620px, calc(100vw - 22px));
        padding: 16px 14px 12px;
      }
    }

    @media (max-width: 820px) {
      .item {
        grid-template-columns: 1fr;
      }
      .item-side {
        justify-content: flex-start;
      }
      .head h2 {
        font-size: 24px;
      }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <div>
        <h1 class="title">API 密钥管理</h1>
        <div class="subtitle">同级管理页面（待激活、禁用、过期、续期、额度限制）</div>
      </div>
      <button class="btn" id="backBtn">返回配置面板</button>
    </div>

    <div class="card service-card">
      <h3 class="service-title">服务连接信息</h3>
      <div class="service-row">
        <div>
          <div class="service-k">API Base URL</div>
          <div class="service-v" id="baseURL">-</div>
        </div>
        <button class="copy-ghost" id="copyBaseBtn" title="复制 Base URL">⧉</button>
      </div>
      <div class="service-row">
        <div>
          <div class="service-k">主 API Key</div>
          <div class="service-v" id="masterKey">-</div>
        </div>
        <button class="copy-ghost" id="copyMasterBtn" title="复制主 API Key">⧉</button>
      </div>
      <div class="status ok" id="ok"></div>
      <div class="status err" id="err"></div>
      <div class="actions" style="margin-top:8px">
        <button class="btn" id="refreshBtn">刷新</button>
        <button class="btn" id="rediscoverBtn">重新识别会话</button>
      </div>
    </div>

    <div class="head">
      <h2>API Key 管理</h2>
      <div class="actions">
        <button class="chip active" id="sortLatestBtn">最新</button>
        <button class="chip" id="sortUsageDescBtn">费用↓</button>
        <button class="chip" id="sortUsageAscBtn">费用↑</button>
        <button class="btn primary" id="openCreateBtn">+ 创建 Key</button>
      </div>
    </div>

    <div class="create-overlay" id="createPanel">
      <div class="create-dialog" id="createDialog" role="dialog" aria-modal="true" aria-label="创建 API Key">
        <button class="create-close" id="closeCreateBtn" title="关闭">×</button>
        <h3 class="create-title">创建 API Key</h3>
        <div class="create-desc">为用户创建一个新的 API Key</div>
        <div class="form-grid">
          <div class="field">
            <label>备注名称</label>
            <input id="createName" placeholder="例如：闭鱼-李搞定" />
          </div>
          <div class="field">
            <label>限制模式</label>
            <div class="mode-switch">
              <button class="mode-btn" id="modeDateBtn" type="button">按日期</button>
              <button class="mode-btn" id="modeQuotaBtn" type="button">按额度</button>
            </div>
          </div>
          <div class="field" id="datePresetField">
            <label>日期预设</label>
            <select id="datePreset">
              <option value="7">7 天</option>
              <option value="30">30 天</option>
              <option value="90">90 天</option>
              <option value="never">永不过期</option>
              <option value="custom">自定义日期</option>
            </select>
          </div>
          <div class="field" id="customDateField" style="display:none">
            <label>自定义到期</label>
            <input type="datetime-local" id="customDate" />
          </div>
          <div class="field" id="quotaField" style="display:none">
            <label>额度上限（请求次数）</label>
            <input type="number" min="1" step="1" id="quotaLimit" placeholder="例如：1000" />
          </div>
        </div>
        <div class="create-footer">
          <button class="btn" id="cancelCreateBtn">取消</button>
          <button class="btn success" id="createBtn">创建</button>
        </div>
      </div>
    </div>

    <div class="list" id="list"></div>
  </div>

  <script>
    (function(){
      var state = {
        token: '',
        serverInfo: null,
        items: [],
        sort: 'latest',
        createMode: 'quota'
      };

      var TOKEN_CACHE_KEY = 'cpa_management_key_cache';
      var embedded = false;

      function el(id){ return document.getElementById(id); }
      function norm(v){ return String(v || '').trim(); }
      function isObject(v){ return v && typeof v === 'object'; }

      function toISO(localValue){
        if (!localValue) return '';
        var d = new Date(localValue);
        if (Number.isNaN(d.getTime())) return '';
        return d.toISOString();
      }

      function formatTime(v){
        if (!v) return '-';
        var d = new Date(v);
        if (Number.isNaN(d.getTime())) return String(v);
        return d.toLocaleString('zh-CN');
      }

      function maskKey(v){
        var s = String(v || '');
        if (!s) return '-';
        if (s.length <= 14) return s;
        return s.slice(0, 8) + '...' + s.slice(-4);
      }

      function normalizeToken(raw){
        if (!raw) return '';
        var token = String(raw).trim();
        if (!token) return '';
        if (/^bearer\s+/i.test(token)) token = token.replace(/^bearer\s+/i, '').trim();
        if (!token || token.length < 6 || token.length > 512) return '';
        return token;
      }

      function setStatus(ok, err){
        el('ok').textContent = ok || '';
        el('err').textContent = err || '';
      }

      function rememberToken(raw){
        var token = normalizeToken(raw);
        if (!token) return '';
        state.token = token;
        try { localStorage.setItem(TOKEN_CACHE_KEY, token); } catch (_) {}
        try { window.__CPA_MANAGEMENT_AUTH__ = token; } catch (_) {}
        if (embedded && window.parent && window.parent !== window) {
          try { window.parent.__CPA_MANAGEMENT_AUTH__ = token; } catch (_) {}
        }
        return token;
      }

      function readGlobalToken(){
        try {
          var t = normalizeToken(window.__CPA_MANAGEMENT_AUTH__);
          if (t) return t;
        } catch (_) {}
        if (window.parent && window.parent !== window) {
          try {
            var p = normalizeToken(window.parent.__CPA_MANAGEMENT_AUTH__);
            if (p) return p;
          } catch (_) {}
        }
        return '';
      }

      function addCandidate(map, value, score){
        var token = normalizeToken(value);
        if (!token) return;
        var prev = map.get(token);
        if (!prev || score > prev) map.set(token, score);
      }

      function scanValue(map, value, score){
        if (!value) return;
        if (typeof value === 'string') {
          addCandidate(map, value, score);
          var trimmed = value.trim();
          if (trimmed.length > 2 && trimmed.length < 12000 && (trimmed[0] === '{' || trimmed[0] === '[')) {
            try {
              var parsed = JSON.parse(trimmed);
              scanValue(map, parsed, score - 1);
            } catch (_) {}
          }
          return;
        }
        if (!isObject(value)) return;

        var stack = [value];
        var hops = 0;
        while (stack.length > 0 && hops < 120) {
          hops++;
          var node = stack.pop();
          if (typeof node === 'string') {
            addCandidate(map, node, score - 1);
            continue;
          }
          if (!isObject(node)) continue;
          var keys = Object.keys(node);
          for (var i = 0; i < keys.length; i++) {
            var sub = node[keys[i]];
            if (typeof sub === 'string') addCandidate(map, sub, score - 2);
            else if (isObject(sub)) stack.push(sub);
          }
        }
      }

      function collectCandidates(){
        var map = new Map();
        addCandidate(map, state.token, 1000);
        addCandidate(map, readGlobalToken(), 990);
        try { addCandidate(map, localStorage.getItem(TOKEN_CACHE_KEY), 980); } catch (_) {}

        var stores = [];
        try { stores.push(localStorage); } catch (_) {}
        try { stores.push(sessionStorage); } catch (_) {}

        var hints = ['manage', 'token', 'auth', 'password', 'secret', 'key'];
        for (var s = 0; s < stores.length; s++) {
          var storage = stores[s];
          if (!storage) continue;
          for (var i = 0; i < storage.length; i++) {
            var k = '';
            try { k = storage.key(i) || ''; } catch (_) { k = ''; }
            if (!k) continue;
            var kl = k.toLowerCase();
            var score = 200;
            for (var h = 0; h < hints.length; h++) {
              if (kl.indexOf(hints[h]) >= 0) score += 100;
            }
            var value = '';
            try { value = storage.getItem(k) || ''; } catch (_) { value = ''; }
            scanValue(map, value, score);
          }
        }

        return Array.from(map.entries())
          .sort(function(a, b){ return b[1] - a[1]; })
          .map(function(p){ return p[0]; })
          .slice(0, 80);
      }

      async function probeToken(token){
        var t = normalizeToken(token);
        if (!t) return false;
        try {
          var resp = await fetch('/v0/management/server-info', {
            method: 'GET',
            headers: { Authorization: 'Bearer ' + t }
          });
          if (!resp.ok) return false;
          rememberToken(t);
          return true;
        } catch (_) {
          return false;
        }
      }

      async function ensureToken(){
        if (state.token) return state.token;

        var direct = readGlobalToken();
        if (direct && await probeToken(direct)) return state.token;

        var all = collectCandidates();
        for (var i = 0; i < all.length; i++) {
          if (await probeToken(all[i])) return state.token;
        }

        return '';
      }

      async function copy(text, label){
        if (!text || text === '-') return;
        try {
          await navigator.clipboard.writeText(String(text));
          setStatus('已复制：' + label, '');
        } catch (err) {
          setStatus('', '复制失败：' + (err && err.message ? err.message : String(err)));
        }
      }

      function parseJSON(text){
        if (!text) return {};
        try { return JSON.parse(text); } catch (_) { return { raw: text }; }
      }

      async function request(path, options, retried){
        if (!state.token) await ensureToken();
        var headers = Object.assign({}, (options && options.headers) || {});
        headers['Content-Type'] = headers['Content-Type'] || 'application/json';
        if (state.token) headers['Authorization'] = 'Bearer ' + state.token;

        var resp = await fetch(path, Object.assign({}, options || {}, { headers: headers }));
        var text = await resp.text();
        var data = parseJSON(text);

        if (!resp.ok) {
          if (resp.status === 401 && !retried) {
            state.token = '';
            var renewed = await ensureToken();
            if (renewed) return request(path, options, true);
          }
          var message = (data && (data.error || data.message || data.raw)) || ('HTTP ' + resp.status);
          throw new Error(String(message));
        }
        return data;
      }

      function statusText(status){
        var map = {
          active: '启用',
          pending: '待激活',
          disabled: '已禁用',
          expired: '已过期',
          quota_reached: '额度耗尽'
        };
        return map[status] || status || '未知';
      }

      function statusClass(status){
        return String(status || '').toLowerCase();
      }

      function updateSortChips(){
        var sort = state.sort;
        el('sortLatestBtn').classList.toggle('active', sort === 'latest');
        el('sortUsageDescBtn').classList.toggle('active', sort === 'usage_desc');
        el('sortUsageAscBtn').classList.toggle('active', sort === 'usage_asc');
      }

      function getSortedItems(){
        var list = state.items.slice();
        if (state.sort === 'usage_desc') {
          list.sort(function(a, b){ return (Number(b.quotaUsed || 0) - Number(a.quotaUsed || 0)); });
        } else if (state.sort === 'usage_asc') {
          list.sort(function(a, b){ return (Number(a.quotaUsed || 0) - Number(b.quotaUsed || 0)); });
        } else {
          list.sort(function(a, b){
            var at = new Date(a.createdAt || 0).getTime();
            var bt = new Date(b.createdAt || 0).getTime();
            return bt - at;
          });
        }
        return list;
      }

      function makeIconBtn(label, cssClass, text, onClick){
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'icon-btn' + (cssClass ? ' ' + cssClass : '');
        btn.title = label;
        btn.textContent = text;
        btn.addEventListener('click', onClick);
        return btn;
      }

      function renderList(){
        updateSortChips();

        var container = el('list');
        container.innerHTML = '';

        var list = getSortedItems();
        if (list.length === 0) {
          var empty = document.createElement('div');
          empty.className = 'empty';
          empty.textContent = '暂无 API Key，点击右上角“创建 Key”开始。';
          container.appendChild(empty);
          return;
        }

        list.forEach(function(item){
          var row = document.createElement('div');
          row.className = 'item';

          var left = document.createElement('div');
          left.className = 'item-main';

          var line = document.createElement('div');
          line.className = 'item-line';

          var name = document.createElement('span');
          name.className = 'item-name';
          name.textContent = item.name || ('Key #' + item.id);

          var badge = document.createElement('span');
          badge.className = 'badge ' + statusClass(item.status);
          badge.textContent = statusText(item.status);

          line.appendChild(name);
          line.appendChild(badge);

          var key = document.createElement('div');
          key.className = 'item-key';
          key.textContent = maskKey(item.key);

          var meta = document.createElement('div');
          meta.className = 'item-meta';
          meta.textContent = '创建: ' + formatTime(item.createdAt) +
            '   到期: ' + formatTime(item.expiresAt) +
            '   时长: ' + (item.durationDays == null ? '-' : String(item.durationDays) + ' 天');

          var usage = document.createElement('div');
          usage.className = 'item-usage';
          var quotaLimit = item.quotaLimit == null ? '-' : String(item.quotaLimit);
          usage.textContent =
            '出 ' + String(item.quotaUsed || 0) + ' 次请求   入 -   出 -   $-   限额: ' + quotaLimit;

          left.appendChild(line);
          left.appendChild(key);
          left.appendChild(meta);
          left.appendChild(usage);

          var right = document.createElement('div');
          right.className = 'item-side';

          var copyBtn = makeIconBtn('复制 Key', '', '⧉', function(){
            copy(item.key || '', 'API Key');
          });

          var toggleWrap = document.createElement('label');
          toggleWrap.className = 'switch';
          var toggle = document.createElement('input');
          toggle.type = 'checkbox';
          toggle.checked = Boolean(item.enabled);
          var slider = document.createElement('span');
          slider.className = 'slider';
          toggle.addEventListener('change', async function(){
            try {
              await request('/v0/management/managed-api-keys/' + item.id, {
                method: 'PATCH',
                body: JSON.stringify({ enabled: toggle.checked })
              });
              setStatus('状态已更新', '');
              await refreshAll();
            } catch (err) {
              toggle.checked = !toggle.checked;
              setStatus('', '状态更新失败：' + err.message);
            }
          });
          toggleWrap.appendChild(toggle);
          toggleWrap.appendChild(slider);

          var renewBtn = makeIconBtn('续期/加额', '', '✎', async function(){
            var daysRaw = window.prompt('续期天数（可留空）', '');
            var incRaw = window.prompt('增加额度（可留空，整数）', '');
            var payload = { resetQuotaUsed: true };

            if (daysRaw && String(daysRaw).trim() !== '') {
              var days = Number(daysRaw);
              if (!Number.isFinite(days) || days <= 0) {
                setStatus('', '续期天数必须大于 0');
                return;
              }
              payload.durationDays = days;
            }

            if (incRaw && String(incRaw).trim() !== '') {
              var inc = Number(incRaw);
              if (!Number.isFinite(inc) || inc < 0 || Math.floor(inc) !== inc) {
                setStatus('', '增加额度必须是非负整数');
                return;
              }
              payload.quotaIncrease = inc;
            }

            if (payload.durationDays == null && payload.quotaIncrease == null) {
              setStatus('', '未输入续期或额度参数');
              return;
            }

            try {
              await request('/v0/management/managed-api-keys/' + item.id + '/renew', {
                method: 'POST',
                body: JSON.stringify(payload)
              });
              setStatus('续期成功', '');
              await refreshAll();
            } catch (err) {
              setStatus('', '续期失败：' + err.message);
            }
          });

          var deleteBtn = makeIconBtn('删除', 'delete', '🗑', async function(){
            if (!window.confirm('确认删除该 Key？')) return;
            try {
              await request('/v0/management/managed-api-keys/' + item.id, { method: 'DELETE' });
              setStatus('删除成功', '');
              await refreshAll();
            } catch (err) {
              setStatus('', '删除失败：' + err.message);
            }
          });

          right.appendChild(copyBtn);
          right.appendChild(toggleWrap);
          right.appendChild(renewBtn);
          right.appendChild(deleteBtn);

          row.appendChild(left);
          row.appendChild(right);
          container.appendChild(row);
        });
      }

      async function loadServerInfo(){
        var data = await request('/v0/management/server-info', { method: 'GET' });
        state.serverInfo = data || {};

        var baseURL = data.baseURL || data['base-url'] || window.location.origin;
        var master = data.masterApiKey || data['master-api-key'] || '-';
        el('baseURL').textContent = baseURL;
        el('masterKey').textContent = master ? maskKey(master) : '-';
      }

      async function loadKeys(){
        var data = await request('/v0/management/managed-api-keys', { method: 'GET' });
        state.items = (data && data.items) || [];
        renderList();
      }

      function updateCreateModeUI(){
        var mode = state.createMode || 'quota';
        var preset = el('datePreset').value;
        el('modeDateBtn').classList.toggle('active', mode === 'date');
        el('modeQuotaBtn').classList.toggle('active', mode === 'quota');
        el('datePresetField').style.display = mode === 'date' ? '' : 'none';
        el('customDateField').style.display = (mode === 'date' && preset === 'custom') ? '' : 'none';
        el('quotaField').style.display = mode === 'quota' ? '' : 'none';
      }

      function resetCreateForm(){
        el('createName').value = '';
        el('datePreset').value = '7';
        el('customDate').value = '';
        el('quotaLimit').value = '';
        state.createMode = 'quota';
        updateCreateModeUI();
      }

      function setCreateOpen(open){
        el('createPanel').classList.toggle('open', Boolean(open));
        if (open) {
          resetCreateForm();
          setTimeout(function(){ el('createName').focus(); }, 0);
        }
      }

      async function createKey(){
        var name = norm(el('createName').value);
        if (!name) {
          setStatus('', '请填写备注名称');
          return;
        }

        var payload = { name: name };
        var mode = state.createMode;

        if (mode === 'date') {
          var preset = el('datePreset').value;
          if (preset === 'never') {
            // no expires settings
          } else if (preset === 'custom') {
            var iso = toISO(el('customDate').value);
            if (!iso) {
              setStatus('', '自定义日期无效');
              return;
            }
            payload.expiresAt = iso;
          } else {
            payload.durationDays = Number(preset);
          }
        } else {
          var limit = Number(el('quotaLimit').value);
          if (!Number.isFinite(limit) || limit <= 0 || Math.floor(limit) !== limit) {
            setStatus('', '额度必须是正整数');
            return;
          }
          payload.quotaLimit = limit;
        }

        try {
          await request('/v0/management/managed-api-keys', {
            method: 'POST',
            body: JSON.stringify(payload)
          });
          setStatus('创建成功', '');
          setCreateOpen(false);
          await refreshAll();
        } catch (err) {
          setStatus('', '创建失败：' + err.message);
        }
      }

      async function refreshAll(){
        setStatus('', '');
        await loadServerInfo();
        await loadKeys();
      }

      async function handleRediscover(){
        state.token = '';
        setStatus('正在识别管理会话...', '');
        var token = await ensureToken();
        if (!token) {
          setStatus('', '未检测到管理会话。请先在管理后台任一页面登录后，再点“刷新”。');
          return;
        }
        setStatus('已识别管理会话', '');
        await refreshAll();
      }

      function bindEvents(){
        el('backBtn').addEventListener('click', function(){
          window.location.href = '/management.html#/config';
        });

        el('copyBaseBtn').addEventListener('click', function(){
          copy(el('baseURL').textContent || '', 'Base URL');
        });

        el('copyMasterBtn').addEventListener('click', function(){
          var raw = state.serverInfo ? (state.serverInfo.masterApiKey || state.serverInfo['master-api-key']) : '';
          if (!raw) {
            setStatus('', '当前没有可复制的主 API Key');
            return;
          }
          copy(raw, '主 API Key');
        });

        el('refreshBtn').addEventListener('click', function(){
          refreshAll().catch(function(err){
            setStatus('', '刷新失败：' + err.message);
          });
        });

        el('rediscoverBtn').addEventListener('click', function(){
          handleRediscover().catch(function(err){
            setStatus('', '会话识别失败：' + err.message);
          });
        });

        el('sortLatestBtn').addEventListener('click', function(){
          state.sort = 'latest';
          renderList();
        });

        el('sortUsageDescBtn').addEventListener('click', function(){
          state.sort = 'usage_desc';
          renderList();
        });

        el('sortUsageAscBtn').addEventListener('click', function(){
          state.sort = 'usage_asc';
          renderList();
        });

        el('openCreateBtn').addEventListener('click', function(){
          setCreateOpen(true);
        });

        el('cancelCreateBtn').addEventListener('click', function(){
          setCreateOpen(false);
        });

        el('closeCreateBtn').addEventListener('click', function(){
          setCreateOpen(false);
        });

        el('modeDateBtn').addEventListener('click', function(){
          state.createMode = 'date';
          updateCreateModeUI();
        });

        el('modeQuotaBtn').addEventListener('click', function(){
          state.createMode = 'quota';
          updateCreateModeUI();
        });

        el('datePreset').addEventListener('change', updateCreateModeUI);
        el('createPanel').addEventListener('click', function(event){
          if (event.target === el('createPanel')) setCreateOpen(false);
        });
        document.addEventListener('keydown', function(event){
          if (event.key === 'Escape' && el('createPanel').classList.contains('open')) setCreateOpen(false);
        });
        el('createBtn').addEventListener('click', function(){
          createKey().catch(function(err){
            setStatus('', '创建失败：' + err.message);
          });
        });

        window.addEventListener('message', function(event){
          var data = event && event.data;
          if (!data || data.type !== 'cpa-management-auth') return;
          rememberToken(data.token);
        });
      }

      function detectEmbedded(){
        var params = new URLSearchParams(window.location.search || '');
        embedded = params.get('embedded') === '1';
        if (embedded) {
          document.body.classList.add('embedded');
          var backBtn = el('backBtn');
          if (backBtn) backBtn.style.display = 'none';
        }
      }

      async function init(){
        detectEmbedded();
        bindEvents();
        updateCreateModeUI();

        // seed token from parent/global/cache
        rememberToken(readGlobalToken());
        try { rememberToken(localStorage.getItem(TOKEN_CACHE_KEY)); } catch (_) {}

        var token = await ensureToken();
        if (!token) {
          setStatus('', '未检测到管理会话。请先在管理后台任一页面完成登录，然后刷新本页。');
          renderList();
          return;
        }

        try {
          await refreshAll();
        } catch (err) {
          setStatus('', '加载失败：' + err.message);
        }
      }

      init();
    })();
  </script>
</body>
</html>`

func (s *Server) serveManagedAPIKeysPage(c *gin.Context) {
	cfg := s.cfg
	if cfg == nil || cfg.RemoteManagement.DisableControlPanel {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(managedAPIKeysPageHTML))
}

func appendManagementControlPanelPatches(content []byte) []byte {
	if len(content) == 0 {
		return content
	}
	content = stripLegacyManagementAPIKeysNavPatch(content)
	hasUploadPatch := strings.Contains(string(content), managementUploadPatchVersionMarker)
	hasNavPatch := strings.Contains(string(content), managementAPIKeysNavPatchVersionMarker)
	if hasUploadPatch && hasNavPatch {
		return content
	}

	lower := strings.ToLower(string(content))
	idx := strings.LastIndex(lower, "</body>")
	if idx < 0 {
		return content
	}

	out := make([]byte, 0, len(content)+len(managementAuthUploadOverlayPatch)+len(managementAPIKeysNavPatch))
	out = append(out, content[:idx]...)
	if !hasUploadPatch {
		out = append(out, managementAuthUploadOverlayPatch...)
	}
	if !hasNavPatch {
		out = append(out, managementAPIKeysNavPatch...)
	}
	out = append(out, content[idx:]...)
	return out
}

func stripLegacyManagementAPIKeysNavPatch(content []byte) []byte {
	legacyMarkers := []string{
		"cpa-managed-apikey-nav-v1",
		"cpa-managed-apikey-nav-v2",
		"cpa-managed-apikey-nav-v3",
		"cpa-managed-apikey-nav-v4",
		"cpa-managed-apikey-nav-v5",
		"cpa-managed-apikey-nav-v6",
		"cpa-managed-apikey-nav-v7",
	}
	for _, marker := range legacyMarkers {
		if marker == managementAPIKeysNavPatchVersionMarker {
			continue
		}
		content = stripScriptBlockByMarker(content, marker)
	}
	return content
}

func stripScriptBlockByMarker(content []byte, marker string) []byte {
	markerBytes := []byte(marker)
	for {
		idx := bytes.Index(content, markerBytes)
		if idx < 0 {
			return content
		}

		start := bytes.LastIndex(content[:idx], []byte("<script"))
		endRel := bytes.Index(content[idx:], []byte("</script>"))
		if start < 0 || endRel < 0 {
			return content
		}
		end := idx + endRel + len("</script>")

		out := make([]byte, 0, len(content)-(end-start))
		out = append(out, content[:start]...)
		out = append(out, content[end:]...)
		content = out
	}
}
