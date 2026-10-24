/* LoginGuard dashboard. Plain JavaScript, no dependencies.
 *
 * Security note: usernames, IP strings and rule details come from log files an attacker can
 * influence. Everything is inserted with textContent / createTextNode (see h()), never innerHTML. */
'use strict';

// ---------------------------------------------------------------- helpers

const $ = (sel, root = document) => root.querySelector(sel);

/** Builds a DOM element. Children are appended as text nodes unless they already are nodes. */
function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : String(v));
    }
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

const SVG_NS = 'http://www.w3.org/2000/svg';
function s(tag, attrs, ...kids) {
  const el = document.createElementNS(SVG_NS, tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, String(v));
    }
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

const nf = new Intl.NumberFormat('en-US');
const fmt = (n) => nf.format(n);
const pad = (n) => String(n).padStart(2, '0');
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const DAY = 86400;

function fmtTime(ts) {
  const d = new Date(ts * 1000);
  return `${MONTHS[d.getUTCMonth()]} ${d.getUTCDate()}, ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
}
function fmtDay(ts) {
  const d = new Date(ts * 1000);
  return `${MONTHS[d.getUTCMonth()]} ${d.getUTCDate()}`;
}

const SEVERITIES = ['low', 'medium', 'high', 'critical']; // index == numeric severity from the API
const SEV_LABEL = { low: 'Low', medium: 'Medium', high: 'High', critical: 'Critical' };

const RULE_LABEL = {
  brute_force: 'Brute force',
  password_spraying: 'Password spraying',
  distributed_attack: 'Distributed attack',
  success_after_failures: 'Login after repeated failures',
  off_hours_login: 'Off-hours login',
  blacklisted_ip: 'Blacklisted IP address',
};
function ruleLabel(rule) {
  if (RULE_LABEL[rule]) return RULE_LABEL[rule];
  if (rule.startsWith('custom:')) return 'Pattern: ' + rule.slice(7).replace(/[_-]+/g, ' ');
  return rule;
}
function factorLabel(name) {
  if (name.startsWith('base:')) return 'Base weight of the rule';
  return ({
    volume: 'Activity well above the threshold',
    blacklisted_ip: 'Source IP is on the blacklist',
    successful_login_from_blacklist: 'Login succeeded from a blacklisted IP',
    privileged_account: 'Privileged account involved',
    campaign_correlation: 'Part of a campaign with several rule types',
  })[name] || name;
}

function debounce(fn, ms) {
  let t;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
}

async function api(path, params) {
  const url = new URL(path, window.location.origin);
  if (params) for (const [k, v] of Object.entries(params)) url.searchParams.set(k, String(v));
  let res;
  try {
    res = await fetch(url, { headers: { Accept: 'application/json' } });
  } catch (e) {
    throw new Error('Cannot reach the LoginGuard server. Is it still running?');
  }
  let body = null;
  try { body = await res.json(); } catch (e) { /* non-JSON error page */ }
  if (!res.ok) throw new Error(body && body.error ? body.error : `Request failed (HTTP ${res.status})`);
  return body;
}

// ---------------------------------------------------------------- state

const state = {
  severities: new Set(),
  rule: '',
  q: '',
  minScore: 0,
  from: null,
  to: null,
  bucketSel: null, // {t, seconds, label} when a timeline period is selected
  cluster: null,
  sort: 'score',
  order: 'desc',
  offset: 0,
  limit: 25,
  bucket: 3600,
  selectedId: null,
};
let summary = null;
let config = null;
let timelineData = null;
let lastTotal = 0;
let alertRequest = 0;

// ---------------------------------------------------------------- overview

function renderRunInfo() {
  const r = summary.run || {};
  const parts = [];
  if (r.source) parts.push(`Analysed ${r.source}`);
  if (r.events_per_sec) parts.push(`${fmt(summary.events.total)} events processed at ${fmt(Math.round(r.events_per_sec))} events per second`);
  if (r.analyzed_at) parts.push(`on ${r.analyzed_at} UTC`);
  $('#run-info').textContent = parts.join(', ');
}

function renderFigures() {
  const e = summary.events;
  const days = Math.max(0, (e.last_ts - e.first_ts) / DAY);
  const rate = e.total ? (e.failure / e.total) * 100 : 0;
  const fig = (label, value, note) =>
    h('div', null, h('dt', { text: label }), h('dd', null, value, note ? h('small', { text: note }) : null));
  $('#figures').replaceChildren(
    fig('Login attempts', fmt(e.total)),
    fig('Failed', fmt(e.failure), `${rate.toFixed(1)}%`),
    fig('Accounts', fmt(e.users)),
    fig('IP addresses', fmt(e.ips)),
    fig('Period', days < 1 ? 'Under a day' : `${days.toFixed(1)} days`),
    fig('Alerts', fmt(summary.alerts.total), `${fmt(summary.alerts.campaigns)} campaigns`),
  );
}

function renderSeverityPills() {
  const box = $('#severity-filter');
  box.replaceChildren();
  for (const sev of ['critical', 'high', 'medium', 'low']) {
    const btn = h('button', {
      type: 'button',
      class: `sev-pill sev-${sev}`,
      'aria-pressed': state.severities.has(sev) ? 'true' : 'false',
      onclick: () => {
        if (state.severities.has(sev)) state.severities.delete(sev); else state.severities.add(sev);
        state.offset = 0;
        renderSeverityPills();
        loadAlerts();
      },
    }, SEV_LABEL[sev], h('b', { text: fmt(summary.alerts.by_severity[sev] || 0) }));
    box.append(btn);
  }
}

// ---------------------------------------------------------------- timeline (hero)

function niceMax(v) {
  if (v <= 1) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  const f = v / p;
  return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * p;
}

function chooseDefaultBucket() {
  const days = (summary.events.last_ts - summary.events.first_ts) / DAY;
  return days <= 10 ? 3600 : days <= 90 ? 21600 : 86400;
}

function selectBucket(t, seconds) {
  const already = state.bucketSel && state.bucketSel.t === t && state.bucketSel.seconds === seconds;
  if (already) {
    state.bucketSel = null; state.from = null; state.to = null;
  } else {
    state.bucketSel = { t, seconds, label: seconds >= DAY ? fmtDay(t) : `${fmtTime(t)} to ${pad(new Date((t + seconds) * 1000).getUTCHours())}:00` };
    state.from = t; state.to = t + seconds - 1;
  }
  state.offset = 0;
  renderTimeline();
  loadAlerts();
}

function renderTimeline() {
  const box = $('#timeline');
  box.replaceChildren();
  if (!timelineData || !timelineData.buckets.length) {
    box.append(h('p', { class: 'empty', text: 'There are no login events to chart.' }));
    return;
  }
  const B = timelineData.bucket_seconds;
  const buckets = timelineData.buckets;
  const byT = new Map(buckets.map((b) => [b.t, b]));
  const first = buckets[0].t;
  const last = buckets[buckets.length - 1].t;
  const n = Math.floor((last - first) / B) + 1;

  const W = Math.max(320, box.clientWidth || 900);
  const H = W < 560 ? 210 : 250;
  const m = { l: 46, r: 8, t: 10, b: 30 };
  const markH = 22;
  const innerW = W - m.l - m.r;
  const plotH = H - m.t - m.b - markH;
  const step = innerW / n;
  const bw = Math.max(1, step - (step > 6 ? 1.5 : 0));
  const maxFail = Math.max(1, ...buckets.map((b) => b.fail));
  const top = niceMax(maxFail);
  const y = (v) => m.t + plotH - (v / top) * plotH;

  const svg = s('svg', { viewBox: `0 0 ${W} ${H}`, focusable: 'false' });
  const grid = s('g', { class: 'grid' });
  const axis = s('g', { class: 'axis' });
  for (const frac of [0, 0.5, 1]) {
    const v = top * frac;
    grid.append(s('line', { x1: m.l, x2: W - m.r, y1: y(v), y2: y(v) }));
    axis.append(s('text', { x: m.l - 8, y: y(v) + 4, 'text-anchor': 'end' }, fmt(Math.round(v))));
  }
  svg.append(grid);

  // x-axis ticks aligned to bucket starts
  const candidates = [3 * 3600, 6 * 3600, 12 * 3600, DAY, 2 * DAY, 7 * DAY, 14 * DAY, 30 * DAY].filter((c) => c >= B && c % B === 0);
  const tickStep = candidates.find((c) => (c / B) * step >= 70) || candidates[candidates.length - 1] || B;
  for (let t = Math.ceil(first / tickStep) * tickStep; t <= last; t += tickStep) {
    const x = m.l + ((t - first) / B) * step + bw / 2;
    const d = new Date(t * 1000);
    const label = tickStep < DAY && d.getUTCHours() !== 0 ? `${pad(d.getUTCHours())}:00` : fmtDay(t);
    axis.append(s('line', { x1: x, x2: x, y1: m.t + plotH, y2: m.t + plotH + 4, stroke: 'currentColor' }));
    axis.append(s('text', { x, y: H - 8, 'text-anchor': 'middle' }, label));
  }
  svg.append(axis);

  const bars = s('g');
  const hits = s('g');
  const marks = s('g');
  for (let i = 0; i < n; i++) {
    const t = first + i * B;
    const b = byT.get(t);
    const x = m.l + i * step;
    const fail = b ? b.fail : 0;
    const ok = b ? b.ok : 0;
    const alerts = b ? b.alerts : 0;
    const selected = state.bucketSel && state.bucketSel.t === t;
    if (fail > 0) {
      const hh = Math.max(1, (fail / top) * plotH);
      bars.append(s('rect', { class: `bar-fail${state.bucketSel && !selected ? ' dim' : ''}`, x, y: m.t + plotH - hh, width: bw, height: hh }));
    }
    const tip = `${fmtTime(t)} UTC: ${fmt(fail)} failed, ${fmt(ok)} successful, ${alerts} ${alerts === 1 ? 'alert' : 'alerts'}`;
    const hit = s('rect', {
      class: selected ? 'bar-sel' : 'bar-hit', x, y: m.t, width: Math.max(step, 2), height: plotH + markH,
      onclick: () => selectBucket(t, B),
      ...(alerts > 0 ? { tabindex: 0, role: 'button', 'aria-label': `${tip}. Filter alerts to this period.` } : {}),
      onkeydown: (ev) => { if (alerts > 0 && (ev.key === 'Enter' || ev.key === ' ')) { ev.preventDefault(); selectBucket(t, B); } },
    }, s('title', null, tip));
    hits.append(hit);
    if (alerts > 0) {
      marks.append(s('circle', { class: `mark s${b.max_severity}`, cx: x + bw / 2, cy: m.t + plotH + 13, r: b.max_severity >= 2 ? 5 : 4 }));
    }
  }
  svg.append(bars, marks, hits);
  box.append(svg);
  box.setAttribute('aria-label', `Failed logins per ${B >= DAY ? 'day' : B >= 3600 * 6 ? '6 hours' : 'hour'} with incident markers`);
}

async function loadTimeline() {
  timelineData = await api('/api/timeline', { bucket: state.bucket });
  renderTimeline();
}

// ---------------------------------------------------------------- alerts table

function alertParams() {
  const p = { sort: state.sort, order: state.order, limit: state.limit, offset: state.offset };
  if (state.severities.size) p.severity = [...state.severities].join(',');
  if (state.rule) p.rule = state.rule;
  if (state.q) p.q = state.q;
  if (state.minScore > 0) p.min_score = state.minScore;
  if (state.from != null) p.from = state.from;
  if (state.to != null) p.to = state.to;
  if (state.cluster != null) p.cluster = state.cluster;
  return p;
}

function hasFilters() {
  return state.severities.size > 0 || state.rule || state.q || state.minScore > 0 || state.from != null || state.cluster != null;
}

function clearFilters() {
  state.severities.clear(); state.rule = ''; state.q = ''; state.minScore = 0;
  state.from = null; state.to = null; state.bucketSel = null; state.cluster = null; state.offset = 0;
  $('#q').value = ''; $('#rule-select').value = ''; $('#min-score').value = '0'; $('#min-score-out').textContent = '0';
  renderSeverityPills();
  renderTimeline();
  loadAlerts();
}

function renderChips() {
  const box = $('#active-filters');
  box.replaceChildren();
  const chip = (text, onRemove) => box.append(h('span', { class: 'chip' }, text, h('button', { type: 'button', 'aria-label': `Remove filter: ${text}`, onclick: onRemove }, '×')));
  if (state.bucketSel) chip(`Period: ${state.bucketSel.label} UTC`, () => selectBucket(state.bucketSel.t, state.bucketSel.seconds));
  if (state.cluster != null) chip(`Campaign ${state.cluster}`, () => { state.cluster = null; state.offset = 0; renderChips(); loadAlerts(); });
  if (state.rule) chip(`Rule: ${ruleLabel(state.rule)}`, () => { state.rule = ''; $('#rule-select').value = ''; state.offset = 0; loadAlerts(); });
  if (state.q) chip(`Search: ${state.q}`, () => { state.q = ''; $('#q').value = ''; state.offset = 0; loadAlerts(); });
  if (state.minScore > 0) chip(`Score at least ${state.minScore}`, () => { state.minScore = 0; $('#min-score').value = '0'; $('#min-score-out').textContent = '0'; state.offset = 0; loadAlerts(); });
}

function pivot(text) {
  state.q = text;
  state.offset = 0;
  $('#q').value = text;
  loadAlerts();
}

function renderAlerts(data) {
  lastTotal = data.total;
  const tbody = $('#alert-rows');
  tbody.replaceChildren();
  if (!data.items.length) {
    tbody.append(h('tr', null, h('td', { colspan: 7, class: 'empty' },
      hasFilters() ? 'No alerts match these filters.' : 'No alerts were raised for this log.',
      hasFilters() ? h('div', null, h('button', { type: 'button', class: 'btn', onclick: clearFilters }, 'Clear filters')) : null)));
  }
  for (const a of data.items) {
    const open = () => openAlert(a.id);
    const linkBtn = (text) => h('button', { type: 'button', class: 'link', title: `Search for ${text}`, onclick: (ev) => { ev.stopPropagation(); pivot(text); } }, text);
    const tr = h('tr', { class: `s${a.severity}${state.selectedId === a.id ? ' is-selected' : ''}`, 'data-id': a.id, onclick: open },
      h('td', { class: 'col-sev' }, h('button', { type: 'button', class: 'link sev-name', 'aria-label': `${SEV_LABEL[a.severity_label]} severity alert ${a.id}: ${ruleLabel(a.rule)}. Open details.`, onclick: (ev) => { ev.stopPropagation(); open(); } }, SEV_LABEL[a.severity_label])),
      h('td', { class: 'col-score' }, h('span', { class: 'score' }, a.score, h('span', { class: 'score-bar', 'aria-hidden': 'true' }, h('i', { 'data-w': a.score })))),
      h('td', { class: 'what' }, h('strong', { text: ruleLabel(a.rule) }), h('span', { text: a.detail })),
      h('td', { class: 'hide-md' }, a.username ? linkBtn(a.username) : '—'),
      h('td', { class: 'hide-md' }, a.ip ? linkBtn(a.ip) : '—'),
      h('td', { class: 'num hide-sm' }, fmt(a.events)),
      h('td', { class: 'col-time', title: `${a.ts_text} UTC` }, fmtTime(a.ts)));
    // CSP forbids inline style attributes, so widths are applied through the CSSOM.
    const fill = tr.querySelector('.score-bar i');
    fill.style.width = `${a.score}%`;
    tbody.append(tr);
  }

  const from = data.total ? data.offset + 1 : 0;
  const to = Math.min(data.offset + data.items.length, data.total);
  $('#page-info').textContent = data.total ? `${fmt(from)} to ${fmt(to)} of ${fmt(data.total)}` : '';
  $('#prev').disabled = data.offset <= 0;
  $('#next').disabled = data.offset + data.limit >= data.total;
  const all = summary.alerts.total;
  $('#result-count').textContent = hasFilters() ? `${fmt(data.total)} of ${fmt(all)} alerts match` : `${fmt(all)} alerts`;
  renderChips();

  for (const th of document.querySelectorAll('.alerts th[data-sort]')) {
    if (th.dataset.sort === state.sort) th.setAttribute('aria-sort', state.order === 'asc' ? 'ascending' : 'descending');
    else th.removeAttribute('aria-sort');
  }
}

async function loadAlerts() {
  const ticket = ++alertRequest;
  try {
    const data = await api('/api/alerts', alertParams());
    if (ticket !== alertRequest) return; // a newer request superseded this one
    renderAlerts(data);
    hideFatal();
  } catch (e) {
    if (ticket === alertRequest) showFatal(e.message);
  }
}

// ---------------------------------------------------------------- side panels

function rankItem(r, maxTotal, onPick, kind) {
  const li = h('li', { class: `s${r.max_severity}` },
    h('button', { type: 'button', class: 'link name', title: `Search alerts for ${r.key}`, onclick: () => onPick(r.key) }, r.key),
    h('span', { class: 'pts', title: 'Sum of alert scores' }, fmt(r.total_score)),
    h('span', { class: 'meter', 'aria-hidden': 'true' }, h('i')),
    h('span', { class: 'sub', text: `${r.alerts} ${r.alerts === 1 ? 'alert' : 'alerts'}, highest score ${r.max_score}, ${fmt(r.failures)} failed logins, ${kind === 'ip' ? `${fmt(r.other)} accounts targeted` : `${fmt(r.other)} IP addresses`}` }));
  li.querySelector('.meter i').style.width = `${Math.max(3, (r.total_score / maxTotal) * 100)}%`;
  return li;
}

function renderRank(sel, rows, kind) {
  const ol = $(sel);
  ol.replaceChildren();
  if (!rows.length) { ol.append(h('li', { class: 'muted small', text: 'Nothing to show.' })); return; }
  const max = Math.max(...rows.map((r) => r.total_score), 1);
  for (const r of rows) ol.append(rankItem(r, max, pivot, kind));
}

function renderRules(rows) {
  const ul = $('#rules');
  ul.replaceChildren();
  if (!rows.length) { ul.append(h('li', { class: 'muted small', text: 'No alerts.' })); return; }
  const max = Math.max(...rows.map((r) => r.alerts), 1);
  for (const r of rows) {
    const li = h('li', { class: `s${r.max_severity}` },
      h('button', { type: 'button', title: 'Show only these alerts', onclick: () => { state.rule = r.rule; $('#rule-select').value = r.rule; state.offset = 0; loadAlerts(); } }, ruleLabel(r.rule)),
      h('span', { text: fmt(r.alerts) }),
      h('span', { class: 'meter', 'aria-hidden': 'true' }, h('i')));
    li.querySelector('.meter i').style.width = `${Math.max(3, (r.alerts / max) * 100)}%`;
    ul.append(li);
  }
}

function renderHours(rows) {
  const box = $('#hours');
  box.replaceChildren();
  const bh = (config && config.business_hours) || { start: 7, end: 20 };
  const inHours = (hr) => (bh.start < bh.end ? hr >= bh.start && hr < bh.end : hr >= bh.start || hr < bh.end);
  const W = Math.max(240, box.clientWidth || 300);
  const H = 120;
  const m = { l: 4, r: 4, t: 6, b: 20 };
  const step = (W - m.l - m.r) / 24;
  const max = Math.max(1, ...rows.map((r) => r.fail));
  const svg = s('svg', { viewBox: `0 0 ${W} ${H}`, focusable: 'false' });
  const axis = s('g', { class: 'axis' });
  rows.forEach((r) => {
    const hh = Math.max(r.fail > 0 ? 1 : 0, (r.fail / max) * (H - m.t - m.b));
    const x = m.l + r.hour * step;
    svg.append(s('rect', { class: `hour-bar${inHours(r.hour) ? ' quiet' : ''}`, x: x + 1, y: H - m.b - hh, width: Math.max(1, step - 2), height: hh },
      s('title', null, `${pad(r.hour)}:00 UTC: ${fmt(r.fail)} failed, ${fmt(r.ok)} successful`)));
    if (r.hour % 6 === 0) axis.append(s('text', { x: x + step / 2, y: H - 5, 'text-anchor': 'middle' }, `${pad(r.hour)}:00`));
  });
  svg.append(axis);
  box.append(svg);
  box.append(h('p', { class: 'muted small', text: 'Darker bars fall outside business hours.' }));
}

function renderCampaigns(rows) {
  const ol = $('#campaigns');
  ol.replaceChildren();
  if (!rows.length) { ol.append(h('li', { class: 'muted small', text: 'No campaigns with more than one alert.' })); return; }
  for (const c of rows) {
    const rules = c.rules.split(',').map(ruleLabel).join(', ');
    ol.append(h('li', null,
      h('div', { class: 'row' },
        h('button', { type: 'button', title: 'Show only this campaign’s alerts', onclick: () => { state.cluster = c.cluster_id; state.offset = 0; loadAlerts(); } }, `Campaign ${c.cluster_id}`),
        h('span', { class: `dot s${c.max_severity}`, title: `${SEV_LABEL[c.severity_label]}, top score ${c.max_score}` }),
      ),
      h('span', { class: 'small', text: `${c.alerts} alerts, top score ${c.max_score}` }),
      h('span', { class: 'small muted', text: rules }),
      h('span', { class: 'small muted', text: `${fmtTime(c.first_ts)} UTC` })));
  }
}

async function loadSide() {
  const jobs = [
    api('/api/top-risk', { by: 'ip', limit: 6 }).then((r) => renderRank('#risk-ips', r, 'ip')),
    api('/api/top-risk', { by: 'user', limit: 6 }).then((r) => renderRank('#risk-users', r, 'user')),
    api('/api/rules').then(renderRules),
    api('/api/hour-of-day').then((rows) => { hourRows = rows; renderHours(rows); }),
    api('/api/campaigns', { min_alerts: 2, limit: 6 }).then(renderCampaigns),
  ];
  await Promise.all(jobs);
}
let hourRows = null;

// ---------------------------------------------------------------- drawer

const drawer = $('#drawer');
const scrim = $('#scrim');
let drawerOpener = null;

function closeDrawer() {
  if (drawer.hidden) return;
  drawer.hidden = true;
  scrim.hidden = true;
  state.selectedId = null;
  for (const tr of document.querySelectorAll('.alerts tr.is-selected')) tr.classList.remove('is-selected');
  if (drawerOpener && document.contains(drawerOpener)) drawerOpener.focus();
  drawerOpener = null;
}

async function openAlert(id) {
  if (drawer.hidden) {
    // Remember where to return focus. A mouse click on a row leaves <body> focused, so fall back to
    // the row's own button, which keeps keyboard users oriented after the drawer closes.
    const active = document.activeElement;
    drawerOpener = active && active !== document.body ? active : document.querySelector(`.alerts tr[data-id="${Number(id)}"] .sev-name`);
  }
  state.selectedId = id;
  for (const tr of document.querySelectorAll('.alerts tbody tr')) tr.classList.toggle('is-selected', Number(tr.dataset.id) === id);
  drawer.hidden = false;
  scrim.hidden = false;
  $('#drawer-title').textContent = `Alert ${id}`;
  $('#drawer-body').replaceChildren(h('p', { class: 'muted', text: 'Loading…' }));
  drawer.focus();
  try {
    const d = await api(`/api/alerts/${id}`);
    if (state.selectedId !== id) return;
    renderDrawer(d);
  } catch (e) {
    $('#drawer-body').replaceChildren(h('p', { class: 'notice', role: 'alert', text: e.message }));
  }
}

function renderDrawer(d) {
  const a = d.alert;
  $('#drawer-title').textContent = ruleLabel(a.rule);
  const sevClass = `s${a.severity}`;
  const body = $('#drawer-body');
  body.replaceChildren();

  const score = h('span', { class: 'd-score' }, a.score);
  score.style.setProperty('--c', `var(--sev-${a.severity_label})`);
  body.append(
    h('div', { class: 'd-top' }, score,
      h('div', null, h('div', { class: 'd-tag', text: `${SEV_LABEL[a.severity_label]} severity` }), h('div', { class: 'muted small', text: `Risk score out of 100, campaign ${a.cluster_id}` }))),
    h('p', { class: 'd-detail', text: a.detail }));

  const meta = h('dl', { class: 'd-meta' });
  const row = (k, v) => { if (v) meta.append(h('dt', { text: k }), h('dd', null, v)); };
  row('Account', a.username ? h('span', { class: 'mono', text: a.username }) : null);
  row('IP address', a.ip ? h('span', { class: 'mono', text: a.ip }) : null);
  row('First seen', `${a.ts_text} UTC`);
  if (a.end_ts !== a.ts) row('Last activity', `${a.end_ts_text} UTC`);
  row('Events in this incident', fmt(a.events));
  const windowed = ['brute_force', 'password_spraying', 'distributed_attack'].includes(a.rule) || a.rule.startsWith('custom:');
  if (windowed) {
    const unit = { brute_force: 'failures', password_spraying: 'distinct accounts', distributed_attack: 'distinct IP addresses' }[a.rule] || 'events';
    row('Peak within the rule window', `${fmt(a.count)} ${unit}`);
  }
  body.append(meta);

  // why this score
  body.append(h('h3', { text: 'Why this score' }));
  const ul = h('ul', { class: 'factors' });
  const maxPts = Math.max(1, ...d.factors.map((f) => Math.abs(f.points)));
  for (const f of d.factors) {
    const li = h('li', null, h('span', { text: factorLabel(f.name) }), h('span', { text: `${f.points > 0 ? '+' : ''}${f.points}` }), h('span', { class: 'meter', 'aria-hidden': 'true' }, h('i')));
    li.querySelector('.meter i').style.width = `${(Math.abs(f.points) / maxPts) * 100}%`;
    li.style.setProperty('--c', `var(--sev-${a.severity_label})`);
    ul.append(li);
  }
  const sum = d.factors.reduce((t, f) => t + f.points, 0);
  ul.append(h('li', { class: 'total' }, h('span', { text: sum > 100 ? 'Total (capped at 100)' : 'Total' }), h('span', { text: a.score })));
  body.append(ul);

  // events
  body.append(h('h3', { text: 'Login attempts behind it' }));
  if (!d.events.length) {
    body.append(h('p', { class: 'muted', text: 'No individual events are stored for this window.' }));
  } else {
    const t = h('table', { class: 'mini' }, h('thead', null, h('tr', null, h('th', { scope: 'col', text: 'Time (UTC)' }), h('th', { scope: 'col', text: 'Account' }), h('th', { scope: 'col', text: 'IP address' }), h('th', { scope: 'col', text: 'Result' }))));
    const tb = h('tbody');
    for (const e of d.events) {
      tb.append(h('tr', null, h('td', { text: e.ts_text.slice(5) }), h('td', { class: 'mono', text: e.username }), h('td', { class: 'mono', text: e.ip }), h('td', { class: e.success ? 'good' : 'bad', text: e.success ? 'Succeeded' : 'Failed' })));
    }
    t.append(tb);
    body.append(t);
    if (d.events_total > d.events.length) body.append(h('p', { class: 'muted small', text: `Showing the first ${fmt(d.events.length)} of ${fmt(d.events_total)} events.` }));
  }

  // campaign
  if (d.campaign.length > 1) {
    body.append(h('h3', { text: `Campaign ${a.cluster_id}: ${d.campaign.length} linked alerts` }));
    const ol = h('ol', { class: 'camp' });
    for (const c of d.campaign) {
      ol.append(h('li', null, h('span', { class: `dot s${c.severity}` }),
        c.id === a.id ? h('strong', { text: `${ruleLabel(c.rule)} (this alert)` }) : h('button', { type: 'button', onclick: () => openAlert(c.id) }, ruleLabel(c.rule)),
        h('span', { class: 'muted small', text: `score ${c.score}, ${c.ts_text.slice(5)}` })));
    }
    body.append(ol);
    body.append(h('p', null, h('button', { type: 'button', class: 'btn', onclick: () => { state.cluster = a.cluster_id; state.offset = 0; closeDrawer(); loadAlerts(); } }, 'Show only this campaign in the alert list')));
  }
}

drawer.addEventListener('keydown', (ev) => {
  if (ev.key !== 'Tab') return;
  const f = [...drawer.querySelectorAll('button, [href], input, select, [tabindex]:not([tabindex="-1"])')].filter((el) => !el.disabled && el.offsetParent !== null);
  if (!f.length) return;
  const first = f[0], last = f[f.length - 1];
  if (ev.shiftKey && (document.activeElement === first || document.activeElement === drawer)) { ev.preventDefault(); last.focus(); }
  else if (!ev.shiftKey && document.activeElement === last) { ev.preventDefault(); first.focus(); }
});
document.addEventListener('keydown', (ev) => { if (ev.key === 'Escape') closeDrawer(); });
scrim.addEventListener('click', closeDrawer);
$('#drawer-close').addEventListener('click', closeDrawer);

// ---------------------------------------------------------------- errors

function showFatal(message) {
  const box = $('#fatal');
  box.textContent = `Something went wrong: ${message}`;
  box.hidden = false;
}
function hideFatal() { $('#fatal').hidden = true; }

// ---------------------------------------------------------------- wiring

function wireControls() {
  $('#q').addEventListener('input', debounce((ev) => { state.q = ev.target.value.trim(); state.offset = 0; loadAlerts(); }, 250));
  $('#filters').addEventListener('submit', (ev) => ev.preventDefault());
  $('#rule-select').addEventListener('change', (ev) => { state.rule = ev.target.value; state.offset = 0; loadAlerts(); });
  const applyScore = debounce(() => { state.offset = 0; loadAlerts(); }, 150);
  $('#min-score').addEventListener('input', (ev) => { state.minScore = Number(ev.target.value); $('#min-score-out').textContent = ev.target.value; applyScore(); });
  $('#clear-filters').addEventListener('click', clearFilters);
  $('#prev').addEventListener('click', () => { state.offset = Math.max(0, state.offset - state.limit); loadAlerts(); });
  $('#next').addEventListener('click', () => { state.offset += state.limit; loadAlerts(); });
  $('#bucket-select').addEventListener('change', async (ev) => {
    state.bucket = Number(ev.target.value);
    state.bucketSel = null; state.from = null; state.to = null; state.offset = 0;
    try { await loadTimeline(); } catch (e) { showFatal(e.message); }
    loadAlerts();
  });
  $('.alerts thead').addEventListener('click', (ev) => {
    const th = ev.target.closest('th[data-sort]');
    if (!th) return;
    const col = th.dataset.sort;
    if (state.sort === col) state.order = state.order === 'asc' ? 'desc' : 'asc';
    else { state.sort = col; state.order = ['score', 'severity', 'events', 'ts'].includes(col) ? 'desc' : 'asc'; }
    state.offset = 0;
    loadAlerts();
  });
  let resizeTimer;
  window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => { renderTimeline(); if (hourRows) renderHours(hourRows); }, 150);
  });
}

function renderFooter() {
  if (!config || !config.rules) return;
  const r = config.rules;
  const bits = [];
  if (r.brute_force) bits.push(`brute force: ${r.brute_force.max_failures} failures within ${r.brute_force.window_seconds} s`);
  if (r.password_spraying) bits.push(`spraying: ${r.password_spraying.distinct_users} accounts within ${r.password_spraying.window_seconds} s`);
  if (r.distributed_attack) bits.push(`distributed: ${r.distributed_attack.distinct_ips} IP addresses within ${r.distributed_attack.window_seconds} s`);
  if (r.success_after_failures) bits.push(`login after failures: ${r.success_after_failures.min_failures} failures within ${r.success_after_failures.window_seconds} s`);
  const bh = config.business_hours;
  $('#config-note').textContent = `Thresholds used for this analysis – ${bits.join('; ')}. Business hours ${pad(bh.start)}:00 to ${pad(bh.end)}:00. Change them in config.json and run the analysis again.`;
}

async function init() {
  wireControls();
  try {
    const [sum, rules, cfg] = await Promise.all([api('/api/summary'), api('/api/rules'), api('/api/config')]);
    summary = sum;
    config = cfg;
    state.bucket = chooseDefaultBucket();
    $('#bucket-select').value = String(state.bucket);
    renderRunInfo();
    renderFigures();
    renderSeverityPills();
    renderFooter();
    const select = $('#rule-select');
    for (const r of rules) select.append(h('option', { value: r.rule, text: `${ruleLabel(r.rule)} (${r.alerts})` }));
    await Promise.all([loadTimeline(), loadAlerts(), loadSide()]);
  } catch (e) {
    showFatal(e.message);
  }
}

init();
