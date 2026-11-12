/**
 * Healtence order tracking — Shopify App Proxy endpoint (Vercel Node.js function)
 *
 * Storefront request:  https://healtence.com/apps/track?tracking_number=LP00123456789
 * Shopify proxies to:  https://<your-app>.vercel.app/api/track?tracking_number=...&shop=...
 *                      &logged_in_customer_id=...&path_prefix=/apps/track&timestamp=...&signature=...
 *
 * Environment variables:
 *   SHOPIFY_APP_SECRET   (required) the app's Client secret. Used to verify the proxy signature.
 *   SHOPIFY_SHOP_DOMAIN  (optional) e.g. healtence.myshopify.com. Rejects requests signed for any other shop.
 *   HIDE_ORIGIN_COUNTRY  (optional) "true" to leave the origin country out of responses.
 */
import crypto from 'node:crypto';

const CAINIAO_ENDPOINT = 'https://global.cainiao.com/detail.json';
const UPSTREAM_TIMEOUT_MS = 8000;
const SIGNATURE_MAX_AGE_SEC = 300;
const UPSTREAM_MAX_PER_MINUTE = 40;
const CACHE_MAX_ENTRIES = 500;
const CACHE_TTL_MS = {
  delivered: 6 * 60 * 60 * 1000,
  active: 20 * 60 * 1000,
  notFound: 5 * 60 * 1000,
};
const STALE_MAX_AGE_MS = 24 * 60 * 60 * 1000;
const MAX_EVENTS = 150;
const TRACKING_RE = /^[A-Z0-9]{8,40}$/;

const HIDE_ORIGIN = /^(1|true|yes)$/i.test(process.env.HIDE_ORIGIN_COUNTRY || '');

const STATUS_LABELS = {
  info_received: 'Order processed',
  in_transit: 'In transit',
  out_for_delivery: 'Out for delivery',
  pickup: 'Ready for pickup',
  delivered: 'Delivered',
  exception: 'Delivery issue',
  unknown: 'Status pending',
};

const ERROR_MESSAGES = {
  METHOD_NOT_ALLOWED: 'Method not allowed.',
  SERVER_MISCONFIGURED: 'Tracking is temporarily unavailable. Please try again later.',
  UNAUTHORIZED: 'This request could not be verified.',
  INVALID_TRACKING_NUMBER: 'Enter a valid tracking number: 8 to 40 letters and numbers, no spaces.',
  NOT_FOUND:
    'There are no updates for this tracking number yet. New shipments usually appear within 2–5 business days of dispatch.',
  RATE_LIMITED: 'Tracking is busy right now. Try again in a minute.',
  UPSTREAM_TIMEOUT: 'The carrier took too long to respond. Try again in a moment.',
  UPSTREAM_RATE_LIMITED: 'Tracking is temporarily unavailable. Try again in a few minutes.',
  UPSTREAM_BLOCKED: 'Tracking is temporarily unavailable. Try again in a few minutes.',
  UPSTREAM_BAD_RESPONSE: 'Tracking is temporarily unavailable. Try again in a few minutes.',
  UPSTREAM_ERROR: 'Tracking is temporarily unavailable. Try again in a few minutes.',
};

const FIELDS = {
  eventTime: ['time', 'eventTime', 'timestamp', 'gmtCreate', 'opTime'],
  eventTimeLocal: ['timeStr', 'eventTimeStr', 'localTime'],
  eventDesc: ['desc', 'eventDesc', 'description', 'message', 'context', 'standerdDesc', 'standardDesc', 'descTitle', 'statusDesc'],
  eventTitle: ['standerdDesc', 'standardDesc', 'descTitle'],
  eventLocation: ['location', 'eventLocation', 'city', 'address', 'position', 'site', 'facility'],
  eventCarrier: ['cpName', 'carrierName', 'carrier', 'logisticsName', 'providerName'],
  eventCode: ['actionCode', 'status', 'eventCode'],
  statusCode: ['status', 'statusCode', 'mailNoStatus'],
  statusText: ['statusDesc', 'statusDescription', 'statusText'],
  originCountry: ['originCountry', 'originCountryName', 'orgCountry', 'sourceCountry', 'shipFromCountry', 'originCountryCode'],
  destCountry: ['destCountry', 'destCountryName', 'destinationCountry', 'shipToCountry', 'destCountryCode'],
  etaObject: ['globalEtaInfo', 'etaInfo', 'eta', 'deliveryEtaInfo'],
  etaText: ['etaDesc', 'deliveryDesc', 'desc', 'etaText'],
  etaMin: ['deliveryMinTime', 'minDeliveryTime', 'etaMinTime', 'startTime'],
  etaMax: ['deliveryMaxTime', 'maxDeliveryTime', 'etaMaxTime', 'endTime'],
};

const cache = new Map();
const inFlight = new Map();
const upstreamWindow = { start: 0, count: 0 };

class TrackingError extends Error {
  constructor(code, detail) {
    super(detail || code);
    this.code = code;
  }
}

export default async function handler(req, res) {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.setHeader('Allow', 'GET, HEAD');
    return send(res, 405, failure('METHOD_NOT_ALLOWED'));
  }

  const secret = process.env.SHOPIFY_APP_SECRET;
  if (!secret) {
    console.error('[track] SHOPIFY_APP_SECRET is not set');
    return send(res, 500, failure('SERVER_MISCONFIGURED'));
  }

  const params = new URL(req.url, 'http://localhost').searchParams;
  const verification = verifyAppProxySignature(params, secret);
  if (!verification.ok) {
    console.warn(`[track] rejected request: ${verification.reason}`);
    return send(res, 401, failure('UNAUTHORIZED'));
  }

  const trackingNumber = normalizeTrackingNumber(params.get('tracking_number'));
  if (!trackingNumber) return send(res, 200, failure('INVALID_TRACKING_NUMBER'));

  const fresh = cacheGet(trackingNumber);
  if (fresh) return send(res, 200, { ...fresh, cached: true });

  try {
    const result = await lookupDeduped(trackingNumber);
    return send(res, 200, { ...result, cached: false });
  } catch (err) {
    const code = err instanceof TrackingError ? err.code : 'UPSTREAM_ERROR';
    console.error(`[track] ${trackingNumber} ${code}: ${err.message}`);
    const stale = cacheGet(trackingNumber, { allowStale: true });
    if (stale && stale.ok) return send(res, 200, { ...stale, cached: true, stale: true });
    return send(res, 200, failure(code, { trackingNumber }));
  }
}

export function verifyAppProxySignature(params, secret) {
  const signature = params.get('signature') || '';
  if (!/^[a-f0-9]{64}$/i.test(signature)) return { ok: false, reason: 'missing or malformed signature' };

  const grouped = new Map();
  for (const [key, value] of params) {
    if (key === 'signature') continue;
    if (!grouped.has(key)) grouped.set(key, []);
    grouped.get(key).push(value);
  }
  const message = [...grouped.entries()]
    .map(([key, values]) => `${key}=${values.join(',')}`)
    .sort()
    .join('');

  const expected = crypto.createHmac('sha256', secret).update(message, 'utf8').digest();
  const received = Buffer.from(signature, 'hex');
  if (expected.length !== received.length || !crypto.timingSafeEqual(expected, received)) {
    return { ok: false, reason: 'signature mismatch' };
  }

  const timestamp = Number(params.get('timestamp'));
  if (!Number.isFinite(timestamp) || Math.abs(Date.now() / 1000 - timestamp) > SIGNATURE_MAX_AGE_SEC) {
    return { ok: false, reason: 'timestamp outside allowed window' };
  }

  const expectedShop = (process.env.SHOPIFY_SHOP_DOMAIN || '').trim().toLowerCase();
  if (expectedShop && (params.get('shop') || '').toLowerCase() !== expectedShop) {
    return { ok: false, reason: 'unexpected shop' };
  }
  return { ok: true };
}

function lookupDeduped(trackingNumber) {
  const pending = inFlight.get(trackingNumber);
  if (pending) return pending;

  if (!takeUpstreamSlot()) {
    return Promise.reject(new TrackingError('RATE_LIMITED', 'local upstream budget exhausted'));
  }

  const promise = (async () => {
    const json = await fetchCainiao(trackingNumber);
    const result = parseCainiao(json, trackingNumber);
    cacheSet(trackingNumber, result);
    return result;
  })().finally(() => inFlight.delete(trackingNumber));

  inFlight.set(trackingNumber, promise);
  return promise;
}

function takeUpstreamSlot() {
  const now = Date.now();
  if (now - upstreamWindow.start >= 60_000) {
    upstreamWindow.start = now;
    upstreamWindow.count = 0;
  }
  if (upstreamWindow.count >= UPSTREAM_MAX_PER_MINUTE) return false;
  upstreamWindow.count += 1;
  return true;
}

function cacheSet(key, value) {
  const ttl = !value.ok
    ? CACHE_TTL_MS.notFound
    : value.status?.category === 'delivered'
      ? CACHE_TTL_MS.delivered
      : CACHE_TTL_MS.active;
  const now = Date.now();
  cache.delete(key);
  cache.set(key, { value, storedAt: now, expiresAt: now + ttl });
  while (cache.size > CACHE_MAX_ENTRIES) cache.delete(cache.keys().next().value);
}

function cacheGet(key, { allowStale = false } = {}) {
  const entry = cache.get(key);
  if (!entry) return null;
  const now = Date.now();
  if (now < entry.expiresAt) return entry.value;
  if (now - entry.storedAt >= STALE_MAX_AGE_MS) {
    cache.delete(key);
    return null;
  }
  return allowStale ? entry.value : null;
}

async function fetchCainiao(trackingNumber) {
  const url = new URL(CAINIAO_ENDPOINT);
  url.searchParams.set('mailNos', trackingNumber);
  url.searchParams.set('lang', 'en-US');
  url.searchParams.set('language', 'en-US');

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
  let response;
  let body;
  try {
    response = await fetch(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'User-Agent':
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        Referer: `https://global.cainiao.com/newDetail.htm?mailNoList=${encodeURIComponent(trackingNumber)}`,
      },
      signal: controller.signal,
    });
    body = await response.text();
  } catch (err) {
    throw new TrackingError(err.name === 'AbortError' ? 'UPSTREAM_TIMEOUT' : 'UPSTREAM_ERROR', err.message);
  } finally {
    clearTimeout(timer);
  }

  if (response.status === 429) throw new TrackingError('UPSTREAM_RATE_LIMITED', 'HTTP 429');
  if (!response.ok) throw new TrackingError('UPSTREAM_ERROR', `HTTP ${response.status}`);

  let json;
  try {
    json = JSON.parse(body);
  } catch {
    const code = looksBlocked(body) ? 'UPSTREAM_BLOCKED' : 'UPSTREAM_BAD_RESPONSE';
    throw new TrackingError(code, `non-JSON body: ${body.slice(0, 160)}`);
  }
  if (!isObject(json)) throw new TrackingError('UPSTREAM_BAD_RESPONSE', 'JSON root is not an object');

  const hasModule = json.module != null || json.data != null;
  if (!hasModule && looksBlocked(JSON.stringify(json).slice(0, 4000))) {
    throw new TrackingError('UPSTREAM_BLOCKED', 'anti-bot challenge returned');
  }
  return json;
}

function looksBlocked(text) {
  return /rgv587_flag|x5secdata|punish|captcha|slide to verify|_____tmd_____/i.test(text || '');
}

export function parseCainiao(json, trackingNumber) {
  const modules = toArray(json.module ?? json.data?.module ?? json.data).filter(isObject);
  const mod = modules.find((m) => normalizeTrackingNumber(m.mailNo) === trackingNumber) || modules[0];
  if (!mod) return failure('NOT_FOUND', { trackingNumber });

  const events = extractEvents(mod);
  const latestTrace = isObject(mod.latestTrace) ? mod.latestTrace : null;

  const statusCode = pick(mod, FIELDS.statusCode) || (latestTrace && pick(latestTrace, FIELDS.eventCode));
  const statusText = cleanText(
    pick(mod, FIELDS.statusText) || (latestTrace && pick(latestTrace, [...FIELDS.eventTitle, 'desc']))
  );

  const codeCategory = classify(statusCode);
  const textCategory = classify(statusText);
  if (!events.length && (!statusText || codeCategory === 'not_found' || textCategory === 'not_found')) {
    return failure('NOT_FOUND', { trackingNumber });
  }

  let category = [textCategory, codeCategory, events[0]?.category].find(
    (c) => c && c !== 'unknown' && c !== 'not_found'
  );
  category = category || 'unknown';

  const originCountry = HIDE_ORIGIN ? null : cleanText(pick(mod, FIELDS.originCountry));
  const destCountry = cleanText(pick(mod, FIELDS.destCountry));

  return {
    ok: true,
    trackingNumber,
    status: {
      category,
      label: STATUS_LABELS[category],
      code: statusCode || null,
      description: statusText || events[0]?.description || STATUS_LABELS[category],
    },
    estimatedDelivery: category === 'delivered' ? null : extractEta(mod),
    origin: originCountry ? { country: originCountry } : null,
    destination: destCountry ? { country: destCountry } : null,
    carriers: {
      origin: carrierFrom(mod.originCpInfo, { name: mod.originCpName }),
      lastMile: carrierFrom(mod.destCpInfo ?? mod.lastMileCpInfo, {
        name: mod.destCpName,
        trackingNumber: mod.lastMileMailNo ?? mod.destMailNo ?? mod.secondMailNo,
      }),
    },
    events,
    fetchedAt: new Date().toISOString(),
  };
}

function extractEvents(mod) {
  const raw = [];
  collectEventArrays(mod, raw, 0, new WeakSet());

  const seen = new Set();
  const events = [];
  for (const item of raw) {
    const event = normalizeEvent(item);
    if (!event) continue;
    const key = `${event.timestamp ?? `${event.date} ${event.time}`}|${event.description.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    events.push(event);
  }

  events.sort((a, b) => b.sortKey - a.sortKey);
  return events.slice(0, MAX_EVENTS).map(({ sortKey, ...event }) => event);
}

function collectEventArrays(node, out, depth, visited) {
  if (depth > 6 || !node || typeof node !== 'object' || visited.has(node)) return;
  visited.add(node);

  if (Array.isArray(node)) {
    const events = node.filter((item) => isObject(item) && looksLikeEvent(item));
    if (events.length) {
      out.push(...events);
      return;
    }
    for (const child of node) collectEventArrays(child, out, depth + 1, visited);
    return;
  }
  for (const value of Object.values(node)) collectEventArrays(value, out, depth + 1, visited);
}

function looksLikeEvent(obj) {
  const hasTime = [...FIELDS.eventTime, ...FIELDS.eventTimeLocal].some((k) => obj[k] != null && obj[k] !== '');
  const hasDesc = FIELDS.eventDesc.some((k) => typeof obj[k] === 'string' && obj[k].trim());
  return hasTime && hasDesc;
}

function normalizeEvent(e) {
  let description = cleanText(pick(e, FIELDS.eventDesc));
  if (!description) return null;

  let location = cleanText(pick(e, FIELDS.eventLocation));
  const bracket = description.match(/^\s*[[【]([^\]】]{2,80})[\]】]\s*(.+)$/s);
  if (bracket) {
    if (!location) location = bracket[1].trim();
    description = bracket[2].trim();
  }

  const title = cleanText(pick(e, FIELDS.eventTitle));
  const localSource = pick(e, FIELDS.eventTimeLocal) || (typeof e.time === 'string' ? e.time : null);
  const timeZone = cleanText(pick(e, ['timeZone', 'timezone', 'gmtOffset', 'offset'])) || null;
  const local = parseLocalDateTime(localSource, timeZone);
  const ms = toMs(pick(e, FIELDS.eventTime, { allowNumbers: true }));
  const sortKey = ms ?? (local?.timestampMs ?? 0);

  let category = classify(`${title || ''} ${description}`);
  if (category === 'unknown' || category === 'not_found') category = classify(pick(e, FIELDS.eventCode));
  if (category === 'unknown' || category === 'not_found') category = 'in_transit';

  return {
    timestamp: ms != null ? new Date(ms).toISOString() : (local?.timestampMs != null ? new Date(local.timestampMs).toISOString() : null),
    date: local?.date ?? null,
    time: local?.time ?? null,
    timeZone,
    location: location || null,
    description,
    title: title && title.toLowerCase() !== description.toLowerCase() ? title : null,
    carrier: cleanText(pick(e, FIELDS.eventCarrier) || (isObject(e.group) ? e.group.cpName : null)) || null,
    category,
    sortKey,
  };
}

function extractEta(mod) {
  const info = FIELDS.etaObject.map((k) => mod[k]).find(isObject) || {};
  const text = cleanText(pick(info, FIELDS.etaText) || mod.etaDesc);
  const from = toIso(pick(info, FIELDS.etaMin, { allowNumbers: true }));
  const to = toIso(pick(info, FIELDS.etaMax, { allowNumbers: true }) ?? mod.estimatedDeliveryTime);
  if (!text && !from && !to) return null;
  return { text: text || null, from, to };
}

function carrierFrom(info, extra = {}) {
  const o = isObject(info) ? info : {};
  const name = cleanText(pick(o, ['cpName', 'name', 'carrierName', 'providerName']) || extra.name);
  const trackingNumber = cleanText(pick(o, ['mailNo', 'trackingNumber'], { allowNumbers: true }) || extra.trackingNumber);
  if (!name && !trackingNumber) return null;
  return {
    name: name || null,
    trackingNumber: trackingNumber || null,
    url: safeUrl(pick(o, ['url', 'cpUrl', 'website', 'trackingUrl'])),
    phone: cleanText(pick(o, ['phone', 'contactPhone', 'cpPhone'], { allowNumbers: true })) || null,
  };
}

export function classify(input) {
  if (!input) return 'unknown';
  const s = String(input).toLowerCase().replace(/_/g, ' ').replace(/\s+/g, ' ').trim();
  if (!s) return 'unknown';

  if (/\bnot (found|exists?)\b|no (tracking )?(info|information|data|record)|order not exist/.test(s)) return 'not_found';
  if (
    /return(ed|ing)? to (sender|seller|origin)|undeliver|delivery (failed|failure|unsuccessful)|failed (delivery|attempt)|attempted delivery|\bexc\b|exception|\blost\b|damaged|refused|address (issue|problem|incorrect|incomplete)|held by customs|customs (hold|issue|exception)/.test(s)
  ) return 'exception';
  if (
    /order (received|placed|created)|label created|shipping (label|information) (created|received)|electronic (notification|information)|pre-?advice|awaiting (the )?(carrier|seller|courier)|waiting for (the )?(carrier|courier|seller|logistics)/.test(s)
  ) return 'info_received';
  if (
    /wait4sign|available for (pick ?up|collection)|ready for (pick ?up|collection)|awaiting (pick ?up|collection) (at|by (the )?(recipient|customer|addressee))|pick ?up point|collection point|parcel (locker|shop)|post office for pick/.test(s)
  ) return 'pickup';
  if (/out for delivery|\bdelivering\b|with (the )?(courier|driver) for delivery|on (its|the) way to (you|the recipient)/.test(s)) return 'out_for_delivery';
  if (
    /\bsign(ed|in)?\b|signed for|\bdelivered\b(?! to (the )?(airline|carrier|courier|logistics|post|sorting|hub|warehouse|facility|local|station|line ?haul|transport))/.test(s)
  ) return 'delivered';
  if (
    /transit|transport|customs|clearance|depart|arriv|shipped|dispatch|\bhub\b|sorting|sorted|facility|airline|flight|accepted|received by|handed over|picked ?up|collected|processing|left|leaving|outbound|inbound|warehouse|delivered to/.test(s)
  ) return 'in_transit';
  return 'unknown';
}

function pick(obj, keys, { allowNumbers = false } = {}) {
  if (!isObject(obj)) return null;
  for (const key of keys) {
    const v = obj[key];
    if (typeof v === 'string' && v.trim()) return v.trim();
    if (allowNumbers && typeof v === 'number' && Number.isFinite(v)) return v;
  }
  return null;
}

function toMs(value) {
  if (value == null || value === '') return null;
  const str = String(value).trim();
  if (typeof value === 'number' || /^\d{9,13}$/.test(str)) {
    let n = Number(str);
    if (!Number.isFinite(n) || n <= 0) return null;
    if (n < 1e11) n *= 1000;
    return n > 1.4e12 && n < 4.1e12 ? n : null;
  }
  if (/^\d{4}-\d{2}-\d{2}T.*(Z|[+-]\d{2}:?\d{2})$/.test(str)) {
    const parsed = Date.parse(str);
    return Number.isNaN(parsed) ? null : parsed;
  }
  return null;
}

function toIso(value) {
  const ms = toMs(value);
  return ms != null ? new Date(ms).toISOString() : null;
}

function parseLocalDateTime(value, timeZoneHint) {
  if (typeof value !== 'string') return null;
  const text = value.trim();
  const m = text.match(/^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})(?:[ T](\d{1,2}):?(\d{2})(?::?(\d{2}))?)?(?:\s*(Z|UTC|GMT)?\s*([+-])(\d{1,2})(?::?(\d{2}))?)?$/i);
  if (!m) return null;

  const [, year, month, day, hour, minute, second, , sign, tzHour, tzMinute] = m;
  const pad = (n) => String(n).padStart(2, '0');
  const date = `${year}-${pad(month)}-${pad(day)}`;
  const time = hour != null ? `${pad(hour)}:${pad(minute || 0)}` : null;
  const offsetMinutes = parseTimeZoneOffset(timeZoneHint, sign, tzHour, tzMinute);

  if (hour == null) return { date, time: null, timestampMs: null };

  const utcMs = Date.UTC(
    Number(year),
    Number(month) - 1,
    Number(day),
    Number(hour),
    Number(minute || 0),
    Number(second || 0),
    0
  );

  const finalOffsetMinutes = offsetMinutes ?? 0;
  const timestampMs = utcMs - finalOffsetMinutes * 60_000;
  return { date, time, timestampMs };
}

function parseTimeZoneOffset(timeZoneHint, sign, tzHour, tzMinute) {
  const zone = cleanText(timeZoneHint || '');
  const candidate = zone.toUpperCase();
  if (candidate === 'Z' || candidate === 'UTC' || candidate === 'GMT') return 0;

  const explicit = candidate.match(/(?:GMT|UTC)?\s*([+-])(\d{1,2})(?::?(\d{2}))?/i);
  if (explicit) {
    const [, dir, hours, minutes = '0'] = explicit;
    const minutesTotal = Number(hours) * 60 + Number(minutes);
    return dir === '-' ? -minutesTotal : minutesTotal;
  }

  if (sign && tzHour) {
    const minutesTotal = Number(tzHour) * 60 + Number(tzMinute || 0);
    return sign === '-' ? -minutesTotal : minutesTotal;
  }

  return null;
}

function cleanText(value) {
  if (value == null) return '';
  return String(value)
    .replace(/<[^>]*>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 500);
}

function safeUrl(value) {
  if (!value) return null;
  try {
    const u = new URL(value);
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.href : null;
  } catch {
    return null;
  }
}

function normalizeTrackingNumber(value) {
  if (value == null) return null;
  const s = String(value).replace(/[\s-]/g, '').toUpperCase();
  return TRACKING_RE.test(s) ? s : null;
}

function toArray(value) {
  if (Array.isArray(value)) return value;
  return value == null ? [] : [value];
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function failure(code, extra = {}) {
  return { ok: false, error: { code, message: ERROR_MESSAGES[code] || ERROR_MESSAGES.UPSTREAM_ERROR }, ...extra };
}

function send(res, status, body) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.end(JSON.stringify(body));
}
