import crypto from 'node:crypto';
import { Redis } from '@upstash/redis';
import { Ratelimit } from '@upstash/ratelimit';

// ───────────────────────── Config ─────────────────────────
const CAINIAO_ENDPOINT = 'https://global.cainiao.com/detail.json';
const UPSTREAM_TIMEOUT_MS = 8000;
const SIGNATURE_MAX_AGE_SEC = 300;
const MAX_EVENTS = 150;
const TRACKING_RE = /^[A-Z0-9]{8,40}$/;

// Redis Setup
const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

// Global Rate Limiter: Max 100 requests per minute per IP/User to prevent abuse
const ratelimit = new Ratelimit({
  redis: redis,
  limiter: Ratelimit.slidingWindow(100, '1 m'),
});

// Cache TTLs in seconds
const CACHE_TTL = {
  delivered: 21600, // 6 hours
  active: 1200,     // 20 minutes
  notFound: 300,    // 5 minutes
};

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
  INVALID_TRACKING_NUMBER: 'Enter a valid tracking number.',
  NOT_FOUND: 'There are no updates for this tracking number yet.',
  RATE_LIMITED: 'Too many requests. Please try again in a minute.',
  UPSTREAM_TIMEOUT: 'The carrier took too long to respond.',
  UPSTREAM_RATE_LIMITED: 'Tracking is temporarily unavailable.',
  UPSTREAM_BLOCKED: 'Tracking is temporarily unavailable.',
  UPSTREAM_BAD_RESPONSE: 'Tracking is temporarily unavailable.',
  UPSTREAM_ERROR: 'Tracking is temporarily unavailable.',
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

class TrackingError extends Error {
  constructor(code, detail) { super(detail || code); this.code = code; }
}

// ───────────────────────── Handler ─────────────────────────
export default async function handler(req, res) {
  if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, failure('METHOD_NOT_ALLOWED'));

  const secret = process.env.SHOPIFY_APP_SECRET;
  if (!secret) return send(res, 500, failure('SERVER_MISCONFIGURED'));

  const params = new URL(req.url, 'http://localhost').searchParams;
  
  // 1. Signature Verification
  const verification = verifyAppProxySignature(params, secret);
  if (!verification.ok) return send(res, 401, failure('UNAUTHORIZED'));

  // 2. Global Rate Limiting
  const ip = req.headers['x-forwarded-for'] || 'anonymous';
  const { success } = await ratelimit.limit(ip);
  if (!success) return send(res, 429, failure('RATE_LIMITED'));

  const trackingNumber = normalizeTrackingNumber(params.get('tracking_number'));
  if (!trackingNumber) return send(res, 200, failure('INVALID_TRACKING_NUMBER'));

  // 3. Check Redis Cache
  const cacheKey = `track:${trackingNumber}`;
  const cachedData = await redis.get(cacheKey);
  if (cachedData) {
    // If data is already JSON parsed by Upstash, return directly. If string, parse it.
    const parsed = typeof cachedData === 'string' ? JSON.parse(cachedData) : cachedData;
    return send(res, 200, { ...parsed, cached: true });
  }

  // 4. Fetch from Cainiao
  try {
    const json = await fetchCainiao(trackingNumber);
    const result = parseCainiao(json, trackingNumber);
    
    // 5. Save to Redis
    let ttl = !result.ok ? CACHE_TTL.notFound : result.status?.category === 'delivered' ? CACHE_TTL.delivered : CACHE_TTL.active;
    await redis.set(cacheKey, JSON.stringify(result), { ex: ttl });

    return send(res, 200, { ...result, cached: false });
  } catch (err) {
    const code = err instanceof TrackingError ? err.code : 'UPSTREAM_ERROR';
    return send(res, 200, failure(code, { trackingNumber }));
  }
}

// ... (Keep `verifyAppProxySignature`, `fetchCainiao`, `parseCainiao`, `classify`, etc. functions exactly as they are in your original code) ...

// ⚠️ Note for Bhai: Copy paste the helper functions from your original file here (verifyAppProxySignature, extractEvents, classify, etc.). To keep this message short, I didn't paste them again. They remain 100% unchanged.