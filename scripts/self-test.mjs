// Offline self-test. Runs the real handler against a mocked Cainiao response — no network needed.
//   npm test
import crypto from 'node:crypto';
import assert from 'node:assert/strict';

process.env.SHOPIFY_APP_SECRET = 'test_secret';
process.env.SHOPIFY_SHOP_DOMAIN = 'healtence.myshopify.com';

const { default: handler, classify } = await import('../api/track.js');

const SAMPLE = {
  success: true,
  module: [
    {
      mailNo: 'LP00123456789012',
      originCountry: 'China',
      destCountry: 'United States',
      status: 'DELIVERING',
      statusDesc: 'Out for delivery',
      globalEtaInfo: { etaDesc: 'Estimated delivery: Nov 12 - Nov 14', deliveryMinTime: 1762905600000, deliveryMaxTime: 1763078400000 },
      destCpInfo: { cpName: 'USPS', url: 'https://www.usps.com', mailNo: '9400111899223344556677' },
      detailList: [
        { time: 1762850000000, timeStr: '2025-11-11 08:33:20', timeZone: 'GMT-5', desc: '[New York, NY] Out for delivery', standerdDesc: 'Out for delivery' },
        { time: 1762700000000, timeStr: '2025-11-09 14:53:20', desc: 'Arrived at destination country', standerdDesc: 'Arrived at destination' },
        { time: 1762500000000, timeStr: '2025-11-07 07:20:00', desc: 'Customs clearance completed' },
        { time: 1762300000000, timeStr: '2025-11-05 00:46:40', desc: 'Departed from sorting center', group: { cpName: 'Cainiao' } },
        { time: 1762100000000, timeStr: '2025-11-02 18:13:20', desc: 'Order received by logistics provider' },
      ],
      // duplicate event in another nested array, should be de-duplicated
      latestTraceList: [{ time: 1762850000000, desc: '[New York, NY] Out for delivery' }],
    },
  ],
};

let fetchCalls = 0;
globalThis.fetch = async () => {
  fetchCalls += 1;
  return new Response(JSON.stringify(SAMPLE), { status: 200, headers: { 'content-type': 'application/json' } });
};

function signedUrl(params, secret = 'test_secret') {
  const message = Object.entries(params).map(([k, v]) => `${k}=${v}`).sort().join('');
  const signature = crypto.createHmac('sha256', secret).update(message).digest('hex');
  const qs = new URLSearchParams({ ...params, signature });
  return `/api/track?${qs}`;
}

async function call(url) {
  const res = {
    statusCode: 0,
    headers: {},
    body: '',
    setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
    end(b) { this.body = b; },
  };
  await handler({ method: 'GET', url }, res);
  return { status: res.statusCode, json: JSON.parse(res.body) };
}

const base = {
  shop: 'healtence.myshopify.com',
  logged_in_customer_id: '',
  path_prefix: '/apps/track',
  timestamp: String(Math.floor(Date.now() / 1000)),
};

// 1. Valid request
let r = await call(signedUrl({ ...base, tracking_number: 'lp0012 3456 789012' }));
assert.equal(r.status, 200);
assert.equal(r.json.ok, true);
assert.equal(r.json.trackingNumber, 'LP00123456789012');
assert.equal(r.json.status.category, 'out_for_delivery');
assert.equal(r.json.events.length, 5, 'duplicates removed');
assert.equal(r.json.events[0].location, 'New York, NY');
assert.equal(r.json.events[0].description, 'Out for delivery');
assert.equal(r.json.events[0].date, '2025-11-11');
assert.equal(r.json.events.at(-1).category, 'info_received');
assert.equal(r.json.carriers.lastMile.name, 'USPS');
assert.ok(r.json.estimatedDelivery.from);
assert.equal(r.json.cached, false);

// Time-zone aware events without numeric timestamps should still sort by actual instant.
const tzSample = {
  success: true,
  module: [{
    mailNo: 'TZ123456789',
    status: 'IN_TRANSIT',
    statusDesc: 'In transit',
    detailList: [
      { timeStr: '2025-11-11 03:30:00', timeZone: 'GMT-5', desc: 'Arrived at destination' },
      { timeStr: '2025-11-11 09:15:00', timeZone: 'GMT+0', desc: 'Departed from origin' },
    ],
  }],
};
globalThis.fetch = async () => new Response(JSON.stringify(tzSample), { status: 200, headers: { 'content-type': 'application/json' } });
r = await call(signedUrl({ ...base, tracking_number: 'TZ123456789' }));
assert.equal(r.json.events[0].timestamp, '2025-11-11T09:15:00.000Z');
assert.equal(r.json.events[1].timestamp, '2025-11-11T08:30:00.000Z');

// 2. Second call served from cache
r = await call(signedUrl({ ...base, tracking_number: 'LP00123456789012' }));
assert.equal(r.json.cached, true);
assert.equal(fetchCalls, 1);

// 3. Bad signature
r = await call(signedUrl({ ...base, tracking_number: 'LP00123456789012' }, 'wrong_secret'));
assert.equal(r.status, 401);

// 4. Expired timestamp
r = await call(signedUrl({ ...base, timestamp: String(Math.floor(Date.now() / 1000) - 3600), tracking_number: 'LP00123456789012' }));
assert.equal(r.status, 401);

// 5. Wrong shop
r = await call(signedUrl({ ...base, shop: 'other.myshopify.com', tracking_number: 'LP00123456789012' }));
assert.equal(r.status, 401);

// 6. Invalid tracking number
r = await call(signedUrl({ ...base, tracking_number: 'abc' }));
assert.equal(r.json.ok, false);
assert.equal(r.json.error.code, 'INVALID_TRACKING_NUMBER');

// 7. Not found
globalThis.fetch = async () => new Response(JSON.stringify({ success: true, module: [{ mailNo: 'XX123456789', status: 'ORDER_NOT_EXISTS', detailList: [] }] }), { status: 200 });
r = await call(signedUrl({ ...base, tracking_number: 'XX123456789' }));
assert.equal(r.json.error.code, 'NOT_FOUND');

// 8. Anti-bot page
globalThis.fetch = async () => new Response('<html>punish captcha</html>', { status: 200 });
r = await call(signedUrl({ ...base, tracking_number: 'YY123456789' }));
assert.equal(r.json.error.code, 'UPSTREAM_BLOCKED');

// 9. Timeout
globalThis.fetch = async (_u, { signal }) =>
  new Promise((_, reject) => signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' }))));
const t0 = Date.now();
r = await call(signedUrl({ ...base, tracking_number: 'ZZ123456789' }));
assert.equal(r.json.error.code, 'UPSTREAM_TIMEOUT');
assert.ok(Date.now() - t0 < 10_000);

// 10. Classifier spot checks
assert.equal(classify('SIGNIN'), 'delivered');
assert.equal(classify('WAIT4SIGNIN'), 'pickup');
assert.equal(classify('Delivered to airline'), 'in_transit');
assert.equal(classify('Delivered, In/At Mailbox'), 'delivered');
assert.equal(classify('Returned to sender'), 'exception');

console.log('All self-tests passed.');
