import crypto from 'node:crypto';
import { Redis } from '@upstash/redis';

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

export const config = { api: { bodyParser: false } };

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  // Verify Shopify Webhook Security
  const hmac = req.headers['x-shopify-hmac-sha256'];
  const secret = process.env.SHOPIFY_APP_SECRET;
  
  const rawBody = await buffer(req);
  const hash = crypto.createHmac('sha256', secret).update(rawBody).digest('base64');
  
  if (hash !== hmac) return res.status(401).end('Unauthorized');

  const payload = JSON.parse(rawBody.toString());
  
  // Extract tracking numbers from the fulfillment payload
  const trackings = payload.tracking_numbers || [];
  
  for (const trackingNumber of trackings) {
    if (!trackingNumber) continue;
    // We just mark it as "Needs Fetch" in Redis so the tracking page or a cron job knows to fetch it
    await redis.set(`pending_track:${trackingNumber}`, 'true', { ex: 86400 }); // 24 hours expiry
  }

  res.status(200).end('Webhook Received');
}

function buffer(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}