export default function handler(req, res) {
  const expected = 'Bearer ' + (process.env.CRON_SECRET || '');

  if (!process.env.CRON_SECRET) {
    console.warn('[cron] CRON_SECRET is not configured');
    return res.status(500).json({ ok: false, error: 'Cron is not configured' });
  }

  if ((req.headers.authorization || '').trim() !== expected) {
    return res.status(401).json({ ok: false, error: 'Unauthorized' });
  }

  return res.status(200).json({ ok: true, status: 'Cron executed successfully' });
}
