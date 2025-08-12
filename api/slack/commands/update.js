import crypto from 'crypto';
import fetch from 'node-fetch';

export const config = {
  api: {
    bodyParser: false
  }
};

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => (data += chunk));
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

function verifySlackSignature({ signingSecret, body, timestamp, signature }) {
  if (!timestamp || !signature) return false;
  const base = `v0:${timestamp}:${body}`;
  const hash = 'v0=' + crypto.createHmac('sha256', signingSecret).update(base).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(signature));
  } catch {
    return false;
  }
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).send('Method Not Allowed');
    return;
  }

  const SLACK_SIGNING_SECRET = process.env.SLACK_SIGNING_SECRET;
  const WEBHOOK_URL = process.env.WEBHOOK_URL;

  const rawBody = await readBody(req);
  const ts = req.headers['x-slack-request-timestamp'];
  const sig = req.headers['x-slack-signature'];

  if (!verifySlackSignature({
    signingSecret: SLACK_SIGNING_SECRET,
    body: rawBody,
    timestamp: ts,
    signature: sig
  })) {
    res.status(401).send('invalid signature');
    return;
  }

  res.status(200).json({ response_type: 'ephemeral', text: 'Recap is being generated…' });

  const params = new URLSearchParams(rawBody);
  const text = (params.get('text') || '').trim().toLowerCase();
  const blocks = [
    { type: 'header', text: { type: 'plain_text', text: 'HODL-8568 Daily Recap', emoji: true } },
    { type: 'section', fields: [
      { type: 'mrkdwn', text: '*Performance:* [P/L %, P/L $]' },
      { type: 'mrkdwn', text: '*Portfolio Value:* [$X]' },
    ]},
    { type: 'section', text: { type: 'mrkdwn', text: '*Top Movers:*\n• [Best]\n• [Worst]\n• [Volume]' } },
    { type: 'section', text: { type: 'mrkdwn', text: '*News:*\n• [Headline 1]\n• [Headline 2]' } },
    { type: 'section', text: { type: 'mrkdwn', text: '*Events (tomorrow):*\n• [Earnings/Divs/Econ]' } },
    { type: 'section', text: { type: 'mrkdwn', text: '*Risk:*\n• Drawdown [x%]\n• VaR Δ [x%]\n• Concentration [Top name y%]' } },
    { type: 'context', elements: [
      { type: 'mrkdwn', text: `Triggered by /update ${text ? `(${text})` : ''}` }
    ]}
  ];
  try {
    await fetch(WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ blocks })
    });
  } catch (e) {
    console.error('Webhook post failed', e);
  }
}
