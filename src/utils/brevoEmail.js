import { env } from '../config/env.js';

function mustGetBrevoConfig() {
  const apiKey = env.BREVO_API_KEY;
  const fromEmail = env.BREVO_FROM_EMAIL;
  const fromName = env.BREVO_FROM_NAME || 'Hello Paai';

  if (!apiKey) throw new Error('Brevo not configured: missing BREVO_API_KEY');
  if (!fromEmail) throw new Error('Brevo not configured: missing BREVO_FROM_EMAIL');

  return { apiKey, fromEmail, fromName };
}

export async function sendBrevoEmail({ toEmail, subject, htmlContent, textContent }) {
  const { apiKey, fromEmail, fromName } = mustGetBrevoConfig();

  const res = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      accept: 'application/json',
      'content-type': 'application/json',
      'api-key': apiKey
    },
    body: JSON.stringify({
      sender: { email: fromEmail, name: fromName },
      to: [{ email: toEmail }],
      subject,
      htmlContent,
      textContent
    })
  });

  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`Brevo send failed (${res.status}): ${body || res.statusText}`);
  }

  // Brevo returns JSON like { messageId: "..." }
  try {
    return await res.json();
  } catch {
    return { ok: true };
  }
}

