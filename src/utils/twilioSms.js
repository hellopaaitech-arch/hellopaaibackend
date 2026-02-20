import twilio from 'twilio';
import { env } from '../config/env.js';

let twilioClient = null;

function getTwilioClient() {
  if (!twilioClient) {
    const accountSid = env.TWILIO_ACCOUNT_SID;
    const authToken = env.TWILIO_AUTH_TOKEN;

    if (!accountSid || !authToken) {
      throw new Error('Twilio not configured: missing TWILIO_ACCOUNT_SID or TWILIO_AUTH_TOKEN');
    }

    twilioClient = twilio(accountSid, authToken);
  }
  return twilioClient;
}

export async function sendTwilioSms({ toMobile, message }) {
  const client = getTwilioClient();
  const fromNumber = env.TWILIO_PHONE_NUMBER;

  if (!fromNumber) {
    throw new Error('Twilio not configured: missing TWILIO_PHONE_NUMBER');
  }

  // Ensure mobile number is in E.164 format (e.g., +1234567890)
  let formattedMobile = toMobile.trim();
  if (!formattedMobile.startsWith('+')) {
    // If no country code, assume it's a local number - you may want to add country code logic
    // For now, we'll try to send as-is and let Twilio handle it
    formattedMobile = formattedMobile.replace(/^0+/, ''); // Remove leading zeros
  }

  const result = await client.messages.create({
    body: message,
    from: fromNumber,
    to: formattedMobile
  });

  return {
    sid: result.sid,
    status: result.status,
    to: result.to
  };
}
