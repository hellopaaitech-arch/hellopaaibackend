import { env } from '../config/env.js';

/**
 * Send OTP via WhatsApp using Meta WhatsApp Business API
 * @param {Object} params
 * @param {string} params.toMobile - Mobile number in E.164 format (e.g., +1234567890)
 * @param {string} params.otp - 6-digit OTP code
 * @returns {Promise<Object>} API response
 */
export async function sendWhatsAppOtp({ toMobile, otp }) {
  const phoneId = env.WHATSAPP_PHONE_ID;
  const token = env.WHATSAPP_TOKEN;
  const templateName = env.WHATSAPP_TEMPLATE_NAME || 'otp_verification';
  const templateLanguage = env.WHATSAPP_TEMPLATE_LANGUAGE || 'en_US';

  if (!phoneId || !token) {
    throw new Error('WhatsApp not configured: missing WHATSAPP_PHONE_ID or WHATSAPP_TOKEN');
  }

  // Ensure mobile number is in E.164 format
  let formattedMobile = toMobile.trim();
  if (!formattedMobile.startsWith('+')) {
    // If no country code, assume it's a local number
    // You may want to add country code logic here
    formattedMobile = formattedMobile.replace(/^0+/, ''); // Remove leading zeros
    // For now, we'll try to send as-is - Meta API will validate
  }

  const url = `https://graph.facebook.com/v21.0/${phoneId}/messages`;

  // Build components array
  const components = [
    {
      type: 'body',
      parameters: [
        {
          type: 'text',
          text: otp
        }
      ]
    }
  ];

  // If template has buttons (URL or quick reply), add button component
  // Check if button parameters are configured via env
  const buttonUrl = env.WHATSAPP_BUTTON_URL;
  const buttonIndex = env.WHATSAPP_BUTTON_INDEX || 0;
  const hasButtons = env.WHATSAPP_TEMPLATE_HAS_BUTTONS || false;
  
  // If template requires buttons, add button component
  // For URL buttons, provide the URL parameter
  if (hasButtons) {
    components.push({
      type: 'button',
      sub_type: 'url',
      index: buttonIndex,
      parameters: [
        {
          type: 'text',
          text: buttonUrl || 'https://hellopaaitech.com' // Provide URL parameter for button
        }
      ]
    });
  }

  const payload = {
    messaging_product: 'whatsapp',
    to: formattedMobile,
    type: 'template',
    template: {
      name: templateName,
      language: {
        code: templateLanguage
      },
      components
    }
  };

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(
      `WhatsApp API error: ${response.status} ${response.statusText}. ${JSON.stringify(errorData)}`
    );
  }

  const result = await response.json();

  return {
    messageId: result.messages?.[0]?.id,
    status: 'sent',
    to: formattedMobile
  };
}
