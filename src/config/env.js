import 'dotenv/config';
import { z } from 'zod';

const envSchema = z.object({
  NODE_ENV: z.string().optional().default('development'),
  PORT: z.coerce.number().int().positive().default(5000),
  MONGODB_URI: z.string().min(1),
  FRONTEND_ORIGIN: z.string().min(1).default('http://localhost:5173'),

  JWT_ACCESS_SECRET: z.string().min(16),
  JWT_REFRESH_SECRET: z.string().min(16),
  JWT_OTP_SECRET: z.string().min(16).default('dev-otp-secret-change-me'),

  REFRESH_COOKIE_NAME: z.string().min(1).default('hp_refresh'),
  REFRESH_COOKIE_SECURE: z.coerce.boolean().default(false),

  // Brevo (Sendinblue) Transactional Email
  BREVO_API_KEY: z.string().optional(),
  BREVO_FROM_EMAIL: z.string().optional(),
  BREVO_FROM_NAME: z.string().optional().default('Hello Paai'),

  // Twilio SMS
  TWILIO_ACCOUNT_SID: z.string().optional(),
  TWILIO_AUTH_TOKEN: z.string().optional(),
  TWILIO_PHONE_NUMBER: z.string().optional(),

  // WhatsApp Business API
  WHATSAPP_PHONE_ID: z.string().optional(),
  WHATSAPP_TOKEN: z.string().optional(),
  WHATSAPP_TEMPLATE_NAME: z.string().optional().default('otp_verification'),
  WHATSAPP_TEMPLATE_LANGUAGE: z.string().optional().default('en_US'),

  // AWS S3
  AWS_ACCESS_KEY_ID: z.string().optional(),
  AWS_SECRET_ACCESS_KEY: z.string().optional(),
  AWS_REGION: z.string().optional(),
  AWS_BUCKET_NAME: z.string().optional(),

  SUPER_ADMIN_EMAIL: z.string().email(),
  SUPER_ADMIN_PASSWORD: z.string().min(6)
});

export const env = envSchema.parse(process.env);

