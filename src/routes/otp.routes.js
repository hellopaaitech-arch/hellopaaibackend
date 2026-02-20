import { Router } from 'express';
import { z } from 'zod';

import OTP from '../models/OTP.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { randomNumericOtp } from '../utils/crypto.js';
import { signOtpVerifiedToken } from '../utils/jwt.js';
import { env } from '../config/env.js';
import { sendBrevoEmail } from '../utils/brevoEmail.js';
import { sendTwilioSms } from '../utils/twilioSms.js';
import { sendWhatsAppOtp } from '../utils/whatsapp.js';

const router = Router();

router.post(
  '/request',
  asyncHandler(async (req, res) => {
    const schema = z
      .object({
        type: z.enum(['email', 'mobile']),
        email: z.string().email().optional(),
        mobile: z.string().min(6).optional(),
        method: z.enum(['sms', 'whatsapp']).optional().default('sms'), // For mobile OTP: sms or whatsapp
        client: z.string().optional().default('hello-paai')
      })
      .refine((v) => (v.type === 'email' ? !!v.email : !!v.mobile), {
        message: 'Missing destination for OTP'
      });

    const body = schema.parse(req.body);
    
    // Invalidate any existing unused OTPs for this email/mobile before creating a new one
    const query =
      body.type === 'email'
        ? { type: 'email', email: body.email?.toLowerCase(), isUsed: false }
        : { type: 'mobile', mobile: body.mobile, isUsed: false };
    
    await OTP.updateMany(query, { $set: { isUsed: true } });
    
    const otp = randomNumericOtp(6);

    const created = await OTP.create({
      type: body.type,
      email: body.type === 'email' ? body.email?.toLowerCase() : undefined,
      mobile: body.type === 'mobile' ? body.mobile : undefined,
      otp,
      client: body.client
    });

    if (body.type === 'email' && body.email) {
      // Send OTP via Brevo when configured. If not configured, dev flow still works.
      if (env.BREVO_API_KEY && env.BREVO_FROM_EMAIL) {
        const subject = 'Your Hello Paai OTP';
        const text = `Your OTP is ${otp}. It expires in 10 minutes.`;
        const html = `
          <div style="font-family:Arial,sans-serif;line-height:1.5">
            <p>Your OTP is:</p>
            <div style="font-size:24px;font-weight:700;letter-spacing:2px">${otp}</div>
            <p style="color:#666">This OTP expires in 10 minutes.</p>
          </div>
        `;
        await sendBrevoEmail({
          toEmail: body.email.toLowerCase(),
          subject,
          htmlContent: html,
          textContent: text
        });
      }
    }

    if (body.type === 'mobile' && body.mobile) {
      const method = body.method || 'sms';
      
      if (method === 'whatsapp') {
        // Send OTP via WhatsApp when configured
        if (env.WHATSAPP_PHONE_ID && env.WHATSAPP_TOKEN) {
          try {
            await sendWhatsAppOtp({
              toMobile: body.mobile,
              otp
            });
          } catch (err) {
            console.error('[OTP Request] WhatsApp error:', err.message);
            // Fallback to SMS if WhatsApp fails
            if (env.TWILIO_ACCOUNT_SID && env.TWILIO_AUTH_TOKEN && env.TWILIO_PHONE_NUMBER) {
              const message = `Your Hello Paai OTP is ${otp}. It expires in 10 minutes.`;
              await sendTwilioSms({
                toMobile: body.mobile,
                message
              });
            }
          }
        } else if (env.TWILIO_ACCOUNT_SID && env.TWILIO_AUTH_TOKEN && env.TWILIO_PHONE_NUMBER) {
          // Fallback to SMS if WhatsApp not configured
          const message = `Your Hello Paai OTP is ${otp}. It expires in 10 minutes.`;
          await sendTwilioSms({
            toMobile: body.mobile,
            message
          });
        }
      } else {
        // Send OTP via Twilio SMS when configured
        if (env.TWILIO_ACCOUNT_SID && env.TWILIO_AUTH_TOKEN && env.TWILIO_PHONE_NUMBER) {
          const message = `Your Hello Paai OTP is ${otp}. It expires in 10 minutes.`;
          await sendTwilioSms({
            toMobile: body.mobile,
            message
          });
        }
      }
    }

    // For local testing: return OTP only in non-production.
    const response = { ok: true, id: created._id };
    if (env.NODE_ENV !== 'production') response.devOtp = otp;

    return res.status(201).json(response);
  })
);

router.post(
  '/verify',
  asyncHandler(async (req, res) => {
    console.log('[OTP Verify] Request body:', JSON.stringify(req.body, null, 2));
    
    const schema = z
      .object({
        type: z.enum(['email', 'mobile']),
        email: z.string().email().optional(),
        mobile: z.string().min(6).optional(),
        otp: z.string().min(4)
      })
      .refine((v) => (v.type === 'email' ? !!v.email : !!v.mobile), {
        message: 'Missing destination for OTP'
      });
    
    let body;
    try {
      body = schema.parse(req.body);
      console.log('[OTP Verify] Parsed body:', JSON.stringify(body, null, 2));
    } catch (err) {
      if (err instanceof z.ZodError) {
        console.error('[OTP Verify] Validation error:', err.errors);
        return res.status(400).json({
          error: 'BadRequest',
          message: err.errors.map((e) => `${e.path.join('.')}: ${e.message}`).join(', ')
        });
      }
      throw err;
    }

    const query =
      body.type === 'email'
        ? { type: 'email', email: body.email.toLowerCase() }
        : { type: 'mobile', mobile: body.mobile };

    console.log('[OTP Verify] Query:', JSON.stringify(query, null, 2));
    console.log('[OTP Verify] Looking for OTP with:', { ...query, isUsed: false, expiresAt: { $gt: new Date() } });

    const doc = await OTP.findOne({
      ...query,
      isUsed: false,
      expiresAt: { $gt: new Date() }
    }).select('+otp');

    if (!doc) {
      console.log('[OTP Verify] OTP not found or expired');
      return res.status(400).json({
        error: 'BadRequest',
        message: 'OTP not found or expired. Please request a new OTP.'
      });
    }

    console.log('[OTP Verify] Found OTP document. Comparing:', { received: body.otp, stored: doc.otp });
    
    if (doc.otp !== body.otp) {
      console.log('[OTP Verify] OTP mismatch');
      return res.status(400).json({
        error: 'BadRequest',
        message: 'Invalid OTP. Please check and try again.'
      });
    }

    console.log('[OTP Verify] OTP verified successfully');
    doc.isUsed = true;
    await doc.save();

    const verifiedToken = signOtpVerifiedToken({
      type: body.type,
      email: body.type === 'email' ? body.email.toLowerCase() : undefined,
      mobile: body.type === 'mobile' ? body.mobile : undefined
    });

    return res.json({ verifiedToken });
  })
);

export default router;

