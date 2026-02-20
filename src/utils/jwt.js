import jwt from 'jsonwebtoken';
import { env } from '../config/env.js';

export function signAccessToken(payload, opts = {}) {
  return jwt.sign(payload, env.JWT_ACCESS_SECRET, {
    expiresIn: opts.expiresIn ?? '15m',
    issuer: 'hello-paai'
  });
}

export function verifyAccessToken(token) {
  return jwt.verify(token, env.JWT_ACCESS_SECRET, { issuer: 'hello-paai' });
}

export function signRefreshToken(payload, opts = {}) {
  return jwt.sign(payload, env.JWT_REFRESH_SECRET, {
    expiresIn: opts.expiresIn ?? '30d',
    issuer: 'hello-paai'
  });
}

export function verifyRefreshToken(token) {
  return jwt.verify(token, env.JWT_REFRESH_SECRET, { issuer: 'hello-paai' });
}

export function signOtpVerifiedToken(payload, opts = {}) {
  return jwt.sign(payload, env.JWT_OTP_SECRET, {
    expiresIn: opts.expiresIn ?? '15m',
    issuer: 'hello-paai-otp'
  });
}

export function verifyOtpVerifiedToken(token) {
  return jwt.verify(token, env.JWT_OTP_SECRET, { issuer: 'hello-paai-otp' });
}

// Registration token for 4-step registration flow (email verified, mobile pending)
export function signRegistrationToken(payload, opts = {}) {
  return jwt.sign(payload, env.JWT_OTP_SECRET, {
    expiresIn: opts.expiresIn ?? '1h', // 1 hour for registration flow
    issuer: 'hello-paai-registration'
  });
}

export function verifyRegistrationToken(token) {
  return jwt.verify(token, env.JWT_OTP_SECRET, { issuer: 'hello-paai-registration' });
}

