import crypto from 'crypto';

export function sha256(input) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

export function randomNumericOtp(length = 6) {
  const digits = '0123456789';
  let out = '';
  for (let i = 0; i < length; i += 1) {
    out += digits[Math.floor(Math.random() * digits.length)];
  }
  return out;
}

