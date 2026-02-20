import Admin from '../models/Admin.js';
import { env } from '../config/env.js';

export async function ensureSuperAdmin() {
  const existing = await Admin.findOne({ role: 'super_admin' });
  if (existing) return;

  await Admin.create({
    email: env.SUPER_ADMIN_EMAIL,
    password: env.SUPER_ADMIN_PASSWORD,
    role: 'super_admin',
    loginApproved: true,
    isActive: true
  });
}
