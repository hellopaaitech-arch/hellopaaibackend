import { Router } from 'express';
import { z } from 'zod';

import Admin from '../models/Admin.js';
import Client from '../models/Client.js';
import User from '../models/User.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { requireAuth } from '../middleware/auth.js';
import { signAccessToken } from '../utils/jwt.js';

const router = Router();

router.post(
  '/',
  requireAuth,
  asyncHandler(async (req, res) => {
    const schema = z.object({
      targetType: z.enum(['admin', 'client', 'user']),
      targetId: z.string().min(1)
    });
    const { targetType, targetId } = schema.parse(req.body);

    const actor = {
      subjectType: req.auth.subjectType,
      sub: req.auth.sub,
      role: req.auth.role
    };

    const isSuperAdmin = actor.subjectType === 'admin' && actor.role === 'super_admin';
    const isAdmin = actor.subjectType === 'admin' && actor.role === 'admin';
    const isClient = actor.subjectType === 'client' && actor.role === 'client';

    let target = null;
    if (targetType === 'admin') target = await Admin.findById(targetId);
    if (targetType === 'client') target = await Client.findById(targetId);
    if (targetType === 'user') target = await User.findById(targetId);

    if (!target || !target.isActive || !target.loginApproved) {
      return res.status(404).json({ error: 'NotFound', message: 'Target not found/active' });
    }

    if (!isSuperAdmin) {
      if (targetType === 'admin') return res.status(403).json({ error: 'Forbidden', message: 'Not allowed' });

      if (isAdmin) {
        if (targetType === 'client') {
          if (String(target.adminId) !== String(actor.sub)) {
            return res.status(403).json({ error: 'Forbidden', message: 'Client not in your scope' });
          }
        }

        if (targetType === 'user') {
          const user = target;
          const client = await Client.findById(user.clientId);
          if (!client || String(client.adminId) !== String(actor.sub)) {
            return res.status(403).json({ error: 'Forbidden', message: 'User not in your scope' });
          }
        }
      } else if (isClient) {
        if (targetType !== 'user') {
          return res.status(403).json({ error: 'Forbidden', message: 'Not allowed' });
        }
        if (String(target.clientId) !== String(actor.sub)) {
          return res.status(403).json({ error: 'Forbidden', message: 'User not in your scope' });
        }
      } else {
        return res.status(403).json({ error: 'Forbidden', message: 'Not allowed' });
      }
    }

    const role =
      targetType === 'admin' ? target.role : targetType === 'client' ? 'client' : 'user';

    const accessToken = signAccessToken(
      {
        subjectType: targetType,
        sub: String(target._id),
        role,
        impersonated: true,
        actor
      },
      { expiresIn: '10m' }
    );

    return res.json({ accessToken });
  })
);

export default router;

