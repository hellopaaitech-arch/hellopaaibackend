import { Router } from 'express';
import { z } from 'zod';

import User from '../models/User.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { requireAuth, requireRoles, requireSubjectTypes } from '../middleware/auth.js';

const router = Router();

router.use(requireAuth, requireSubjectTypes(['client']), requireRoles(['client']));

router.get(
  '/users',
  asyncHandler(async (req, res) => {
    const users = await User.find({ clientId: req.auth.sub })
      .sort({ createdAt: -1 })
      .populate('clientId', 'clientId email businessName');
    res.json({ users });
  })
);

router.patch(
  '/users/:id',
  asyncHandler(async (req, res) => {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ error: 'NotFound', message: 'User not found' });
    if (String(user.clientId) !== String(req.auth.sub)) {
      return res.status(403).json({ error: 'Forbidden', message: 'User not in your scope' });
    }
    const schema = z.object({
      email: z.string().email().optional(),
      password: z.string().min(6).optional(),
      mobile: z.string().optional(),
      name: z.string().optional(),
      dob: z.string().optional(),
      timeOfBirth: z.string().optional(),
      placeOfBirth: z.string().optional(),
      profession: z.string().optional(),
      logoUrl: z.string().url().optional(),
      loginApproved: z.boolean().optional(),
      isActive: z.boolean().optional()
    });
    const body = schema.parse(req.body);
    if (body.email) user.email = body.email.toLowerCase();
    if (body.password) user.password = body.password;
    if (body.mobile !== undefined) user.mobile = body.mobile;
    if (body.name !== undefined) user.profile = { ...(user.profile?.toObject?.() || user.profile || {}), name: body.name };
    if (body.dob !== undefined) user.profile = { ...(user.profile?.toObject?.() || user.profile || {}), dob: body.dob ? new Date(body.dob) : null };
    if (body.timeOfBirth !== undefined) user.profile = { ...(user.profile?.toObject?.() || user.profile || {}), timeOfBirth: body.timeOfBirth };
    if (body.placeOfBirth !== undefined) user.profile = { ...(user.profile?.toObject?.() || user.profile || {}), placeOfBirth: body.placeOfBirth };
    if (body.profession !== undefined) user.profile = { ...(user.profile?.toObject?.() || user.profile || {}), profession: body.profession };
    if (body.logoUrl !== undefined) user.profileImage = body.logoUrl;
    if (body.loginApproved !== undefined) user.loginApproved = body.loginApproved;
    if (body.isActive !== undefined) user.isActive = body.isActive;
    await user.save();
    res.json({ user: user.toJSON ? user.toJSON() : user });
  })
);

export default router;

