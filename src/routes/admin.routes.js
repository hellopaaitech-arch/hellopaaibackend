import { Router } from 'express';
import { z } from 'zod';

import Client from '../models/Client.js';
import User from '../models/User.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { requireAuth, requireRoles, requireSubjectTypes } from '../middleware/auth.js';

const router = Router();

router.use(requireAuth, requireSubjectTypes(['admin']), requireRoles(['super_admin', 'admin']));

router.get(
  '/clients',
  asyncHandler(async (req, res) => {
    const query = req.auth.role === 'super_admin' ? {} : { adminId: req.auth.sub };
    const clients = await Client.find(query).sort({ createdAt: -1 });
    res.json({ clients });
  })
);

router.patch(
  '/clients/:id',
  asyncHandler(async (req, res) => {
    const client = await Client.findById(req.params.id);
    if (!client) return res.status(404).json({ error: 'NotFound', message: 'Client not found' });
    if (req.auth.role === 'admin' && String(client.adminId) !== String(req.auth.sub)) {
      return res.status(403).json({ error: 'Forbidden', message: 'Client not in your scope' });
    }
    const schema = z.object({
      email: z.string().email().optional(),
      password: z.string().min(6).optional(),
      businessName: z.string().optional(),
      fullName: z.string().optional(),
      mobileNumber: z.string().optional(),
      websiteUrl: z.string().optional(),
      gstNumber: z.string().optional(),
      panNumber: z.string().optional(),
      address: z.string().optional(),
      city: z.string().optional(),
      pincode: z.string().optional(),
      businessType: z.string().optional(),
      contactNumber: z.string().optional(),
      logoUrl: z.string().url().optional(),
      loginApproved: z.boolean().optional(),
      isActive: z.boolean().optional()
    });
    const body = schema.parse(req.body);
    const update = { ...body };
    if (body.logoUrl !== undefined) {
      update.businessLogo = body.logoUrl;
      delete update.logoUrl;
    }
    Object.assign(client, update);
    await client.save();
    res.json({ client });
  })
);

router.patch(
  '/clients/:id/approve',
  asyncHandler(async (req, res) => {
    const client = await Client.findById(req.params.id);
    if (!client) return res.status(404).json({ error: 'NotFound', message: 'Client not found' });
    if (client.loginApproved) return res.status(400).json({ error: 'BadRequest', message: 'Already approved' });

    if (req.auth.role === 'super_admin') {
      client.loginApproved = true;
      await client.save();
      return res.json({ client });
    }
    if (!client.adminId) {
      client.loginApproved = true;
      client.adminId = req.auth.sub;
      client.createdBy = req.auth.sub;
      await client.save();
      return res.json({ client });
    }
    if (String(client.adminId) === String(req.auth.sub)) {
      client.loginApproved = true;
      await client.save();
      return res.json({ client });
    }
    return res.status(403).json({ error: 'Forbidden', message: 'Cannot approve this client' });
  })
);

router.get(
  '/users',
  asyncHandler(async (req, res) => {
    if (req.auth.role === 'super_admin') {
      const users = await User.find().sort({ createdAt: -1 }).populate('clientId', 'clientId email businessName profileImage');
      return res.json({ users });
    }

    const clients = await Client.find({ adminId: req.auth.sub }, { _id: 1 });
    const clientIds = clients.map((c) => c._id);
    const users = await User.find({ clientId: { $in: clientIds } })
      .sort({ createdAt: -1 })
      .populate('clientId', 'clientId email businessName');

    return res.json({ users });
  })
);

router.patch(
  '/users/:id',
  asyncHandler(async (req, res) => {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ error: 'NotFound', message: 'User not found' });
    if (req.auth.role === 'admin') {
      const client = await Client.findById(user.clientId);
      if (!client || String(client.adminId) !== String(req.auth.sub)) {
        return res.status(403).json({ error: 'Forbidden', message: 'User not in your scope' });
      }
    }
    const schema = z.object({
      email: z.string().email().optional(),
      password: z.string().min(6).optional(),
      mobile: z.string().optional(),
      name: z.string().optional(),
      clientId: z.string().optional(),
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
    if (body.clientId) user.clientId = body.clientId;
    if (body.logoUrl !== undefined) user.profileImage = body.logoUrl;
    if (body.loginApproved !== undefined) user.loginApproved = body.loginApproved;
    if (body.isActive !== undefined) user.isActive = body.isActive;
    await user.save();
    res.json({ user: user.toJSON ? user.toJSON() : user });
  })
);

export default router;

