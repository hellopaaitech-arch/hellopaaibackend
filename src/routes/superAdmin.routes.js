import { Router } from 'express';
import { z } from 'zod';

import Admin from '../models/Admin.js';
import Client from '../models/Client.js';
import User from '../models/User.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { requireAuth, requireRoles, requireSubjectTypes } from '../middleware/auth.js';

const router = Router();

router.use(requireAuth, requireSubjectTypes(['admin']), requireRoles(['super_admin']));

router.get(
  '/admins',
  asyncHandler(async (_req, res) => {
    const admins = await Admin.find().sort({ createdAt: -1 });
    res.json({ admins });
  })
);

router.patch(
  '/admins/:id/approve',
  asyncHandler(async (req, res) => {
    const admin = await Admin.findOneAndUpdate(
      { _id: req.params.id, role: 'admin' },
      { loginApproved: true },
      { new: true }
    );
    if (!admin) return res.status(404).json({ error: 'NotFound', message: 'Admin not found' });
    res.json({ admin });
  })
);

router.patch(
  '/admins/:id',
  asyncHandler(async (req, res) => {
    const schema = z.object({
      email: z.string().email().optional(),
      password: z.string().min(6).optional(),
      loginApproved: z.boolean().optional(),
      isActive: z.boolean().optional()
    });
    const body = schema.parse(req.body);
    const admin = await Admin.findById(req.params.id).select('+password');
    if (!admin) return res.status(404).json({ error: 'NotFound', message: 'Admin not found' });
    if (body.email) admin.email = body.email.toLowerCase();
    if (body.password) admin.password = body.password;
    if (body.loginApproved !== undefined) admin.loginApproved = body.loginApproved;
    if (body.isActive !== undefined) admin.isActive = body.isActive;
    await admin.save();
    res.json({ admin: admin.toJSON ? admin.toJSON() : admin });
  })
);

router.get(
  '/clients',
  asyncHandler(async (_req, res) => {
    const clients = await Client.find().sort({ createdAt: -1 });
    res.json({ clients });
  })
);

router.patch(
  '/clients/:id/approve',
  asyncHandler(async (req, res) => {
    const client = await Client.findOneAndUpdate(
      { _id: req.params.id },
      { loginApproved: true },
      { new: true }
    );
    if (!client) return res.status(404).json({ error: 'NotFound', message: 'Client not found' });
    res.json({ client });
  })
);

router.patch(
  '/clients/:id',
  asyncHandler(async (req, res) => {
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
    const client = await Client.findById(req.params.id);
    if (!client) return res.status(404).json({ error: 'NotFound', message: 'Client not found' });
    if (body.email) client.email = body.email.toLowerCase();
    if (body.password) client.password = body.password;
    if (body.businessName !== undefined) client.businessName = body.businessName;
    if (body.fullName !== undefined) client.fullName = body.fullName;
    if (body.mobileNumber !== undefined) client.mobileNumber = body.mobileNumber;
    if (body.websiteUrl !== undefined) client.websiteUrl = body.websiteUrl;
    if (body.gstNumber !== undefined) client.gstNumber = body.gstNumber;
    if (body.panNumber !== undefined) client.panNumber = body.panNumber;
    if (body.address !== undefined) client.address = body.address;
    if (body.city !== undefined) client.city = body.city;
    if (body.pincode !== undefined) client.pincode = body.pincode;
    if (body.businessType !== undefined) client.businessType = body.businessType;
    if (body.contactNumber !== undefined) client.contactNumber = body.contactNumber;
    if (body.logoUrl !== undefined) client.businessLogo = body.logoUrl;
    if (body.loginApproved !== undefined) client.loginApproved = body.loginApproved;
    if (body.isActive !== undefined) client.isActive = body.isActive;
    await client.save();
    res.json({ client: client.toJSON ? client.toJSON() : client });
  })
);

router.get(
  '/users',
  asyncHandler(async (_req, res) => {
    const users = await User.find().sort({ createdAt: -1 }).populate('clientId', 'clientId email businessName profileImage');
    res.json({ users });
  })
);

router.patch(
  '/users/:id',
  asyncHandler(async (req, res) => {
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
    const user = await User.findById(req.params.id).select('+password');
    if (!user) return res.status(404).json({ error: 'NotFound', message: 'User not found' });
    if (body.email) user.email = body.email.toLowerCase();
    if (body.password) user.password = body.password;
    if (body.mobile !== undefined) user.mobile = body.mobile;
    if (body.name !== undefined) user.profile = { ...user.profile?.toObject?.() || user.profile || {}, name: body.name };
    if (body.dob !== undefined) user.profile = { ...user.profile?.toObject?.() || user.profile || {}, dob: body.dob ? new Date(body.dob) : null };
    if (body.timeOfBirth !== undefined) user.profile = { ...user.profile?.toObject?.() || user.profile || {}, timeOfBirth: body.timeOfBirth };
    if (body.placeOfBirth !== undefined) user.profile = { ...user.profile?.toObject?.() || user.profile || {}, placeOfBirth: body.placeOfBirth };
    if (body.profession !== undefined) user.profile = { ...user.profile?.toObject?.() || user.profile || {}, profession: body.profession };
    if (body.clientId) user.clientId = body.clientId;
    if (body.logoUrl !== undefined) user.profileImage = body.logoUrl;
    if (body.loginApproved !== undefined) user.loginApproved = body.loginApproved;
    if (body.isActive !== undefined) user.isActive = body.isActive;
    await user.save();
    res.json({ user: user.toJSON ? user.toJSON() : user });
  })
);

export default router;

