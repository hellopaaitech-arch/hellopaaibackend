import { Router } from 'express';
import { z } from 'zod';

import Admin from '../models/Admin.js';
import Client from '../models/Client.js';
import User from '../models/User.js';
import Session from '../models/Session.js';
import OTP from '../models/OTP.js';

import { asyncHandler } from '../utils/asyncHandler.js';
import { sha256 } from '../utils/crypto.js';
import {
  signAccessToken,
  signRefreshToken,
  signOtpVerifiedToken,
  signRegistrationToken,
  verifyRefreshToken,
  verifyOtpVerifiedToken,
  verifyRegistrationToken
} from '../utils/jwt.js';
import { clearRefreshCookie, setRefreshCookie } from '../utils/authCookies.js';
import { env } from '../config/env.js';
import { requireAuth, requireRoles, requireSubjectTypes } from '../middleware/auth.js';

const router = Router();

function accessPayloadFor(subjectType, subject) {
  if (subjectType === 'admin') {
    return { subjectType, sub: String(subject._id), role: subject.role };
  }
  if (subjectType === 'client') {
    return { subjectType, sub: String(subject._id), role: 'client', clientId: subject.clientId };
  }
  return { subjectType, sub: String(subject._id), role: 'user' };
}

async function createSessionAndTokens({ subjectType, subject, req, res }) {
  const accessToken = signAccessToken(accessPayloadFor(subjectType, subject));
  const refreshToken = signRefreshToken({ subjectType, sub: String(subject._id) });

  const decoded = verifyRefreshToken(refreshToken);
  await Session.create({
    subjectType,
    subjectId: subject._id,
    refreshTokenHash: sha256(refreshToken),
    userAgent: req.headers['user-agent'] || null,
    ip: req.ip || null,
    expiresAt: new Date(decoded.exp * 1000)
  });

  setRefreshCookie(res, refreshToken);

  return { accessToken };
}

router.post(
  '/admin/register',
  asyncHandler(async (req, res) => {
    const schema = z.object({
      email: z.string().email(),
      password: z.string().min(6),
      emailVerifiedToken: z.string().min(1)
    });
    const body = schema.parse(req.body);

    const verified = verifyOtpVerifiedToken(body.emailVerifiedToken);
    if (verified.type !== 'email' || verified.email?.toLowerCase() !== body.email.toLowerCase()) {
      return res.status(400).json({ error: 'BadRequest', message: 'Email OTP not verified' });
    }

    const created = await Admin.create({
      email: body.email,
      password: body.password,
      role: 'admin',
      loginApproved: false,
      isActive: true
    });

    return res.status(201).json({ admin: created });
  })
);

router.post(
  '/client/register',
  asyncHandler(async (req, res) => {
    const schema = z.object({
      email: z.string().email(),
      password: z.string().min(6),
      emailVerifiedToken: z.string().min(1),
      businessName: z.string().optional(),
      fullName: z.string().optional(),
      mobileNumber: z.string().optional(),
      logoUrl: z.string().url().optional()
    });
    const body = schema.parse(req.body);

    const verified = verifyOtpVerifiedToken(body.emailVerifiedToken);
    if (verified.type !== 'email' || verified.email?.toLowerCase() !== body.email.toLowerCase()) {
      return res.status(400).json({ error: 'BadRequest', message: 'Email OTP not verified' });
    }

    const created = await Client.create({
      email: body.email,
      password: body.password,
      businessName: body.businessName,
      fullName: body.fullName,
      mobileNumber: body.mobileNumber,
      businessLogo: body.logoUrl,
      loginApproved: false,
      isActive: true
    });

    return res.status(201).json({ client: created });
  })
);

router.post(
  '/admin/create',
  requireAuth,
  requireSubjectTypes(['admin']),
  requireRoles(['super_admin']),
  asyncHandler(async (req, res) => {
    const schema = z.object({
      email: z.string().email(),
      password: z.string().min(6),
      loginApproved: z.boolean().optional().default(true),
      isActive: z.boolean().optional().default(true)
    });
    const body = schema.parse(req.body);

    const created = await Admin.create({
      email: body.email,
      password: body.password,
      role: 'admin',
      createdBy: req.auth.sub,
      loginApproved: body.loginApproved,
      isActive: body.isActive
    });

    return res.status(201).json({ admin: created });
  })
);

router.post(
  '/client/create',
  requireAuth,
  requireSubjectTypes(['admin']),
  requireRoles(['super_admin', 'admin']),
  asyncHandler(async (req, res) => {
    const schema = z.object({
      email: z.string().email(),
      password: z.string().min(6),
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
      loginApproved: z.boolean().optional().default(true),
      isActive: z.boolean().optional().default(true)
    });
    const body = schema.parse(req.body);

    const created = await Client.create({
      email: body.email,
      password: body.password,
      businessName: body.businessName,
      fullName: body.fullName,
      mobileNumber: body.mobileNumber,
      websiteUrl: body.websiteUrl,
      businessLogo: body.logoUrl,
      gstNumber: body.gstNumber,
      panNumber: body.panNumber,
      address: body.address,
      city: body.city,
      pincode: body.pincode,
      businessType: body.businessType,
      contactNumber: body.contactNumber,
      createdBy: req.auth.sub,
      adminId: req.auth.sub,
      loginApproved: body.loginApproved,
      isActive: body.isActive
    });

    return res.status(201).json({ client: created });
  })
);

router.post(
  '/user/create',
  requireAuth,
  asyncHandler(async (req, res) => {
    const schema = z.object({
      email: z.string().email(),
      password: z.string().min(6),
      mobile: z.string().optional(),
      name: z.string().optional(),
      dob: z.string().optional(),
      timeOfBirth: z.string().optional(),
      placeOfBirth: z.string().optional(),
      gowthra: z.string().optional(),
      logoUrl: z.string().url().optional(),
      loginApproved: z.boolean().optional().default(true),
      isActive: z.boolean().optional().default(true),
      clientId: z.string().optional()
    });
    const body = schema.parse(req.body);

    let clientIdObj = null;

    if (req.auth.subjectType === 'client') {
      clientIdObj = req.auth.sub;
    } else if (req.auth.subjectType === 'admin') {
      if (!body.clientId) {
        return res.status(400).json({ error: 'BadRequest', message: 'clientId required' });
      }
      const client = await Client.findById(body.clientId);
      if (!client) {
        return res.status(400).json({ error: 'BadRequest', message: 'Client not found' });
      }
      if (req.auth.role === 'admin' && String(client.adminId) !== String(req.auth.sub)) {
        return res.status(403).json({ error: 'Forbidden', message: 'Client not in your scope' });
      }
      clientIdObj = client._id;
    } else {
      return res.status(403).json({ error: 'Forbidden', message: 'Not allowed' });
    }

    const profile = {};
    if (body.name) profile.name = body.name;
    if (body.dob) profile.dob = new Date(body.dob);
    if (body.timeOfBirth) profile.timeOfBirth = body.timeOfBirth;
    if (body.placeOfBirth) profile.placeOfBirth = body.placeOfBirth;
    if (body.gowthra) profile.gowthra = body.gowthra;

    const created = await User.create({
      email: body.email,
      password: body.password,
      mobile: body.mobile,
      profile: Object.keys(profile).length > 0 ? profile : undefined,
      profileImage: body.logoUrl,
      clientId: clientIdObj,
      loginApproved: body.loginApproved,
      isActive: body.isActive,
      emailVerified: true,
      mobileVerified: !!body.mobile
    });

    return res.status(201).json({ user: created });
  })
);

// Get registration data (for step 3 - to know email/clientCode)
router.get(
  '/user/register/data',
  asyncHandler(async (req, res) => {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice('Bearer '.length) : null;
    if (!token) {
      return res.status(401).json({ error: 'Unauthorized', message: 'Registration token required' });
    }

    let regData;
    try {
      regData = verifyRegistrationToken(token);
    } catch {
      return res.status(401).json({ error: 'Unauthorized', message: 'Invalid or expired registration token' });
    }

    return res.json({
      email: regData.email,
      clientCode: regData.clientCode,
      emailVerified: regData.emailVerified,
      mobileVerified: regData.mobileVerified,
      mobile: regData.mobile,
      profile: regData.profile,
      logoUrl: regData.logoUrl
    });
  })
);

// Step 2: Mobile verification (uses registrationToken from step 1)
router.post(
  '/user/register/mobile-verify',
  asyncHandler(async (req, res) => {
    const schema = z.object({
      registrationToken: z.string().min(1),
      mobile: z.string().min(6),
      otp: z.string().min(4)
    });
    const body = schema.parse(req.body);

    // Verify registration token
    let regData;
    try {
      regData = verifyRegistrationToken(body.registrationToken);
    } catch {
      return res.status(400).json({ error: 'BadRequest', message: 'Invalid or expired registration token' });
    }

    if (!regData.emailVerified) {
      return res.status(400).json({ error: 'BadRequest', message: 'Email not verified' });
    }

    // Verify mobile OTP
    const doc = await OTP.findOne({
      type: 'mobile',
      mobile: body.mobile,
      isUsed: false,
      expiresAt: { $gt: new Date() }
    }).select('+otp');
    
    if (!doc || doc.otp !== body.otp) {
      return res.status(400).json({ error: 'BadRequest', message: 'Invalid OTP' });
    }
    
    doc.isUsed = true;
    await doc.save();

    // Return mobile verified token
    const mobileVerifiedToken = signOtpVerifiedToken({ type: 'mobile', mobile: body.mobile });
    
    // Update registration token with mobile verified
    const updatedRegistrationToken = signRegistrationToken({
      email: regData.email,
      emailVerified: true,
      mobile: body.mobile,
      mobileVerified: true,
      clientCode: regData.clientCode
    });

    return res.json({ mobileVerifiedToken, registrationToken: updatedRegistrationToken });
  })
);

// Step 3: Save profile details + image (requires registrationToken bearer)
router.post(
  '/user/register/profile',
  asyncHandler(async (req, res) => {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice('Bearer '.length) : null;
    if (!token) {
      return res.status(401).json({ error: 'Unauthorized', message: 'Registration token required' });
    }

    let regData;
    try {
      regData = verifyRegistrationToken(token);
    } catch {
      return res.status(401).json({ error: 'Unauthorized', message: 'Invalid or expired registration token' });
    }

    if (!regData.emailVerified || !regData.mobileVerified) {
      return res.status(400).json({ error: 'BadRequest', message: 'Email and mobile must be verified' });
    }

    const schema = z.object({
      clientCode: z.string().min(1).optional(), // Can update if not set in step 1
      name: z.string().optional(),
      dob: z.string().optional(),
      timeOfBirth: z.string().optional(),
      placeOfBirth: z.string().optional(),
      gowthra: z.string().optional(),
      nativeLanguage: z.string().optional(),
      logoUrl: z.union([z.string().url(), z.literal('')]).optional(),
      liveLocation: z.object({
        latitude: z.number().optional(),
        longitude: z.number().optional(),
        formattedAddress: z.string().optional(),
        city: z.string().optional(),
        state: z.string().optional(),
        country: z.string().optional()
      }).optional()
    });
    const body = schema.parse(req.body);

    // Update registration token with profile data
    const clientCode = body.clientCode?.toUpperCase() || regData.clientCode;
    if (!clientCode) {
      return res.status(400).json({ error: 'BadRequest', message: 'clientCode required' });
    }

    const updatedRegistrationToken = signRegistrationToken({
      email: regData.email,
      emailVerified: true,
      mobile: regData.mobile,
      mobileVerified: true,
      clientCode,
      profile: {
        name: body.name,
        dob: body.dob,
        timeOfBirth: body.timeOfBirth,
        placeOfBirth: body.placeOfBirth,
        gowthra: body.gowthra,
        nativeLanguage: body.nativeLanguage
      },
      logoUrl: body.logoUrl,
      liveLocation: body.liveLocation
    });

    return res.json({ registrationToken: updatedRegistrationToken, profileSaved: true });
  })
);

// Step 4: Complete registration (uses registrationToken + password)
router.post(
  '/user/register/complete',
  asyncHandler(async (req, res) => {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice('Bearer '.length) : null;
    if (!token) {
      return res.status(401).json({ error: 'Unauthorized', message: 'Registration token required' });
    }

    let regData;
    try {
      regData = verifyRegistrationToken(token);
    } catch {
      return res.status(401).json({ error: 'Unauthorized', message: 'Invalid or expired registration token' });
    }

    if (!regData.emailVerified || !regData.mobileVerified || !regData.clientCode) {
      return res.status(400).json({ error: 'BadRequest', message: 'All steps must be completed' });
    }

    const schema = z.object({
      password: z.string().min(6)
    });
    const body = schema.parse(req.body);

    const client = await Client.findOne({ clientId: regData.clientCode, isActive: true });
    if (!client) {
      return res.status(400).json({ error: 'BadRequest', message: 'Invalid client ID' });
    }

    const profile = regData.profile || {};
    const liveLocation = regData.liveLocation ? {
      ...regData.liveLocation,
      lastUpdated: new Date()
    } : undefined;

    const created = await User.create({
      email: regData.email,
      mobile: regData.mobile,
      password: body.password,
      emailVerified: true,
      mobileVerified: true,
      loginApproved: true,
      isActive: true,
      clientId: client._id,
      profile: Object.keys(profile).length > 0 ? profile : undefined,
      profileImage: regData.logoUrl || undefined,
      liveLocation
    });

    // Auto-login after registration
    const { accessToken } = await createSessionAndTokens({ subjectType: 'user', subject: created, req, res });

    return res.status(201).json({ user: created, accessToken });
  })
);

// Legacy: Old user register endpoint (kept for backward compatibility)
router.post(
  '/user/register',
  asyncHandler(async (req, res) => {
    const schema = z.object({
      clientCode: z.string().min(1),
      email: z.string().email(),
      mobile: z.string().min(6),
      password: z.string().min(6),
      emailVerifiedToken: z.string().min(1),
      mobileVerifiedToken: z.string().min(1),
      name: z.string().optional(),
      dob: z.string().optional(),
      timeOfBirth: z.string().optional(),
      placeOfBirth: z.string().optional(),
      gowthra: z.string().optional(),
      nativeLanguage: z.string().optional(),
      logoUrl: z.union([z.string().url(), z.literal('')]).optional(),
      liveLocation: z.object({
        latitude: z.number().optional(),
        longitude: z.number().optional(),
        formattedAddress: z.string().optional(),
        city: z.string().optional(),
        state: z.string().optional(),
        country: z.string().optional()
      }).optional()
    });
    const body = schema.parse(req.body);

    const emailV = verifyOtpVerifiedToken(body.emailVerifiedToken);
    const mobileV = verifyOtpVerifiedToken(body.mobileVerifiedToken);

    if (emailV.type !== 'email' || emailV.email?.toLowerCase() !== body.email.toLowerCase()) {
      return res.status(400).json({ error: 'BadRequest', message: 'Email OTP not verified' });
    }
    if (mobileV.type !== 'mobile' || mobileV.mobile !== body.mobile) {
      return res.status(400).json({ error: 'BadRequest', message: 'Mobile OTP not verified' });
    }

    const client = await Client.findOne({ clientId: body.clientCode.toUpperCase(), isActive: true });
    if (!client) {
      return res.status(400).json({ error: 'BadRequest', message: 'Invalid client ID' });
    }

    const profile = {};
    if (body.name) profile.name = body.name;
    if (body.dob) profile.dob = new Date(body.dob);
    if (body.timeOfBirth) profile.timeOfBirth = body.timeOfBirth;
    if (body.placeOfBirth) profile.placeOfBirth = body.placeOfBirth;
    if (body.gowthra) profile.gowthra = body.gowthra;
    if (body.nativeLanguage) profile.nativeLanguage = body.nativeLanguage;

    const liveLocation = body.liveLocation ? {
      latitude: body.liveLocation.latitude,
      longitude: body.liveLocation.longitude,
      formattedAddress: body.liveLocation.formattedAddress,
      city: body.liveLocation.city,
      state: body.liveLocation.state,
      country: body.liveLocation.country,
      lastUpdated: new Date()
    } : undefined;

    const created = await User.create({
      email: body.email,
      mobile: body.mobile,
      password: body.password,
      emailVerified: true,
      mobileVerified: true,
      loginApproved: true,
      isActive: true,
      clientId: client._id,
      profile: Object.keys(profile).length > 0 ? profile : { name: body.name },
      profileImage: body.logoUrl || undefined,
      liveLocation
    });

    return res.status(201).json({ user: created });
  })
);

router.post(
  '/admin/login',
  asyncHandler(async (req, res) => {
    const schema = z.object({ email: z.string().email(), password: z.string().min(1) });
    const { email, password } = schema.parse(req.body);

    const admin = await Admin.findOne({ email: email.toLowerCase() }).select('+password');
    if (!admin || !admin.isActive) {
      return res.status(401).json({ error: 'Unauthorized', message: 'Invalid credentials' });
    }
    if (!admin.loginApproved) {
      return res.status(403).json({ error: 'Forbidden', message: 'Login not approved' });
    }
    const ok = await admin.comparePassword(password);
    if (!ok) return res.status(401).json({ error: 'Unauthorized', message: 'Invalid credentials' });

    const { accessToken } = await createSessionAndTokens({ subjectType: 'admin', subject: admin, req, res });
    return res.json({ accessToken, admin: admin.toJSON() });
  })
);

router.post(
  '/client/login',
  asyncHandler(async (req, res) => {
    const schema = z.object({ email: z.string().email(), password: z.string().min(1) });
    const { email, password } = schema.parse(req.body);

    const client = await Client.findOne({ email: email.toLowerCase() }).select('+password');
    if (!client || !client.isActive) {
      return res.status(401).json({ error: 'Unauthorized', message: 'Invalid credentials' });
    }
    if (!client.loginApproved) {
      return res.status(403).json({ error: 'Forbidden', message: 'Login not approved' });
    }
    const ok = await client.comparePassword(password);
    if (!ok) return res.status(401).json({ error: 'Unauthorized', message: 'Invalid credentials' });

    const { accessToken } = await createSessionAndTokens({ subjectType: 'client', subject: client, req, res });
    return res.json({ accessToken, client: client.toJSON() });
  })
);

// AI Email Sign-in: Email is automatically verified (no OTP needed)
// Returns registrationToken if user doesn't exist, or accessToken if exists
router.post(
  '/user/email-signin',
  asyncHandler(async (req, res) => {
    const schema = z.object({ 
      email: z.string().email(),
      clientCode: z.string().min(1).optional() // Optional: can be set in step 1
    });
    const { email, clientCode } = schema.parse(req.body);
    const emailLower = email.toLowerCase();

    const user = await User.findOne({ email: emailLower, isActive: true });
    
    if (user && user.loginApproved) {
      // User exists and approved - login
      const { accessToken } = await createSessionAndTokens({ subjectType: 'user', subject: user, req, res });
      return res.json({ accessToken, exists: true, user: user.toJSON() });
    }

    // User doesn't exist or not approved - create registration token
    // Email is considered verified (AI sign-in = verified)
    const registrationToken = signRegistrationToken({ 
      email: emailLower,
      emailVerified: true,
      clientCode: clientCode?.toUpperCase() || null
    });

    return res.json({ 
      exists: false, 
      registrationToken,
      email: emailLower 
    });
  })
);

// Email OTP Sign-in (optional): verify email OTP and return registrationToken (new user) or accessToken (existing user)
router.post(
  '/user/email-signin/verify',
  asyncHandler(async (req, res) => {
    const schema = z
      .object({
        email: z.string().email(),
        otp: z.string().min(4).optional(),
        emailVerifiedToken: z.string().min(1).optional(),
        clientCode: z.string().min(1).optional()
      })
      .refine((v) => !!v.otp || !!v.emailVerifiedToken, { message: 'otp or emailVerifiedToken required' });

    const body = schema.parse(req.body);
    const emailLower = body.email.toLowerCase();

    if (body.emailVerifiedToken) {
      const verified = verifyOtpVerifiedToken(body.emailVerifiedToken);
      if (verified.type !== 'email' || verified.email?.toLowerCase() !== emailLower) {
        return res.status(400).json({ error: 'BadRequest', message: 'Invalid email verification token' });
      }
    } else {
      const doc = await OTP.findOne({
        type: 'email',
        email: emailLower,
        isUsed: false,
        expiresAt: { $gt: new Date() }
      }).select('+otp');

      if (!doc || doc.otp !== body.otp) {
        return res.status(400).json({ error: 'BadRequest', message: 'Invalid OTP' });
      }
      doc.isUsed = true;
      await doc.save();
    }

    const user = await User.findOne({ email: emailLower, isActive: true });
    if (user) {
      if (!user.loginApproved) {
        return res.status(403).json({ error: 'Forbidden', message: 'Login not approved' });
      }
      const { accessToken } = await createSessionAndTokens({ subjectType: 'user', subject: user, req, res });
      return res.json({ accessToken, exists: true, user: user.toJSON() });
    }

    const registrationToken = signRegistrationToken({
      email: emailLower,
      emailVerified: true,
      clientCode: body.clientCode?.toUpperCase() || null
    });

    return res.json({ exists: false, registrationToken, email: emailLower });
  })
);

router.post(
  '/user/login',
  asyncHandler(async (req, res) => {
    const schema = z.object({ email: z.string().email(), password: z.string().min(1) });
    const { email, password } = schema.parse(req.body);

    const user = await User.findOne({ email: email.toLowerCase() }).select('+password');
    if (!user || !user.isActive) {
      return res.status(401).json({ error: 'Unauthorized', message: 'Invalid credentials' });
    }
    if (!user.loginApproved) {
      return res.status(403).json({ error: 'Forbidden', message: 'Login not approved' });
    }
    const ok = await user.comparePassword(password);
    if (!ok) return res.status(401).json({ error: 'Unauthorized', message: 'Invalid credentials' });

    const { accessToken } = await createSessionAndTokens({ subjectType: 'user', subject: user, req, res });
    return res.json({ accessToken, user: user.toJSON() });
  })
);

router.get(
  '/me',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { subjectType, sub } = req.auth;
    if (subjectType === 'admin') {
      const admin = await Admin.findById(sub);
      return res.json({ subjectType, subject: admin });
    }
    if (subjectType === 'client') {
      const client = await Client.findById(sub);
      return res.json({ subjectType, subject: client });
    }
    const user = await User.findById(sub);
    return res.json({ subjectType, subject: user });
  })
);

router.patch(
  '/me',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { subjectType, sub } = req.auth;

    if (subjectType === 'admin') {
      const schema = z.object({
        email: z.string().email().optional(),
        password: z.string().min(6).optional()
      });
      const body = schema.parse(req.body);
      const admin = await Admin.findById(sub).select('+password');
      if (!admin) return res.status(404).json({ error: 'NotFound', message: 'Admin not found' });
      if (body.email) admin.email = body.email.toLowerCase();
      if (body.password) admin.password = body.password;
      await admin.save();
      return res.json({ subjectType, subject: admin.toJSON ? admin.toJSON() : admin });
    }

    if (subjectType === 'client') {
      const schema = z.object({
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
        logoUrl: z.string().url().optional()
      });
      const body = schema.parse(req.body);
      const update = { ...body };
      if (body.logoUrl !== undefined) {
        update.businessLogo = body.logoUrl;
        delete update.logoUrl;
      }
      const client = await Client.findByIdAndUpdate(sub, { $set: update }, { new: true });
      if (!client) return res.status(404).json({ error: 'NotFound', message: 'Client not found' });
      return res.json({ subjectType, subject: client });
    }

    if (subjectType === 'user') {
      const schema = z.object({
        name: z.string().optional(),
        mobile: z.string().optional(),
        password: z.string().min(6).optional(),
        dob: z.string().optional(),
        timeOfBirth: z.string().optional(),
        placeOfBirth: z.string().optional(),
        gowthra: z.string().optional(),
        nativeLanguage: z.string().optional(),
        logoUrl: z.union([z.string().url(), z.literal('')]).optional(),
        liveLocation: z.object({
          latitude: z.number().optional(),
          longitude: z.number().optional(),
          formattedAddress: z.string().optional(),
          city: z.string().optional(),
          state: z.string().optional(),
          country: z.string().optional()
        }).optional()
      });
      const body = schema.parse(req.body);
      const user = await User.findById(sub).select('+password');
      if (!user) return res.status(404).json({ error: 'NotFound', message: 'User not found' });
      if (body.name !== undefined) { user.profile = user.profile || {}; user.profile.name = body.name; }
      if (body.mobile !== undefined) user.mobile = body.mobile;
      if (body.password) user.password = body.password;
      if (body.dob !== undefined) { user.profile = user.profile || {}; user.profile.dob = body.dob ? new Date(body.dob) : undefined; }
      if (body.timeOfBirth !== undefined) { user.profile = user.profile || {}; user.profile.timeOfBirth = body.timeOfBirth; }
      if (body.placeOfBirth !== undefined) { user.profile = user.profile || {}; user.profile.placeOfBirth = body.placeOfBirth; }
      if (body.gowthra !== undefined) { user.profile = user.profile || {}; user.profile.gowthra = body.gowthra; }
      if (body.nativeLanguage !== undefined) { user.profile = user.profile || {}; user.profile.nativeLanguage = body.nativeLanguage; }
      if (body.logoUrl !== undefined) user.profileImage = body.logoUrl || undefined;
      if (body.liveLocation !== undefined) {
        user.liveLocation = {
          ...(user.liveLocation?.toObject?.() || user.liveLocation || {}),
          ...body.liveLocation,
          lastUpdated: new Date()
        };
      }
      await user.save();
      return res.json({ subjectType, subject: user.toJSON ? user.toJSON() : user });
    }

    return res.status(400).json({ error: 'BadRequest', message: 'Unknown subject type' });
  })
);

router.post(
  '/refresh',
  asyncHandler(async (req, res) => {
    const token = req.cookies?.[env.REFRESH_COOKIE_NAME];
    if (!token) return res.status(401).json({ error: 'Unauthorized', message: 'Missing refresh token' });

    let decoded;
    try {
      decoded = verifyRefreshToken(token);
    } catch {
      clearRefreshCookie(res);
      return res.status(401).json({ error: 'Unauthorized', message: 'Invalid refresh token' });
    }

    const session = await Session.findOne({
      subjectType: decoded.subjectType,
      subjectId: decoded.sub,
      refreshTokenHash: sha256(token),
      revokedAt: null
    }).select('+refreshTokenHash');

    if (!session) {
      clearRefreshCookie(res);
      return res.status(401).json({ error: 'Unauthorized', message: 'Session not found' });
    }

    let subject = null;
    if (decoded.subjectType === 'admin') subject = await Admin.findById(decoded.sub);
    if (decoded.subjectType === 'client') subject = await Client.findById(decoded.sub);
    if (decoded.subjectType === 'user') subject = await User.findById(decoded.sub);

    if (!subject || !subject.isActive || !subject.loginApproved) {
      session.revokedAt = new Date();
      await session.save();
      clearRefreshCookie(res);
      return res.status(401).json({ error: 'Unauthorized', message: 'Account inactive/unapproved' });
    }

    // Rotate refresh token
    const newRefresh = signRefreshToken({ subjectType: decoded.subjectType, sub: String(subject._id) });
    const newDecoded = verifyRefreshToken(newRefresh);
    session.refreshTokenHash = sha256(newRefresh);
    session.expiresAt = new Date(newDecoded.exp * 1000);
    await session.save();

    setRefreshCookie(res, newRefresh);
    const accessToken = signAccessToken(accessPayloadFor(decoded.subjectType, subject));

    return res.json({ accessToken });
  })
);

router.post(
  '/logout',
  asyncHandler(async (req, res) => {
    const token = req.cookies?.[env.REFRESH_COOKIE_NAME];
    if (token) {
      try {
        const decoded = verifyRefreshToken(token);
        await Session.updateMany(
          { subjectType: decoded.subjectType, subjectId: decoded.sub, refreshTokenHash: sha256(token) },
          { $set: { revokedAt: new Date() } }
        );
      } catch {
        // ignore
      }
    }
    clearRefreshCookie(res);
    res.json({ ok: true });
  })
);

export default router;

