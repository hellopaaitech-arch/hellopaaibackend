import { Router } from 'express';
import multer from 'multer';
import { z } from 'zod';
import { asyncHandler } from '../utils/asyncHandler.js';
import { generateUploadUrl, uploadToS3 } from '../utils/s3.js';
import { verifyAccessToken, verifyRegistrationToken } from '../utils/jwt.js';

const router = Router();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (_req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) {
      return cb(new Error('Only image files allowed'));
    }
    cb(null, true);
  }
});

// Form-data: Upload image file directly, backend stores in S3, returns public URL (works everywhere)
// Auth is optional - allows uploads during registration (unauthenticated) or profile edit (authenticated)
router.post(
  '/profile-image',
  (req, res, next) => {
    upload.single('image')(req, res, (err) => {
      if (err) {
        return res.status(400).json({ error: 'BadRequest', message: err.message || 'Invalid file' });
      }
      next();
    });
  },
  // Optional auth - try to authenticate (accessToken) or registration token
  (req, res, next) => {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice('Bearer '.length) : null;
    if (token) {
      try {
        // Try access token first (authenticated user)
        const payload = verifyAccessToken(token);
        req.auth = payload;
        req.authType = 'access';
      } catch {
        try {
          // Try registration token (step 3 of registration)
          const regData = verifyRegistrationToken(token);
          req.auth = { 
            subjectType: 'registration',
            sub: regData.email,
            email: regData.email,
            clientCode: regData.clientCode
          };
          req.authType = 'registration';
          req.registrationData = regData;
        } catch {
          // Ignore - allow unauthenticated uploads for backward compatibility
        }
      }
    }
    next();
  },
  asyncHandler(async (req, res) => {
    if (!req.file) {
      return res.status(400).json({ error: 'BadRequest', message: 'Image file required (field: image)' });
    }
    const folder = req.body?.folder || 'users';
    const allowedFolders = ['users', 'clients'];
    if (!allowedFolders.includes(folder)) {
      return res.status(400).json({ error: 'BadRequest', message: 'folder must be users or clients' });
    }
    
    // Determine folder based on auth if available
    let finalFolder = folder;
    if (req.auth) {
      if (req.auth.subjectType === 'client') {
        finalFolder = 'clients';
      } else if (req.auth.subjectType === 'user' || req.auth.subjectType === 'admin') {
        finalFolder = 'users';
      }
    }
    
    // Include user/client ID in filename for tracking (if authenticated or registration token)
    if (req.auth) {
      if (req.authType === 'registration') {
        // Registration flow: use email as identifier
        const prefix = `reg_${req.auth.email.replace('@', '_at_')}_`;
        req.file.originalname = prefix + req.file.originalname;
        req.file.userId = req.auth.email;
        req.file.userType = 'registration';
      } else {
        // Authenticated user
        const prefix = `${req.auth.subjectType}_${req.auth.sub}_`;
        req.file.originalname = prefix + req.file.originalname;
        req.file.userId = req.auth.sub;
        req.file.userType = req.auth.subjectType;
      }
    }
    
    const result = await uploadToS3(req.file, finalFolder);
    
    return res.json({ 
      fileUrl: result.url || result.Location, 
      key: result.key,
      uploadedBy: req.auth ? { 
        subjectType: req.auth.subjectType, 
        id: req.auth.sub,
        role: req.auth.role 
      } : null
    });
  })
);

// Generate presigned URL for logo upload (legacy - for registration or profile edit)
router.post(
  '/logo',
  asyncHandler(async (req, res) => {
    const schema = z.object({
      fileName: z.string().min(1),
      contentType: z.string().min(1),
      folder: z.enum(['users', 'clients']).optional().default('users')
    });
    
    const body = schema.parse(req.body);
    
    // Validate content type is an image
    if (!body.contentType.startsWith('image/')) {
      return res.status(400).json({
        error: 'BadRequest',
        message: 'Only image files are allowed for logos'
      });
    }
    
    const result = await generateUploadUrl(body.fileName, body.contentType, body.folder);
    
    return res.json({
      uploadUrl: result.uploadUrl,
      fileUrl: result.fileUrl,
      key: result.key
    });
  })
);

export default router;
