import { Router } from 'express';
import multer from 'multer';
import { z } from 'zod';
import { asyncHandler } from '../utils/asyncHandler.js';
import { generateUploadUrl, uploadToS3 } from '../utils/s3.js';

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
  asyncHandler(async (req, res) => {
    if (!req.file) {
      return res.status(400).json({ error: 'BadRequest', message: 'Image file required (field: image)' });
    }
    const folder = req.body?.folder || 'users';
    const allowedFolders = ['users', 'clients'];
    if (!allowedFolders.includes(folder)) {
      return res.status(400).json({ error: 'BadRequest', message: 'folder must be users or clients' });
    }
    const result = await uploadToS3(req.file, folder);
    return res.json({ fileUrl: result.url || result.Location, key: result.key });
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
