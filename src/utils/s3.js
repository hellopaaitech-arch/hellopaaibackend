import { S3Client, PutObjectCommand, DeleteObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { env } from '../config/env.js';

// Validate required environment variables
const requiredEnvVars = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_REGION', 'AWS_BUCKET_NAME'];
const missingEnvVars = requiredEnvVars.filter(envVar => !env[envVar]);

if (missingEnvVars.length > 0) {
  console.warn('⚠️  Missing AWS environment variables:', missingEnvVars);
  console.warn('S3 functionality will not work until these are configured.');
}

let s3Client = null;

function getS3Client() {
  if (!s3Client && env.AWS_ACCESS_KEY_ID && env.AWS_SECRET_ACCESS_KEY && env.AWS_REGION) {
    s3Client = new S3Client({
      region: env.AWS_REGION,
      credentials: {
        accessKeyId: env.AWS_ACCESS_KEY_ID,
        secretAccessKey: env.AWS_SECRET_ACCESS_KEY,
      },
    });
  }
  return s3Client;
}

// Generate presigned URL for uploading
export const putobject = async (key, contentType) => {
  const client = getS3Client();
  if (!client) throw new Error('S3 not configured');
  
  try {
    const command = new PutObjectCommand({
      Bucket: env.AWS_BUCKET_NAME,
      Key: key,
      ContentType: contentType,
    });

    const signedUrl = await getSignedUrl(client, command, { expiresIn: 3600 }); // 1 hour
    return signedUrl;
  } catch (error) {
    console.error('Error generating presigned URL:', error);
    throw error;
  }
};

// Generate presigned URL for direct browser upload
export const generateUploadUrl = async (fileName, contentType, folder) => {
  const client = getS3Client();
  if (!client) throw new Error('S3 not configured');
  
  try {
    // Generate unique key with timestamp and random ID
    const timestamp = Date.now();
    const randomId = Math.random().toString(36).substring(2, 15);
    const fileExtension = fileName.split('.').pop();
    const uniqueFileName = `${timestamp}_${randomId}.${fileExtension}`;
    const key = folder ? `${folder}/${uniqueFileName}` : uniqueFileName;
    
    const command = new PutObjectCommand({
      Bucket: env.AWS_BUCKET_NAME,
      Key: key,
      ContentType: contentType,
      CacheControl: 'max-age=31536000',
      Metadata: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, PUT, POST, DELETE, HEAD',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
      }
    });

    const uploadUrl = await getSignedUrl(client, command, { expiresIn: 3600 });
    const fileUrl = `https://${env.AWS_BUCKET_NAME}.s3.${env.AWS_REGION}.amazonaws.com/${key}`;
    
    return { uploadUrl, fileUrl, key };
  } catch (error) {
    console.error('Error generating upload URL:', error);
    throw error;
  }
};

// Generate presigned URL for getting/reading an object
export const getobject = async (key, expiresIn = 604800) => {
  const client = getS3Client();
  if (!client) throw new Error('S3 not configured');
  
  try {
    // If key is a URL, extract the key first
    const actualKey = key.startsWith('http') ? extractS3KeyFromUrl(key) : key;
    
    if (!actualKey) {
      throw new Error('Invalid S3 key provided');
    }
    
    const command = new GetObjectCommand({
      Bucket: env.AWS_BUCKET_NAME,
      Key: actualKey,
      ResponseContentDisposition: 'inline',
      ResponseContentType: actualKey.match(/\.(mp4|webm|ogg)$/i) ? 'video/mp4' : 
                           actualKey.match(/\.(jpg|jpeg|png|gif|webp)$/i) ? 'image/jpeg' : undefined,
      ResponseCacheControl: 'max-age=31536000, public',
      ResponseExpires: new Date(Date.now() + expiresIn * 1000).toISOString()
    });

    const signedUrl = await getSignedUrl(client, command, { expiresIn });
    return signedUrl;
  } catch (error) {
    console.error('Error generating get presigned URL:', error);
    throw error;
  }
};

// Upload file directly to S3 (from buffer/multer)
export const uploadToS3 = async (file, folder = '') => {
  const client = getS3Client();
  if (!client) throw new Error('S3 not configured');
  
  try {
    if (!file || !file.buffer) {
      throw new Error('Invalid file: missing file buffer');
    }
    
    // Clean filename - remove spaces and special characters
    const cleanFileName = file.originalname
      .replace(/\s+/g, '_')
      .replace(/[^a-zA-Z0-9._-]/g, '')
      .toLowerCase();
    
    const key = folder ? `${folder}/${Date.now()}-${cleanFileName}` : `${Date.now()}-${cleanFileName}`;
    
    const command = new PutObjectCommand({
      Bucket: env.AWS_BUCKET_NAME,
      Key: key,
      Body: file.buffer,
      ContentType: file.mimetype,
      CacheControl: 'max-age=31536000',
      Metadata: {
        'uploaded-by': 'hello-paai',
        'upload-timestamp': Date.now().toString()
      }
    });

    await client.send(command);
    
    const fileUrl = `https://${env.AWS_BUCKET_NAME}.s3.${env.AWS_REGION}.amazonaws.com/${key}`;
    
    return {
      key: key,
      Location: fileUrl,
      url: fileUrl
    };
  } catch (error) {
    console.error('Error uploading to S3:', error);
    throw error;
  }
};

// Delete file from S3
export const deleteFromS3 = async (keyOrUrl) => {
  const client = getS3Client();
  if (!client) throw new Error('S3 not configured');
  
  try {
    let key;
    
    if (keyOrUrl.startsWith('http')) {
      const url = new URL(keyOrUrl);
      key = url.pathname.substring(1);
    } else {
      key = keyOrUrl;
    }
    
    const command = new DeleteObjectCommand({
      Bucket: env.AWS_BUCKET_NAME,
      Key: key,
    });

    await client.send(command);
  } catch (error) {
    console.error('Error deleting from S3:', error);
    throw error;
  }
};

/**
 * Extract S3 key from S3 URL
 */
export const extractS3KeyFromUrl = (url) => {
  if (!url || typeof url !== 'string') {
    return null;
  }
  
  if (url.startsWith('s3://')) {
    const parts = url.replace('s3://', '').split('/');
    if (parts.length > 1) {
      return parts.slice(1).join('/');
    }
    return null;
  }
  
  if (url.startsWith('http://') || url.startsWith('https://')) {
    try {
      const urlObj = new URL(url);
      const key = urlObj.pathname.substring(1);
      return key || null;
    } catch (error) {
      const match = url.match(/s3[.-]([^.]+)\.amazonaws\.com\/(.+)$/);
      if (match && match[2]) {
        return decodeURIComponent(match[2]);
      }
      return null;
    }
  }
  
  return url;
};

export { getS3Client as s3Client };
