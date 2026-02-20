import { verifyAccessToken } from '../utils/jwt.js';

export function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice('Bearer '.length) : null;
  if (!token) return res.status(401).json({ error: 'Unauthorized', message: 'Missing access token' });

  try {
    const payload = verifyAccessToken(token);
    req.auth = payload;
    return next();
  } catch {
    return res.status(401).json({ error: 'Unauthorized', message: 'Invalid/expired access token' });
  }
}

export function requireRoles(roles) {
  return function roleGuard(req, res, next) {
    if (!req.auth) return res.status(401).json({ error: 'Unauthorized', message: 'Missing auth context' });
    if (!roles.includes(req.auth.role)) {
      return res.status(403).json({ error: 'Forbidden', message: 'Insufficient role' });
    }
    return next();
  };
}

export function requireSubjectTypes(types) {
  return function typeGuard(req, res, next) {
    if (!req.auth) return res.status(401).json({ error: 'Unauthorized', message: 'Missing auth context' });
    if (!types.includes(req.auth.subjectType)) {
      return res.status(403).json({ error: 'Forbidden', message: 'Invalid subject type' });
    }
    return next();
  };
}

