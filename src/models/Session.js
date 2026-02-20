import mongoose from 'mongoose';

const sessionSchema = new mongoose.Schema(
  {
    subjectType: {
      type: String,
      enum: ['admin', 'client', 'user'],
      required: true
    },
    subjectId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true
    },
    refreshTokenHash: {
      type: String,
      required: true,
      select: false
    },
    userAgent: { type: String, default: null, trim: true },
    ip: { type: String, default: null, trim: true },
    expiresAt: { type: Date, required: true },
    revokedAt: { type: Date, default: null }
  },
  { timestamps: true }
);

sessionSchema.index({ subjectType: 1, subjectId: 1 });
sessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const Session = mongoose.model('Session', sessionSchema);
export default Session;

