import mongoose from 'mongoose';

const otpSchema = new mongoose.Schema(
  {
    mobile: {
      type: String,
      required: false,
      trim: true
    },
    email: {
      type: String,
      required: false,
      trim: true,
      lowercase: true
    },
    otp: {
      type: String,
      required: true,
      select: false
    },
    client: {
      type: String,
      default: 'brahmakosh'
    },
    expiresAt: {
      type: Date,
      required: true,
      default: () => new Date(Date.now() + 10 * 60 * 1000)
    },
    isUsed: {
      type: Boolean,
      default: false
    },
    type: {
      type: String,
      enum: ['email', 'mobile', 'whatsapp', 'sms', 'gupshup'],
      default: 'mobile'
    },
    sessionId: {
      type: String,
      required: false,
      trim: true,
      sparse: true
    }
  },
  { timestamps: true }
);

otpSchema.pre('validate', function preValidate() {
  if (!this.mobile && !this.email) {
    this.invalidate('mobile', 'Either mobile or email is required');
    this.invalidate('email', 'Either mobile or email is required');
  }
});

otpSchema.index({ mobile: 1, otp: 1, isUsed: 1 }, { sparse: true });
otpSchema.index({ email: 1, otp: 1, isUsed: 1 }, { sparse: true });
otpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const OTP = mongoose.model('OTP', otpSchema);
export default OTP;

