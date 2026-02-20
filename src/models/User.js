import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true,
    select: false
  },
  authMethod: {
    type: String,
    enum: ['password', 'google', 'firebase', 'email'],
    default: 'password'
  },
  firebaseId: {
    type: String,
    sparse: true,
    unique: true
  },
  profile: {
    name: String,
    dob: Date,
    timeOfBirth: String,
    placeOfBirth: String,
    latitude: { type: Number, min: -90, max: 90 },
    longitude: { type: Number, min: -180, max: 180 },
    gowthra: String,
    nativeLanguage: String
  },
  liveLocation: {
    latitude: { type: Number, min: -90, max: 90 },
    longitude: { type: Number, min: -180, max: 180 },
    formattedAddress: String,
    city: String,
    state: String,
    country: String,
    lastUpdated: { type: Date, default: Date.now }
  },
  profileImage: String,
  mobile: {
    type: String,
    sparse: true
  },
  emailVerified: { type: Boolean, default: false },
  mobileVerified: { type: Boolean, default: false },
  emailOtp: { type: String, select: false },
  emailOtpExpiry: { type: Date, select: false },
  mobileOtp: { type: String, select: false },
  mobileOtpExpiry: { type: Date, select: false },
  mobileOtpMethod: {
    type: String,
    enum: ['sms', 'whatsapp', 'gupshup', 'twilio'],
    select: false
  },
  registrationStep: {
    type: Number,
    default: 0,
    min: 0,
    max: 3
  },
  loginApproved: { type: Boolean, default: false },
  isActive: { type: Boolean, default: true },
  // Note: field name kept as `clientId` for compatibility, but it's an ObjectId ref.
  clientId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Client'
  },
  passwordResetToken: { type: String, select: false },
  passwordResetExpires: { type: Date, select: false },
  credits: { type: Number, default: 0, min: 0 },
  karmaPoints: { type: Number, default: 0, min: 0 },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

userSchema.pre('save', async function preSave() {
  if (!this.isModified('password')) return;
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

userSchema.pre('save', function updateTimestamp() {
  this.updatedAt = Date.now();
});

userSchema.methods.comparePassword = async function comparePassword(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.toJSON = function toJSON() {
  const obj = this.toObject();
  delete obj.password;
  delete obj.emailOtp;
  delete obj.emailOtpExpiry;
  delete obj.mobileOtp;
  delete obj.mobileOtpExpiry;
  delete obj.mobileOtpMethod;
  return obj;
};

const User = mongoose.model('User', userSchema);
export default User;

