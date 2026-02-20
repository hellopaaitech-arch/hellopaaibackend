import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import { customAlphabet } from 'nanoid';

const nanoid = customAlphabet('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', 6);

const clientSchema = new mongoose.Schema(
  {
    clientId: {
      type: String,
      unique: true,
      uppercase: true,
      trim: true
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true
    },
    password: {
      type: String,
      required: true,
      minlength: 6,
      select: false
    },
    businessName: { type: String, trim: true },
    websiteUrl: { type: String, trim: true },
    gstNumber: { type: String, trim: true },
    panNumber: { type: String, trim: true },
    businessLogo: { type: String, trim: true },
    fullName: { type: String, trim: true },
    mobileNumber: { type: String, trim: true },
    address: { type: String, trim: true },
    city: { type: String, trim: true },
    pincode: { type: String, trim: true },
    businessType: { type: String, trim: true },
    contactNumber: { type: String, trim: true },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
    adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
    isActive: { type: Boolean, default: true },
    loginApproved: { type: Boolean, default: false },
    settings: {
      geminiApiKey: { type: String, default: null, trim: true },
      openaiApiKey: { type: String, default: null, trim: true }
    }
  },
  { timestamps: true }
);

clientSchema.pre('validate', async function preValidate() {
  if (this.clientId) return;

  let unique = false;
  while (!unique) {
    const generatedId = `CLI-${nanoid()}`;
    // eslint-disable-next-line no-await-in-loop
    const existing = await mongoose.model('Client').findOne({ clientId: generatedId });
    if (!existing) {
      this.clientId = generatedId;
      unique = true;
    }
  }
});

clientSchema.pre('save', async function preSave() {
  if (!this.isModified('password')) return;
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

clientSchema.methods.comparePassword = async function comparePassword(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

clientSchema.methods.toJSON = function toJSON() {
  const clientObject = this.toObject();
  delete clientObject.password;
  return clientObject;
};

const Client = mongoose.model('Client', clientSchema);
export default Client;

