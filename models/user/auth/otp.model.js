import { Types, Schema, model } from "mongoose";

const userOtpSchema = new Schema({
  user: {
    type: Types.ObjectId,
    ref: "Shopper",
    required: true,
  },

  otp: {
    type: String,
    trim: true,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now(),
  },
  expiry: {
    type: Date,
    default: Date.now(),
  },
  otpType: {
    type: String,
    enum: ["verify-email", "password-reset"],
  },
});

userOtpSchema.index({ expiry: 1 }, { expireAfterSeconds: 0 });
const userOtp = model("userOtp", userOtpSchema);

export { userOtp };
