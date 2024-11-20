import { userShopper } from "../../models/user/auth/user.model.js";
import bcrypt from "bcryptjs";
import {
  generateVerificationToken,
  generateAccessToken,
} from "../../helpers/auth/token.verification.js";
import { sendOTP } from "../../helpers/auth/nodemailer.js";
import jwt from "jsonwebtoken";
import { userOtp } from "../../models/user/auth/otp.model.js";

const createUser = async (req, res) => {
  try {
    const { fullName, email, password, confirmPassword, dateOfBirth, gender } =
      req.body;

    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: "Password and Confirm Password does not match",
      });
    }

    const emailExist = await userShopper.findOne({ email: email });
    if (emailExist) {
      return res
        .status(400)
        .json({ success: false, message: "Email already exists" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = await userShopper.create({
      fullName,
      email,
      password: hashedPassword,
      dateOfBirth,
      gender,
    });

    if (newUser) {
      await sendOTP(newUser);
      const token = generateVerificationToken(newUser._id);
      console.log(token);
      res.status(200).json({ success: true, message: `${token}` });
    }
  } catch (error) {
    console.log(error.message);
    res.status(500).json({ success: false, message: error.message });
  }
};

const verifyUser = async (req, res) => {
  const { otp } = req.body;
  let token = "";
  const authHeader = req.headers["authorization"];
  if (authHeader && authHeader.startsWith("Bearer ")) {
    token = authHeader.split(" ")[1];
    console.log(`Derived token from headers ${token}`);
  }

  if (!token) {
    return res
      .status(401)
      .json({ success: false, message: "Verification Token Missing" });
  }

  const payload = jwt.verify(token, process.env.jwt_VERIFICATION_PASS);

  try {
    const userOTP = await userOtp.findOne({
      user: payload.id,
      otpType: "verify-email",
    });

    if (!userOTP) {
      return res
        .status(400)
        .json({ success: false, message: "User with OTP does not exist" });
    }
    if (userOTP.otp === otp) {
      const User = await userShopper.findByIdAndUpdate(userOTP.user, {
        isEmailVerified: true,
      });
      await userOtp.findByIdAndDelete(userOTP._id);

      const payload = { id: User._id };
      const accessToken = generateAccessToken(payload);
      console.log(accessToken);
      return res.status(200).json({
        success: true,
        message: `Email is Verified, Access Token: ${accessToken}`,
      });
    }
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
};

const loginUser = async (req, res) => {
  const { email, password } = req.body;
  try {
    const User = await userShopper.findOne({ email });
    if (!User) {
      throw new Error(`User does not Exists`);
    }

    const isMatches = await bcrypt.compare(password, User.password);
    if (!isMatches) {
      throw new Error(`Password credentials error`);
    }

    if (!User.isEmailVerified) {
      const userOTP = await userOtp.findOne({
        user: User._id,
        otpType: "verify-email",
      });
      console.log(userOTP);
      console.log("--------");
      console.log(userOTP);
      if (userOTP?.expiry) {
        console.log(
          `OTP still valid, redirect to OTP Page, with the saved Verification Token`
        );
        return res
          .status(200)
          .json({ success: true, message: `OTP is still valid` });
      } else {
        console.log(`OTP expired, resending OTP`);
        await sendOTP(User);
        const token = generateVerificationToken(User._id);
        return res.status(200).json({
          success: true,
          message: `OTP sent to ${User.email}`,
          token: `${token}`,
        });
      }
    }

    const payload = { id: User._id };
    const accessToken = generateAccessToken(payload);
    return res.status(200).json({
      success: true,
      message: `Succesfully logged In`,
      accessToken: `${accessToken}`,
    });
  } catch (error) {
    return res
      .status(500)
      .json({ success: false, message: `${error.message}` });
  }
};

const logOutUser = async (req, res) => {};

const authMiddlWare = async (req, res) => {};

export { createUser, verifyUser, loginUser };
