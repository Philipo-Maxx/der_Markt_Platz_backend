import nodemailer from "nodemailer";
import { otpGeneration } from "./otpGen.js";
const sendOTP = async (user) => {
  try {
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.SENDER_EMAIL,
        pass: process.env.SENDER_PASS,
      },
    });

    const otp = await otpGeneration(user._id, "verify-email");
    console.log(otp);
    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Welcome to MarktPlaz, Your OTP is contained in the Email",
      text: `This is your OTP: ${otp}`,
    };

    await transporter.sendMail(mailOptions);
  } catch (error) {
    throw new Error("Error from Sending Email to new User");
  }
};

export { sendOTP };
