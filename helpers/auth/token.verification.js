import jwt from "jsonwebtoken";

const generateVerificationToken = (userId) => {
  const userPayload = { id: userId };
  const token = jwt.sign(userPayload, process.env.jwt_VERIFICATION_PASS, {
    expiresIn: "5m",
  });
  return token;
};

const generateAccessToken = (payload) => {
  const token = jwt.sign(payload, process.env.jwt_ACCESS_TOKEN, {
    expiresIn: "24h",
  });

  return token;
};

export { generateVerificationToken, generateAccessToken };
