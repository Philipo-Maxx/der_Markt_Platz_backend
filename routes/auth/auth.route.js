import express from "express";
import {
  createUser,
  verifyUser,
  loginUser,
} from "../../controllers/auth/auth.controllers.js";

const authRoute = express.Router();

authRoute.post("/create-user", createUser);
authRoute.post("/login-user", loginUser);
authRoute.post("/verify-user", verifyUser);

export { authRoute };
