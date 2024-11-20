import dotenv from "dotenv";
dotenv.config();
import express from "express";
import { connectDB } from "./config/auth/db.js";
import cookieParser from "cookie-parser";
import bodyParser from "body-parser";
import cors from "cors";
import { authRoute } from "./routes/auth/auth.route.js";

const app = express();
const PORT = process.env.PORT_NUM || 5000;
connectDB();

app.use(
  cors({
    origin: "http://localhost:5173",
    methods: ["GET", "POST", "DELETE", "PUT"],
    allowedHeaders: [
      "Authorization",
      "Content-Type",
      "Cache-Control",
      "Expires",
      "Pragma",
    ],
    credentials: true,
  })
);

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use("/api/v1/auth", authRoute);
app.listen(PORT, () => {
  console.log(`Server listening on PORT ${PORT}`);
});
