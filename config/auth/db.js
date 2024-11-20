import mongoose from "mongoose";

const connectDB = async () => {
  try {
    const connect = await mongoose.connect(process.env.LOCAL_MONGO_URL);
    console.log(connect.connection.host);
  } catch (error) {
    console.log(error || "Error connecting to Database");
  }
};

export { connectDB };
