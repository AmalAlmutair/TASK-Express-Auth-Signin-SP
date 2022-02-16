const mongoose = require("mongoose");
const connectDB = async () => {
  const PASSWORD = "Amal65155822";
  const DATABASE_NAME = "productDB";
  const CONNECTION_URL = `mongodb+srv://amalalmutairi:${PASSWORD}@cluster0.pyaik.mongodb.net/${DATABASE_NAME}?retryWrites=true&w=majority`;

  const conn = await mongoose.connect(CONNECTION_URL, {
    useUnifiedTopology: true,
    useNewUrlParser: true,
  });
  console.log(`mongo connected: ${conn.connection.host}`);
};
module.exports = connectDB;
