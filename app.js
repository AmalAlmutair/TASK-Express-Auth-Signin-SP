const express = require("express");
const cors = require("cors");
const connectDb = require("./database");
const productsRoutes = require("./api/products/routes");
const shopsRoutes = require("./api/shops/routes");
const userRoutes = require("./api/users/routes");
const passport = require("passport");
const { jwtStrategy } = require("./middleware/passport");
const { localStrategy } = require("./middleware/passport");
const app = express();
const PORT = 5000;
connectDb();

app.use(cors());
app.use(express.json());
app.use(passport.initialize());
passport.use(localStrategy);
passport.use(jwtStrategy);
app.use((req, res, next) => {
  console.log(
    `${req.method} ${req.protocol}://${req.get("host")}${req.originalUrl}`
  );
  next();
});

// Routes
app.use("/api/products", productsRoutes);
app.use("/api/shops", shopsRoutes);
app.use("/api", userRoutes);
app.use((err, req, res, next) => {
  res.status(err.status || 500).json({
    message: err.message || "Internal Server Error",
  });
});
app.listen(PORT);
