const express = require("express");
const passport = require("passport");
const router = express.Router();
const { signup, signin } = require("./controllers");

router.post("/signup", signup);
router.post(
  "/signin",
  passport.authenticate("local", { session: false }),
  signin
);

module.exports = router;
