const express = require("express");
const { session } = require("passport");
const passport = require("passport");
const router = express.Router();
const upload = require("../../middleware/multer");

const { shopCreate, getShops, productCreate } = require("./controllers");

router.get("/", getShops);
router.post("/", passport.authenticate("jwt", { session: false }), shopCreate);
router.post("/:shopId/products", upload.single("image"), productCreate);

module.exports = router;
