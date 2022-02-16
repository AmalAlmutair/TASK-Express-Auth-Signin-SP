const mongooseSlugPlugin = require("mongoose-slug-plugin");
const mongoose = require("mongoose");

const ShopSchema = new mongoose.Schema(
  {
    name: String,
    image: String,
    products: [{ type: mongoose.Schema.Types.ObjectId, ref: "Product" }],
    owner: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  },
  { timestamps: true }
);

ShopSchema.plugin(mongooseSlugPlugin, { tmpl: "<%=name%>" });
module.exports = mongoose.model("Shop", ShopSchema);
