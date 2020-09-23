const express = require("express");
const path = require("path");

module.exports = app => {
  app.use("/docs", express.static(path.join(__dirname, "/../doc")));
};
