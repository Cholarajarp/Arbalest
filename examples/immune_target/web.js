// Fixture organism — JavaScript attack surface.
const express = require("express");
const app = express();

function getUsers(req, res) {
  const filter = eval(req.query.filter); // SENT-JS-001
  res.json(users.filter(filter));
}

app.get("/users", getUsers);

const apiKey = "sk-live-abcdefghijklmnop1234"; // SENT-JS-009
module.exports = app;
