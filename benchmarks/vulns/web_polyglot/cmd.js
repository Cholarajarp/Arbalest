const { exec } = require("child_process");
app.get("/convert", (req, res) => {
  exec("convert " + req.query.file, (err, out) => res.send(out));
});
