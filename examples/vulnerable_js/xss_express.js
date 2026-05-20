// Example vulnerable JS code — Express app with XSS + SSRF.
const express = require("express");
const axios = require("axios");
const app = express();

// CWE-79: Reflected XSS — name is echoed without escaping.
app.get("/hello", (req, res) => {
  const name = req.query.name || "world";
  res.send("<h1>Hello, " + name + "</h1>");
});

// CWE-918: SSRF — server fetches an arbitrary URL.
app.get("/fetch", async (req, res) => {
  const target = req.query.url;
  const r = await axios.get(target);
  res.send(r.data);
});

// CWE-94: eval of untrusted input
app.post("/eval", express.text(), (req, res) => {
  // eslint-disable-next-line no-eval
  res.send(String(eval(req.body)));
});

app.listen(3000);
