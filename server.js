require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const pool = require("./db");

const app = express();
app.use(express.json());
app.use(express.static("public"));

/* ------------------ FACULTY REGISTER ------------------ */
app.post("/faculty-register", async (req, res) => {
  const { name, email, password, department } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10); // Hash password
    const conn = await pool.getConnection();

    await conn.query(
      "INSERT INTO users (name, email, password, role, department) VALUES (?,?,?,?,?)",
      [name, email, hashedPassword, "faculty", department]
    );

    conn.release();
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: "Registration failed" });
  }
});

/* ------------------ FACULTY LOGIN ------------------ */
app.post("/faculty-login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const conn = await pool.getConnection();
    const rows = await conn.query(
      "SELECT * FROM users WHERE email=? AND role='faculty'",
      [email]
    );
    conn.release();

    if (rows.length && await bcrypt.compare(password, rows[0].password)) {
      res.json({ success: true });
    } else {
      res.json({ success: false, message: "Invalid login" });
    }
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: "Login error" });
  }
});

/* ------------------ STAFF LOGIN ------------------ */
app.post("/staff-login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const conn = await pool.getConnection();

    console.log("Checking staff login for email:", email);

    const rows = await conn.query(
      "SELECT * FROM users WHERE email=? AND role='staff'",
      [email]
    );

    conn.release();

    if (rows.length) {
      console.log("Staff row found:", rows[0]);
      if (rows[0].password === password) { // plain-text comparison
        res.json({ success: true });
      } else {
        console.log("Password mismatch!");
        res.json({ success: false, message: "Invalid staff login" });
      }
    } else {
      console.log("No staff with this email!");
      res.json({ success: false, message: "Invalid staff login" });
    }
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: "Login error" });
  }
});



/* ------------------ ADMIN LOGIN ------------------ */
app.post("/admin-login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const conn = await pool.getConnection();

    // Debug: log what is being checked
    console.log("Checking admin login for:", email, password);

    const rows = await conn.query(
      "SELECT * FROM users WHERE email=? AND role='admin'",
      [email]
    );

    conn.release();

    if (rows.length) {
      console.log("Admin row found:", rows[0]);
      if (rows[0].password === password) {
        res.json({ success: true });
      } else {
        console.log("Password mismatch!");
        res.json({ success: false, message: "Invalid admin login" });
      }
    } else {
      console.log("No admin with this email!");
      res.json({ success: false, message: "Invalid admin login" });
    }
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: "Login error" });
  }
});

/* ------------------ START SERVER ------------------ */
app.listen(process.env.PORT, () =>
  console.log(`Server running on http://localhost:${process.env.PORT}`)
);
