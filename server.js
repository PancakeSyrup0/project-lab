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
  const { id, password } = req.body;

  try {
    const conn = await pool.getConnection();
    const rows = await conn.query(
      "SELECT * FROM users WHERE id=? AND role='staff'",
      [id]
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

/* ------------------ ADMIN LOGIN ------------------ */
app.post("/admin-login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const conn = await pool.getConnection();
    const rows = await conn.query(
      "SELECT * FROM users WHERE email=? AND role='admin'",
      [email]
    );
    conn.release();

    if (rows.length && await bcrypt.compare(password, rows[0].password)) {
      res.json({ success: true });
    } else {
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
