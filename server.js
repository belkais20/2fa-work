require('dotenv').config();
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const path = require('path');
const { loadUsers, addUser } = require('./users_db');

const app = express();

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(session({
  secret: 'secret-key',
  resave: false,
  saveUninitialized: true
}));
app.use(express.static(path.join(__dirname)));

// Rate limiting
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100
});
app.use(limiter);

// Nodemailer setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Routes
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'homepage.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'register.html')));
app.get('/2FA', (req, res) => {
  if (!req.session.username) return res.redirect('/login');
  res.sendFile(path.join(__dirname, '2FA.html'));
});

app.post('/register', (req, res) => {
  const { username, password, email } = req.body;
  const users = loadUsers();
  if (users.some(u => u.username === username)) {
    return res.send('❌ اسم المستخدم موجود مسبقًا.');
  }
  addUser(username, email, password);
  res.redirect('/login');
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const users = loadUsers();
  const user = users.find(u => u.username === username && u.password === password);

  if (user) {
    const code = crypto.randomInt(100000, 999999).toString();
    req.session.username = username;
    req.session.code = code;

    transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: '2FA',
      text: `Your code is: ${code}`
    }, (err) => {
      if (err) {
        console.error('Error sending email:', err);
        return res.send('Error sending verification code.');
      }
      res.redirect('/2FA');
    });
  } else {
    res.send('❌ Incorrect username or password.');
  }
});

app.post('/2FA', (req, res) => {
  const { code } = req.body;
  if (req.session.username && req.session.code === code.trim()) {
    delete req.session.code;

    // Set verifiedUser cookie
    res.cookie('verifiedUser', req.session.username, {
      maxAge: 24 * 60 * 60 * 1000,
      httpOnly: false,
      path: '/'
    });

    console.log(`✅ Cookie sent: verifiedUser = ${req.session.username}`);
    res.sendFile(path.join(__dirname, 'success.html'));
  } else {
    res.sendFile(path.join(__dirname, 'fail.html'));
  }
});

const PORT = process.env.PORT || 9000;
app.listen(PORT, () => console.log(`✅ The server is working on http://localhost:${PORT}`));
