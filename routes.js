const express = require('express');
const router = express.Router();
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const protect = require('../middleware/auth');

// Generate JWT token
const generateToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET, {
    expiresIn: '1d',
  });
};

// Register
router.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ message: 'User already exists' });

    const user = await User.create({ name, email, password });
    const token = generateToken(user._id);

    res.cookie('token', token, {
      httpOnly: true,
      secure: true, // Set to true in production
      sameSite: 'Lax',
      maxAge: 86400000
    });

    res.status(201).json({ message: 'User registered', user: { name, email } });
  } catch (err) {
    res.status(500).json({ message: 'Error registering user' });
  }
});

// Login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user || !(await user.matchPassword(password)))
      return res.status(400).json({ message: 'Invalid credentials' });

    const token = generateToken(user._id);
    res.cookie('token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
      maxAge: 86400000
    });

    res.json({ message: 'Login successful', user: { name: user.name, email: user.email } });
  } catch {
    res.status(500).json({ message: 'Login failed' });
  }
});

// Protected route example
router.get('/dashboard', protect, async (req, res) => {
  res.json({ message: 'Welcome to your dashboard!', userId: req.user.id });
});

// Logout
router.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out' });
});

module.exports = router;
