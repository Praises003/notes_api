const express = require('express');
const router = express.Router();
const { signup, login, verifyOtp, resetPassword } = require('../controllers/authController');
const { verifyToken } = require('../middleware/authMiddleware');

router.post('/register', signup);
router.post('/login', login);
router.post('/verify-otp', verifyOtp);
router.post('/reset-password', verifyToken, resetPassword);

module.exports = router;
