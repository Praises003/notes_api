const zod = require('zod');
const { z } = zod;

// Zod validation schema for register and login
const registerSchema = z.object({
    name: z.string().min(3, 'Username should be at least 3 characters'),
    email: z.string().email('Invalid email format'),
    password: z.string().min(6, 'Password should be at least 6 characters')
});

const loginSchema = z.object({
    email: z.string().email('Invalid email format'),
    password: z.string().min(6, 'Password should be at least 6 characters')
});

const verifyOtpSchema = z.object({
    userId: z.string().min(24, "Invalid user ID"),  // Assuming MongoDB ObjectId is 24 characters
    otp: z.string().length(6, "OTP must be 6 digits"),  // Assuming OTP length is 6
});

// Password Reset Schema
const resetPasswordSchema = z.object({
    userId: z.string().min(24, "Invalid user ID"),
    token: z.string(),
    password: z.string().min(6, "Password must be at least 6 characters long"),
});

module.exports = {registerSchema, loginSchema, verifyOtpSchema, resetPasswordSchema};   