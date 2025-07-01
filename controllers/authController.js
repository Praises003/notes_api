require("dotenv").config();
const bcrypt = require('bcryptjs');
const { sendMail } = require("../utils/Emails");
const { generateOTP } = require("../utils/GenerateOtp");
const Otp = require("../models/OTP");
const PasswordResetToken = require("../models/PasswordResetToken");
const User = require("../models/User");
const { sanitizeUser } = require("../utils/SanitizeUser");
const { generateToken } = require("../utils/GenerateToken");
const { registerSchema, loginSchema, verifyOtpSchema, resetPasswordSchema } = require("../utils/validate");  // Import validation schemas

// SignUp: Register new user and generate OTP
exports.signup = async (req, res) => {
    try {
        // Validate input using Zod
        const parsed = registerSchema.safeParse(req.body);
        if (!parsed.success) {
            return res.status(400).json({ message: "Validation error", errors: parsed.error.errors });
        }

        

        const { email, password, name } = req.body;

        const existingUser = await User.findOne({ email });

        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }

        
        const createdUser = new User({ email, password, name });
        await createdUser.save();

        const otp = generateOTP();
        const hashedOtp = await bcrypt.hash(otp, 10);

        const newOtp = await Otp.create({
            user: createdUser._id,
            otp: hashedOtp,
            expiresAt: new Date(Date.now() + parseInt(process.env.OTP_EXPIRATION_TIME)),
        });

        await sendMail(createdUser.email, "Your OTP Code", `Your OTP code is: ${otp}`);

        res.status(201).json({
            message: "Registration successful. Please verify your email with the OTP sent to you.",
            user: sanitizeUser(createdUser),
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error occurred during signup, please try again later" });
    }
};

// Login: Authenticate user and generate JWT
exports.login = async (req, res) => {
    try {
        // Validate input using Zod
        const parsed = loginSchema.safeParse(req.body);
        if (!parsed.success) {
            return res.status(400).json({ message: "Validation error", errors: parsed.error.errors });
        }

        const { email, password } = req.body;

        const existingUser = await User.findOne({ email });
       
        if (existingUser && await bcrypt.compare(password, existingUser.password)) {
            const secureInfo = sanitizeUser(existingUser);
            console.log(existingUser)
            const token = generateToken(secureInfo);

            res.cookie('token', token, {
                sameSite: process.env.PRODUCTION === 'true' ? "None" : 'Lax',
                maxAge: new Date(Date.now() + (parseInt(process.env.COOKIE_EXPIRATION_DAYS) * 24 * 60 * 60 * 1000)),
                httpOnly: true,
                secure: process.env.PRODUCTION === 'true',
            });
        

            return res.status(200).json(sanitizeUser(existingUser));
        }

        res.clearCookie('token');
        return res.status(404).json({ message: "Invalid Credentials" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Some error occurred while logging in, please try again later" });
    }
};

// Verify OTP: Confirm OTP and mark user as verified
exports.verifyOtp = async (req, res) => {
    try {
        // Validate input using Zod
        const parsed = verifyOtpSchema.safeParse(req.body);
        if (!parsed.success) {
            return res.status(400).json({ message: "Validation error", errors: parsed.error.errors });
        }

        const { userId, otp } = req.body;

        const isValidUserId = await User.findById(userId);
        if (!isValidUserId) {
            return res.status(404).json({ message: 'User not found' });
        }

        const isOtpExisting = await Otp.findOne({ user: isValidUserId._id });
        if (!isOtpExisting) {
            return res.status(404).json({ message: 'OTP not found' });
        }

        if (new Date(isOtpExisting.expiresAt) < new Date()) {
            await Otp.findByIdAndDelete(isOtpExisting._id);
            return res.status(400).json({ message: "OTP has expired" });
        }

        if (await bcrypt.compare(otp, isOtpExisting.otp)) {
            await Otp.findByIdAndDelete(isOtpExisting._id);
            const verifiedUser = await User.findByIdAndUpdate(isValidUserId._id, { isVerified: true }, { new: true });
            return res.status(200).json(sanitizeUser(verifiedUser));
        }

        // Generate JWT token
        const secureInfo = sanitizeUser(isValidUserId); // Assuming sanitizeUser is a function to clean user data
        const token = generateToken(secureInfo);

        // Set token in response cookies
        res.cookie('token', token, {
            sameSite: process.env.PRODUCTION === 'true' ? "None" : 'Lax',
            maxAge: new Date(Date.now() + (parseInt(process.env.COOKIE_EXPIRATION_DAYS) * 24 * 60 * 60 * 1000)),
            httpOnly: true,
            secure: process.env.PRODUCTION === 'true'
        });

        // Respond with user info
        res.status(200).json(sanitizeUser(isValidUserId));

        return res.status(400).json({ message: 'OTP is invalid' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error occurred while verifying OTP" });
    }
};

// Reset Password: Reset the user's password using a token
exports.resetPassword = async (req, res) => {
    try {
        // Validate input using Zod
        const parsed = resetPasswordSchema.safeParse(req.body);
        if (!parsed.success) {
            return res.status(400).json({ message: "Validation error", errors: parsed.error.errors });
        }

        const { userId, token, password } = req.body;

        const existingUser = await User.findById(userId);
        if (!existingUser) {
            return res.status(404).json({ message: "User not found" });
        }

        const resetToken = await PasswordResetToken.findOne({ user: userId });
        if (!resetToken) {
            return res.status(404).json({ message: "Invalid reset token" });
        }

        if (new Date(resetToken.expiresAt) < new Date()) {
            await PasswordResetToken.findByIdAndDelete(resetToken._id);
            return res.status(400).json({ message: "Reset token has expired" });
        }

        if (await bcrypt.compare(token, resetToken.token)) {
            await PasswordResetToken.findByIdAndDelete(resetToken._id);
            const hashedPassword = await bcrypt.hash(password, 10);
            await User.findByIdAndUpdate(userId, { password: hashedPassword });
            return res.status(200).json({ message: "Password updated successfully" });
        }

        return res.status(400).json({ message: "Invalid reset token" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error occurred while resetting password" });
    }
};

// Other controller methods remain unchanged
