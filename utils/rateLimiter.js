const rateLimit = require('express-rate-limit');

// Rate limiter for general requests (for example: login, register)
const generalRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,  // 15 minutes
    max: 100,  // Limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again after 15 minutes'
});

// Rate limiter for login requests (to prevent brute force attacks)
const loginRateLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,  // 10 minutes
    max: 5,  // Limit each IP to 5 login attempts per windowMs
    message: 'Too many login attempts from this IP, please try again after 10 minutes'
});

module.exports = { generalRateLimiter, loginRateLimiter };
