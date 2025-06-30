const sanitizeUser = (user) => {
    return {
        _id: user._id,
        name: user.name,
        email: user.email,
        isVerified: user.isVerified
    };
};

module.exports = { sanitizeUser };
