require('dotenv').config()
const jwt=require('jsonwebtoken')
const { sanitizeUser } = require('../utils/SanitizeUser')

exports.verifyToken=async(req,res,next)=>{
    try {
        // extract the token from request cookies
        const {token}=req.cookies

        // if token is not there, return 401 response
        if(!token){
            return res.status(401).json({message:"Token missing, please login again"})
        }

        // verifies the token 
        const decodedInfo=jwt.verify(token,process.env.SECRET_KEY)

        // checks if decoded info contains legit details, then set that info in req.user and calls next
        if(decodedInfo){
            req.user=decodedInfo
            next()
        }

        // if token is invalid then sends the response accordingly
        else{
            return res.status(401).json({message:"Invalid Token, please login again"})
        }
        
    } catch (error) {

        console.log(error);
        
        if (error instanceof jwt.TokenExpiredError) {
            return res.status(401).json({ message: "Token expired, please login again" });
        } 
        else if (error instanceof jwt.JsonWebTokenError) {
            return res.status(401).json({ message: "Invalid Token, please login again" });
        } 
        else {
            return res.status(500).json({ message: "Internal Server Error" });
        }
    }
}

// Admin Verification Middleware
exports.verifyAdmin = async (req, res, next) => {
    try {
        // Ensure the user is available (token verified)
        if (!req.user) {
            return res.status(401).json({ message: "Not authorized" });
        }

        // Fetch the user from the database using userId (from the decoded token)
        const user = await User.findById(req.user.userId);

        // Check if the user exists and has admin privileges
        if (!user || !user.isAdmin) {
            return res.status(403).json({ message: "Access denied. Admins only." });
        }

        // If the user is an admin, move to the next middleware or route handler
        return next();

    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Internal Server Error" });
    }
};