const express = require('express');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const cors = require('cors');
const { generalRateLimiter, loginRateLimiter } = require('./utils/rateLimiter');
const authRoute =  require('./routes/authRoute')
const noteRoute = require('./routes/noteRoute')

// Load environment variables
dotenv.config();

const corsOptions = {
   origin: ['http://localhost:3000',""],
   credentials: true,

 };

const app = express();
app.use(express.json());
app.use(express.urlencoded({extended: true}))
app.use(cookieParser());
app.use(cors(corsOptions))
app.use(generalRateLimiter);

mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true})
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.log('MongoDB connection error:', err));

//Applying rate limiting to login route only 
app.use('/api/auth/login', loginRateLimiter);

// Routes
app.use('/api/auth', authRoute);
app.use('/api', noteRoute);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
