require('dotenv').config();
const mongoose = require('mongoose');
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const Token = require('./models/Token');
const User = require('./models/User');
const bcrypt = require('bcrypt');
const cors = require('cors');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');
const sgMail = require('@sendgrid/mail');

// SendGrid setup
sgMail.setApiKey(process.env.SENDGRID_API_KEY); 

const app = express();
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(helmet());

// MongoDB URI for session management
const mongoUri = process.env.MONGODB_URI;

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: mongoUri }),
    cookie: {
        secure: false,
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 30 * 60 * 1000
    }
}));

// Rate Limiting for Login Route
const loginLimiter = rateLimit({
    windowMs: 30 * 60 * 1000,
    max: 5,
    message: 'Too many login attempts, please try again after 30 minutes.',
    handler: (req, res, next, options) => {
        res.status(options.statusCode).json({ success: false, message: options.message });
    }
});

// Authentication Middleware
const isAuthenticated = (req, res, next) => {
    if (req.session.userId) {
        return next();
    } else {
        return res.status(401).json({ success: false, message: 'You are not authenticated.' });
    }
};

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));

// Serve pages
app.get('/forgot-password', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'forgot-password.html'));
});

app.get('/reset-password', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'reset-password.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Fetch user details
app.get('/user-details', async (req, res) => {
    try {
        const userId = req.session.userId;
        if (!userId) return res.status(401).json({ success: false, message: 'Unauthorized' });

        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });

        res.json({ success: true, user: { email: user.emaildb } });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Generate random string for token
const generateRandomString = (length) => {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    return Array.from({ length }, () => characters.charAt(Math.floor(Math.random() * characters.length))).join('');
};

// Validate email format
const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

// Forgot password endpoint
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    if (!email || !isValidEmail(email)) {
        return res.status(400).json({ success: false, message: 'A valid email is required' });
    }

    try {
        let existingToken = await Token.findOne({ email: email });
        const resetToken = generateRandomString(32);

        if (existingToken) {
            existingToken.token = resetToken;
            await existingToken.save();
        } else {
            const newToken = new Token({ email: email, token: resetToken });
            await newToken.save();
        }

        const msg = {
            to: email,
            from: 'shanimnida69@gmail.com', // Replace with your verified SendGrid email
            subject: 'Password Reset Request',
            text: `Your password reset token is: ${resetToken}`,
            html: `<p>Your password reset token is:</p><h3>${resetToken}</h3>`
        };

        // Sending email with SendGrid
        await sgMail.send(msg);
        res.status(200).json({ success: true, message: 'Password reset email sent successfully' });
    } catch (error) {
        console.error('Error processing password reset request:', error);
        res.status(500).json({ success: false, message: 'Error processing your request' });
    }
});

// Reset password endpoint
app.post('/reset-password', async (req, res) => {
    const { resetKey, newPassword } = req.body;
    if (!resetKey || !newPassword) {
        return res.status(400).json({ success: false, message: 'Reset token and new password are required.' });
    }

    try {
        const tokenDoc = await Token.findOne({ token: resetKey });
        if (!tokenDoc) return res.status(400).json({ success: false, message: 'Invalid or expired reset token.' });

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        const updatedUser = await User.findOneAndUpdate(
            { emaildb: tokenDoc.email },
            { password: hashedPassword }
        );

        if (!updatedUser) return res.status(404).json({ success: false, message: 'User not found.' });

        await Token.deleteOne({ _id: tokenDoc._id });

        res.status(200).json({ success: true, message: 'Password reset successfully.' });
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).json({ success: false, message: 'Server error. Please try again later.' });
    }
});

// Sign-up endpoint
app.post('/signup', async (req, res) => {
    const { full_name, mob_number, email, password } = req.body;

    if (!full_name || !mob_number || !email || !password) {
        return res.status(400).json({ success: false, message: 'All fields are required.' });
    }

    if (!isValidEmail(email)) {
        return res.status(400).json({ success: false, message: 'Please provide a valid email address.' });
    }

    try {
        const existingUser = await User.findOne({ emaildb: email });
        if (existingUser) {
            return res.status(400).json({ success: false, message: 'Email already registered.' });
        }

        // Step 4: Hash password and create new user
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({
            emaildb: email,
            password: hashedPassword,
            full_name: full_name,
            mob_number: mob_number
        });

        await newUser.save();
        return res.status(201).json({ success: true, message: 'Account created successfully!' });

    } catch (error) {
        console.error('Error creating account:', error);
        return res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// Login Route with Rate Limiter
app.post('/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body;

    try {
        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Email and password are required.' });
        }

        if (!validator.isEmail(email)) {
            return res.status(400).json({ success: false, message: 'Invalid email format.' });
        }

        const user = await User.findOne({ emaildb: email });
        if (!user) return res.status(400).json({ success: false, message: 'Invalid email or password.' });

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) return res.status(400).json({ success: false, message: 'Invalid email or password.' });

        req.session.userId = user._id;
        res.status(200).json({ success: true, message: 'Login successful.', user: { email: user.emaildb } });
    } catch (error) {
        console.error('Error logging in:', error);
        res.status(500).json({ success: false, message: 'Internal server error.' });
    }
});

// Logout Route
app.post('/logout', (req, res) => {
    // Destroy the session to log the user out
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).json({ success: false, message: 'Error logging out' });
        }

        // Send success response after logout
        res.status(200).json({ success: true, message: 'Logged out successfully' });
    });
});

mongoose.connect(mongoUri, { 
    ssl: true // Ensure SSL is enabled
})
    .then(() => {
        console.log('Connected to MongoDB');
        app.listen(PORT, () => {
            console.log(`Server is running on http://localhost:${PORT}`);
        });
    })
    .catch((err) => {
        console.error('Error connecting to MongoDB:', err);
        process.exit(1); // Optional: exit the app on failure to connect to DB
    });
