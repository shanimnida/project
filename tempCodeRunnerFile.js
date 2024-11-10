require('dotenv').config();
const mongoose = require('mongoose');
const express = require('express');
const bodyParser = require('body-parser');
const Mailgun = require('mailgun.js');
const formData = require('form-data');
const path = require('path');
const Token = require('./models/Token');  // Import the Token model

const mailgun = new Mailgun(formData);

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Configure Mailgun with API key
const mg = mailgun.client({ username: 'api', key: process.env.MAILGUN_API_KEY });

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));

// Serve forgot-password.html for the GET request
app.get('/forgot-password', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'forgot-password.html'));
});

// Generate Random String Function
const generateRandomString = (length) => {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    return Array.from({ length }, () => characters.charAt(Math.floor(Math.random() * characters.length))).join('');
};

// Email Validation Function
const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

// Forgot Password Endpoint (POST request)
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    
    // Validate the email
    if (!email || !isValidEmail(email)) {
        return res.status(400).send('A valid email is required');
    }

    try {
        // Check if the email already has a reset token
        let existingToken = await Token.findOne({ email: email });
        const resetToken = generateRandomString(32); // Generate new token

        if (existingToken) {
            // Update the token if the email already exists in DB
            existingToken.token = resetToken;
            await existingToken.save();
        } else {
            // Create a new token if the email is not in the DB
            const newToken = new Token({
                email: email,
                token: resetToken,
            });
            await newToken.save();
        }

        // Send the email with the token using Mailgun
        const msg = {
            from: 'shanimnida69@gmail.com',  // Replace with your Mailgun-verified sender email
            to: email,
            subject: 'Password Reset Request',
            text: `Your password reset token is: ${resetToken}`,
            html: `<p>Your password reset token is:</p><h3>${resetToken}</h3>`,
        };

        mg.messages.create(process.env.MAILGUN_DOMAIN, msg)
            .then(() => res.status(200).send('Password reset email sent successfully'))
            .catch((error) => {
                console.error('Error sending email:', error);
                res.status(500).send('Error sending email');
            });

    } catch (error) {
        console.error('Error finding or updating token:', error);
        res.status(500).send('Error finding or updating token');
    }
});

// Start the Server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

// MongoDB connection using .env variable
mongoose.connect(process.env.MONGO_URI)
    .then(() => {
        console.log('Connected to MongoDB');
    })
    .catch((error) => {
        console.error('MongoDB connection error:', error);
    });
