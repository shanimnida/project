const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    emaildb: {
        type: String,
        required: true,  
        unique: true,  
        trim: true,   
    },
    password: { 
        type: String, 
        required: true },
    full_name: { 
        type: String, 
        required: true },
    mob_number: { 
        type: String, 
        required: true }
});

const User = mongoose.model('User', UserSchema);
module.exports = User;
