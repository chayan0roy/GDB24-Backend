const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    image:{
        type: String,
    },
    googleId: {
        type: String,
    },
    email: {
        type: String,
        required: true,
        unique: true,
    },
    password: {
        type: String,
    },
    isVerifyed: {
        type: Boolean,
        default: false
    }
}, { timestamps: true });

const UserModel = mongoose.model('user', UserSchema);
module.exports = UserModel;