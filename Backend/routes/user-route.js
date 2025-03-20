const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');
const User = require('../modules/user');
const EmailVerificationModel = require('../modules/EmailVerification')
const generateTokens = require('../utils/generateToken');

const { singleImageUpload } = require('../middleware/multer')

const fs = require('fs');
const path = require('path');
const { promisify } = require('util');
const unlinkAsync = promisify(fs.unlink);


const sendOtpVerificationEmail = require('../utils/EmailVerification')

router.get(
    '/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

router.get(
    '/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login' }),
    async (req, res) => {
        try {
            const { auth_token } = await generateTokens(req.user);

            res.redirect(`http://localhost:3000/profile?token=${auth_token}`);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    }
);


// Register
router.post('/register', singleImageUpload, async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json('Please enter valid data');
        }


        const isUserExist = await User.findOne({ email });
        if (isUserExist) {
            return res.status(400).json('User Already Exist');
        }

        const salt = await bcrypt.genSalt(Number(process.env.SALT));
        const hashPassword = await bcrypt.hash(password, salt);

        const newUser = await User.create({ email, password: hashPassword, image: req.file.filename });
        sendOtpVerificationEmail(req, res, newUser)

        res.status(201).json({
            status: true,
        })
    } catch (error) {
        console.log(error);
        res.status(500).json('Internal Server Error');
    }
});




router.post('/verifyEmail', async (req, res) => {
    try {
        const { email, otp } = req.body;

        if (!email || !otp) {
            return res.status(400).json({ status: "failed", message: "All fields are required" });
        }

        const existingUser = await User.findOne({ email });

        if (!existingUser) {
            return res.status(404).json({ status: "failed", message: "Email doesn't exists" });
        }

        if (existingUser.isVerifyed) {
            return res.status(400).json({ status: "failed", message: "Email is already verified" });
        }

        const emailVerification = await EmailVerificationModel.findOne({ userId: existingUser._id, otp });
        if (!emailVerification) {
            if (!existingUser.isVerifyed) {
                await sendEmail(req, res, existingUser)
                return res.status(400).json({ status: "failed", message: "Invalid OTP, new OTP sent to your email" });
            }
            return res.status(400).json({ status: "failed", message: "Invalid OTP" });
        }

        const currentTime = new Date();
        const expirationTime = new Date(emailVerification.createdAt.getTime() + 15 * 60 * 1000);
        if (currentTime > expirationTime) {
            await sendEmail(req, res, existingUser)
            return res.status(400).json({ status: "failed", message: "OTP expired, new OTP sent to your email" });
        }

        existingUser.isVerifyed = true;
        await existingUser.save();

        const { auth_token } = await generateTokens(existingUser)

        await EmailVerificationModel.deleteMany({ userId: existingUser._id });
        res.status(200).json({
            status: true,
            role: existingUser.role,
            auth_token
        });
    } catch (error) {
        console.log(error);
        res.status(500).json({ status: "failed", message: "Unable to verify email, please try again later" });
    }
})



// Login
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json('Please enter valid data');
        }

        const isUserExist = await User.findOne({ email });
        if (!isUserExist) {
            return res.status(400).json('User Not Exist');
        }

        const isMatch = await bcrypt.compare(password, isUserExist.password);
        if (!isMatch) {
            return res.status(400).json('Invalid Credentials');
        }

        const { auth_token } = await generateTokens(isUserExist);
        res.status(200).json({ auth_token });
    } catch (error) {
        console.log(error);
        res.status(500).json('Internal Server Error');
    }
});



router.get('/get-profile', passport.authenticate('jwt', { session: false }),
    async (req, res) => {
        try {
            res.status(200).json({ user: req.user });
        } catch (error) {
            console.log(error);
            res.status(500).json('Internal Server Error');
        }
    }
);


router.put('/update-profile-picture', passport.authenticate('jwt', { session: false }), singleImageUpload, async (req, res) => {
    try {
        const user = req.user;

        if (user.image) {
            const oldImagePath = path.join(__dirname, '..', 'uploads', user.image);
            if (fs.existsSync(oldImagePath)) {
                await unlinkAsync(oldImagePath);
            }
        }


        user.image = req.file.filename;
        await user.save();

        res.status(200).json({ message: 'Profile picture updated successfully', image: req.file.filename });

    } catch (error) {
        console.log(error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});




router.delete('/delete-profile-picture', passport.authenticate('jwt', { session: false }), async (req, res) => {
    try {
        const user = req.user;

        if (user.image) {
            const imagePath = path.join(__dirname, '..', 'uploads', user.image);

            if (fs.existsSync(imagePath)) {
                await unlinkAsync(imagePath);
            }

            user.image = null;
            await user.save();

            return res.status(200).json({ message: 'Profile picture deleted successfully' });
        } else {
            return res.status(400).json({ message: 'No profile picture found' });
        }

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});







module.exports = router;

