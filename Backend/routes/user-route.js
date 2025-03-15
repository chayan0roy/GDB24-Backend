const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');
const User = require('../modules/user');
const generateTokens = require('../utils/generateToken');

const {singleImageUpload} = require('../middleware/multer')



const fs = require('fs');
const path = require('path');
const { promisify } = require('util');
const unlinkAsync = promisify(fs.unlink);





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

        if(!email || !password) {
            return res.status(400).json('Please enter valid data');
        }


        const isUserExist = await User.findOne({ email });
        if (isUserExist) {
            return res.status(400).json('User Already Exist');
        }

        const salt = await bcrypt.genSalt(Number(process.env.SALT));
        const hashPassword = await bcrypt.hash(password, salt);

        const newUser = await User.create({ email, password: hashPassword, image:req.file.filename });

        const { auth_token } = await generateTokens(newUser);
        res.status(200).json({ auth_token });
    } catch (error) {
        console.log(error);
        res.status(500).json('Internal Server Error');
    }
});

// Login
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if(!email || !password) {
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












router.put('/update-profile-picture', passport.authenticate('jwt', { session: false }), singleImageUpload,  async (req, res) => {
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

