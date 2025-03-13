const express = require('express');
const passport = require('passport');
const dotenv = require('dotenv');
const session = require('express-session');
dotenv.config();

const app = express();

const db = require('./config/database');

app.use(session({
    secret: process.env.JWT_TOKEN_SECRET_KEY,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

app.use(passport.initialize());
app.use(passport.session());

require('./config/passport');
require('./config/passport-google');

app.use(express.json());

const userRoute = require('./routes/user-route');
app.use('/User', userRoute);

app.listen(process.env.PORT, () => {
    console.log(`Server running on port ${process.env.PORT}`);
});