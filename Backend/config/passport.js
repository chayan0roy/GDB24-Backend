const User = require('../modules/user'); // Add this line
const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt');
const passport = require('passport');
const dotenv = require('dotenv');
dotenv.config();

const opts = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_TOKEN_SECRET_KEY,
};

passport.use(
    new JwtStrategy(opts, async (jwt_payload, done) => {
        try {
            const user = await User.findOne({ _id: jwt_payload.id }).select('-password');
            if (user) {
                return done(null, user);
            } else {
                return done(null, false);
            }
        } catch (error) {
            return done(error, false);
        }
    })
);

module.exports = passport;