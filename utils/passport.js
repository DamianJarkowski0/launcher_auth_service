const bcrypt = require("bcrypt");
const Sequelize = require("sequelize");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const JwtStrategy = require("passport-jwt").Strategy,
    ExtractJwt = require("passport-jwt").ExtractJwt;
const crypto = require("crypto");
const config = require("config");
const fs = require("fs");

const {User} = require("./sequelize");
const logger = require("./logger");

const Op = Sequelize.Op;

passport.use(
    "register",
    new LocalStrategy(
        {
            usernameField: "username",
            passwordField: "password",
            passReqToCallback: true,
            session: false,
        },
        (req, username, password, done) => {
            try {
                User.findOne({where: {[Op.or]: [{username: username}, {email: req.body.email}]}}).then((user) => {
                    if (user != null) {
                        if (user.username === username) {
                            return done(null, null, "USER_EXIST");
                        } else if (user.email === req.body.email) {
                            return done(null, null, "EMAIL_EXIST");
                        }
                    }
                    bcrypt
                        .hash(password, config.get("BCRYPT_SALT_ROUND"))
                        .then((hashedPassword) => {
                            User.create({
                                username: username,
                                password: hashedPassword,
                                email: req.body.email,
                                emailConfirmationToken: crypto.randomBytes(20).toString("hex"),
                                emailConfirmationExpires: Date.now() + 86400000,
                                changePasswordDate: Date.now(),
                            }).then((user) => {
                                return done(null, user, "ACCOUNT_CREATED");
                            });
                        });
                });
            } catch (err) {
                return done(err);
            }
        },
    ),
);

passport.use(
    "login",
    new LocalStrategy(
        {
            usernameField: "username",
            passwordField: "password",
            session: false,
        },
        (username, password, done) => {
            try {
                User.findOne({where: {username}}).then((user) => {
                    if (user === null) {
                        return done(null, false, {message: "USER_NOTFOUND"});
                    }
                    if (!user.emailConfirmation) {
                        return done(null, false, {message: "EMAIL_NOTCONFIRMED"});
                    }
                    bcrypt.compare(password, user.password).then((response) => {
                        if (response !== true) {
                            logger.warn(
                                `${user.username} try to login with invalid password`,
                            );

                            return done(null, false, {message: "INVALID_CREDENTIAL"});
                        }

                        return done(null, user);
                    });
                });
            } catch (err) {
                done(err);
            }
        },
    ),
);

const publicKEY = fs.readFileSync(config.get("JWT.PUBLICKEY"), "utf8");

const opts = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: publicKEY,
    algorithm: config.get('JWT.ALGORITHM'),
};

passport.use(
    "jwt",
    new JwtStrategy(opts, function (jwtPayload, done) {
        User.findOne({
            where: {
                id: jwtPayload.id,
                username: jwtPayload.username,
                changePasswordDate: {[Op.lte]: jwtPayload.iat * 1000},
            },
        }).then((user) => {
            if (user) {
                return done(null, user);
            } else {
                logger.warn(`${jwtPayload.username} use invalid token`);

                return done(null, false, {message: "AUTHORIZATION_FAILED"});
            }
        });
    }),
);
