const passport = require('passport');
const fetch = require('isomorphic-fetch');
const nodemailer = require('nodemailer');
const config = require('config');
const logger = require('../utils/logger');

/**
 * ReCaptcha Validation
 * @param {object} req Request Object.
 * @returns {object} Json object.
 */
function checkReCaptcha(req) {
    if (req.body.token === undefined || req.body.token === '') {
        logger.warn(`${req.body.username} try to register without ReCaptcha`);
        throw 'RECAPTCHA-TOKEN-REQUIRED';
    }
    const url = `https://www.google.com/recaptcha/api/siteverify?` +
                `secret=${config.get("RECAPTCHA_SECRET")}&` +
                `response=${req.body.token}&` +
                `remoteip=${req.connection.remoteAddress}`;

    return fetch(url)
        .then((response) => response.json())
        .then((contents) => {
            if (contents.success) {
                return {
                    success: true,
                    message: contents.score,
                };
            } else {
                throw contents["error-codes"][0];
            }
        });
}

module.exports = (app) => {
    app.post('/register', (req, res, next) => {
        checkReCaptcha(req)
            .then(() => {
                passport.authenticate('register', (err, user, info) => {
                    if (err) {
                        logger.error(err);

                        return res.status(403).send({success: false, message: err});
                    }
                    if (!user) {
                        return res.status(403).send({success: false, message: info.message});
                    } else {
                        const transporter = nodemailer.createTransport({
                            service: 'gmail',
                            auth: {
                                user: `${config.get("EMAIL_LOGIN")}`,
                                pass: `${config.get("EMAIL_PASSWORD")}`,
                            },
                        });

                        const mailOptions = {
                            from: 'indbuildcraft',
                            to: `${user.email}`,
                            subject: 'Link to confirmation account',
                            text:
`'Hello,\n\n` +
`You are receiving this email because you created an account at IBC.\n\n` +
`Please click on the link below to verify your account:\n\n` +
`------------------------------------------------------\n` +
`${config.get("PROTOCOL")}://${config.get("IP")}:${config.get("PORT")}/email/validate/${user.emailConfirmationToken}\n` +
`------------------------------------------------------\n`,
                        };

                        transporter.sendMail(mailOptions, (err, response) => {
                            if (err) {
                                logger.error(err);
                            } else {
                                logger.log(response);
                            }
                        });

                        return res.status(200).send({success: true, message: 'ACCOUNT_CREATED'});
                    }
                })(req, res, next);
            }).catch((err) => {
                logger.error(err);

                return res.status(403).send({success: false, message: err});
            });
    });
};

/**
 * @api {post} /register Registration endpoint
 * @apiPermission none
 *
 * @apiName register
 * @apiGroup User
 *
 * @apiParam {String}username your username.
 * @apiParam {String}password your password.
 * @apiParam {String}email your email address.
 * @apiParam {String}token ReCaptcha3 token.
 * @apiParamExample {json} Request-Example:
 *     {
 *       "username": "myUsername",
 *       "password": "1234567890",
 *       "token": "your@email.ocm",
 *       "token": "ieurtywgeoritgb54y8tferwyiouwygtiouwyeriotubryoitnvbryv"
 *     }
 *
 * @apiSuccess {Boolean} success Return true
 * @apiSuccess {String} message Return ACCOUNT_CREATED
 * @apiSuccessExample {json} Success-Response:
 * {
 *    "success": true,
 *    "message": "ACCOUNT_CREATED"
 * }
 *
 * @apiError RECAPTCHA_XXX For Recaptcha error.
 * @apiError USER_EXIST When <code>user</code> exist in database.
 * @apiError EMAIL_EXIST When <code>email address</code> exist in database.
 * @apiError OTHER Can return other message when caught other unexpected error.
 * @apiErrorExample {json} Error-Response:
 * {
 *    "success": false,
 *    "message": "USER_EXIST"
 * }
 */
