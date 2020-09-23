const crypto = require('crypto');
const {User} = require('../utils/sequelize');
const nodemailer = require('nodemailer');
const config = require('config');
const logger = require('../utils/logger');

module.exports = (app) => {
    app.post('/forgotPassword', (req, res) => {
        if (!req.body.email || req.body.email === '') {
            return res.status(400)
                .send({success: false, message: "EMAIL_REQUIRED"});
        }

        User.findOne({where: {email: req.body.email}})
            .then((user) => {
                if (user) {
                    const token = crypto.randomBytes(20).toString('hex');

                    user.update({
                        resetPasswordToken: token,
                        resetPasswordExpires: Date.now() + 3600000,
                    }).then(() => {
                        const transporter = nodemailer.createTransport({
                            service: 'gmail',
                            auth: {
                                user: `${config.get("EMAIL.LOGIN")}`,
                                pass: `${config.get("EMAIL.PASSWORD")}`,
                            },
                        });

                        const mailOptions = {
                            from: 'indbuildcraft',
                            to: `${user.email}`,
                            subject: 'Link To Reset Password',
                            text:
`'Hello,\n\n` +
`You are receiving this email because you want to reset password on IBC.\n\n` +
`Please click on the link below to open reset password page:\n\n` +
`------------------------------------------------------\n` +
`${config.get("WEB.URL")}/reset/${token}\n` +
`------------------------------------------------------\n`,
                        };

                        transporter.sendMail(mailOptions, (err, response) => {
                            if (err) {
                                logger.error(err);
                                res.status(403)
                                    .send({success: false,message: "CANNOT_SEND_EMAIL"});
                            } else {
                                logger.log(response);
                                res.status(200)
                                    .send({success: true, message: "EMAIL_SEND"});
                            }
                        });
                    });
                } else {
                    return res.status(403).send({success: false, message: "EMAIL_NOTFOUND"});
                }
            });
    });
};

/**
 * @api {post} /forgotPassword Send email with link to reset password
 * @apiPermission none
 *
 * @apiName forgotPassword
 * @apiGroup User
 *
 * @apiParam {String}email Email address.
 * @apiParamExample {json} Request-Example:
 *     {
 *       "email": "example@mail.com"
 *     }
 *
 * @apiSuccess {Boolean} success Return true
 * @apiSuccess {String} message EMAIL_SEND
 * @apiSuccessExample {json} Success-Response:
 * {
 *    "success": true,
 *    "message": "EMAIL_SEND"
 * }
 *
 * @apiError EMAIL_REQUIRED When <code>EMAIL</code> doesn't exist in request body.
 * @apiError CANNOT_SEND_EMAIL When error occurred during sending email.
 * @apiError EMAIL_NOTFOUND Returned when <code>EMAIL</code> doesn't exist in database.
 * @apiError OTHER Can return other message when caught other unexpected error.
 * @apiErrorExample {json} Error-Response:
 * {
 *    "success": false,
 *    "message": "USER_NOTFOUND"
 * }
 */
