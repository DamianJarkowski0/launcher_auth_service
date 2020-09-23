const bcrypt = require('bcrypt');
const Sequelize = require('sequelize');
const {User} = require('../utils/sequelize');

const Op = Sequelize.Op;
const config = require('config');
const logger = require('../utils/logger');

module.exports = (app) => {
    app.put('/updatePasswordViaToken', (req, res) => {
        User.findOne({
            where: {
                username: req.body.username,
                resetPasswordToken: req.body.resetPasswordToken,
                resetPasswordExpires: {[Op.gt]: Date.now()},
            },
        }).then((user) => {
            if (user) {
                bcrypt.hash(req.body.password, config.get('CRYPT_SALT_ROUND'))
                    .then((hashedPassword) => {
                        user.update({
                            password: hashedPassword,
                            resetPasswordToken: null,
                            resetPasswordExpires: null,
                            changePasswordDate: Date.now(),
                        });
                    })
                    .then(() => {
                        return res.status(200)
                            .send({success: false, message: 'PASSWORD_UPDATED'});
                    });
            } else {
                logger.warn(`${req.body.username} try to change password with invalid token!`);

                return res.status(403)
                    .send({success: false, message: 'TOKEN_INVALID_OR_EXPIRED'});
            }
        });
    });
};

/**
 * @api {put} /updatePasswordViaToken Change password using token from Email
 * @apiPermission none
 *
 * @apiName updatePasswordViaToken
 * @apiGroup User
 *
 * @apiParam {String}username Login.
 * @apiParam {String}password New Password
 * @apiParam {String}resetPasswordToken Token required to change password.
 * @apiParamExample {json} Request-Example:
 *     {
 *         "username": "username",
 *         "password": "newPassword",
 *         "resetPasswordToken": "6390371a0fd92fd743377e7ad544d3524a1c3e7e"
 *     }
 *
 * @apiSuccess {Boolean} success Return true
 * @apiSuccess {String} message PASSWORD_UPDATED
 * @apiSuccessExample {json} Success-Response:
 * {
 *    "success": true,
 *    "message": "PASSWORD_UPDATED"
 * }
 *
 * @apiError TOKEN_INVALID_OR_EXPIRED When token is expired or invalid for user.
 * @apiErrorExample {json} Error-Response:
 * {
 *    "success": false,
 *    "message": "TOKEN_INVALID_OR_EXPIRED"
 * }
 */
