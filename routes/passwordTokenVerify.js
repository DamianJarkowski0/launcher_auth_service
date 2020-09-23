const Sequelize = require('sequelize');
const {User} = require('../utils/sequelize');
const logger = require('../utils/logger');

const Op = Sequelize.Op;

module.exports = (app) => {
    app.get('/passwordTokenVerify', (req, res) => {
        User.findOne({
            where: {
                resetPasswordToken: req.query.resetPasswordToken,
                resetPasswordExpires: {[Op.gt]: Date.now()},
            },
        }).then((user) => {
            if (user) {
                return res.status(200)
                    .send({success: true, message: "TOKEN_VALID"});
            } else {
                logger.warn(`Token ${req.query.resetPasswordToken} not valid`);

                return res.status(403)
                    .send({success: false, message: "TOKEN_INVALID"});
            }
        });
    });
};

/**
 * @api {get} /passwordTokenVerify:resetPasswordToken
 * Check if reset password token is valid
 * @apiPermission none
 *
 * @apiName passwordTokenVerify
 * @apiGroup User
 *
 * @apiExample {curl} Example usage:
 *     curl -i http://localhost:3000/passwordTokenVerify?resetPasswordToken=6390371a0fd92fd743377e7ad544d3524a1c3e7e
 *
 * @apiSuccess {Boolean} success Return true
 * @apiSuccess {String} message TOKEN_VALID
 * @apiSuccessExample {json} Success-Response:
 * {
 *    "success": true,
 *    "message": "TOKEN_VALID"
 * }
 *
 * @apiError TOKEN_INVALID_OR_EXPIRED When <code>token</code>
 * is expired or invalid.
 * @apiErrorExample {json} Error-Response:
 * {
 *    "success": false,
 *    "message": "TOKEN_INVALID_OR_EXPIRED"
 * }
 */
