const {User} = require('../utils/sequelize');
const logger = require('../utils/logger');

module.exports = (app) => {
    app.get('/email/validate/:token', (req, res, next) => {
        User.findOne({where: {emailConfirmationToken: req.params.token}})
            .then((user) => {
                if (user === null) {
                    logger.warn(`Token ${req.params.token} not found`);

                    return res.status(403)
                        .send({success: false, message: 'TOKEN_NOTFOUND'});
                }

                if (user.emailConfirmationExpires < Date.now()) {
                    logger.warn(`Token ${req.params.token} expired`);

                    return res.status(403)
                        .send({success: false, message: 'TOKEN_EXPIRED'});
                }

                user.update({
                    emailConfirmation: 1,
                    emailConfirmationToken: null,
                    emailConfirmationExpires: null,
                })
                    .then(() => {
                        return res.status(200)
                            .send({success: true, message: 'EMAIL_CONFIRMED'});
                    });
            });
    }
    );
};

/**
 * @api {get} /email/validate/:token Validate email on account
 * @apiPermission none
 *
 * @apiName email validate
 * @apiGroup User
 *
 * @apiExample {curl} Example usage:
 *     curl -i http://localhost:3000/email/validate/tg45wg5y54wgywb5ybtwy5hgwb5ybg
 *
 * @apiSuccess {Boolean} success Return true
 * @apiSuccess {String} message EMAIL_CONFIRMED
 * @apiSuccessExample {json} Success-Response:
 * {
 *    "success": true,
 *    "message": "EMAIL_CONFIRMED"
 * }
 *
 * @apiError TOKEN_EXPIRED When <code>token</code> is expired.
 * @apiError TOKEN_NOTFOUND When <code>token</code> doesn't exist.
 * @apiErrorExample {json} Error-Response:
 * {
 *    "success": false,
 *    "message": "TOKEN_EXPIRED"
 * }
 */
