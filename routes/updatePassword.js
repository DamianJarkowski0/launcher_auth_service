const passport = require('passport');
const bcrypt = require('bcrypt');
const config = require('config');
const logger = require('../utils/logger');

module.exports = (app) => {
    app.put('/updatePassword', (req, res, next) => {
        passport.authenticate('jwt', {session: false}, (err, user, info) => {
            if (err) {
                logger.error(err);

                return res.status(403).send({success: false, message: err});
            }

            if (info !== undefined) {
                return res.status(403)
                    .send({success: false, message: info.message.replace(/ /g,'_').toUpperCase()});
            }

            if (user) {
                if (req.body.password) {
                    bcrypt.hash(req.body.password, config.get("BCRYPT_SALT_ROUND"))
                        .then((hashedPassword) => {
                            user.update({
                                password: hashedPassword,
                                changePasswordDate: Date.now(),
                            });
                        })
                        .then(() => {
                            return res.status(200).send({auth: true, message: 'PASSWORD_UPDATED'});
                        });
                } else {
                    return res.status(400).send({success: false, message: "PASSWORD_REQUIRED"});
                }
            }
        })(req, res, next);
    });
};

/**
 * @api {put} /updatePassword Endpoint to change password.
 * @apiPermission JWT
 *
 * @apiName updatePassword
 * @apiGroup User
 *
 * @apiHeader {String} Authorization JWT token required to authorization
 * @apiHeaderExample {json} Header-Example:
 *     {
 *        "Authorization": "bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJraXNpNjkiLCJpYXQiOjE1NjU1MTc4NjZ9.RBUZLxMuhmbZKyPkb_CNQvmHK7cgDixqBDqmGzfmvJl5m1c2OVfX-TkwXO1iLjuKZc_ro1WeyVoGXyg_EEejNkq8AL_Nhiz31GB2gqOyriOdQWBMP-UY8Nrhb9rUvMQIBvRoXXXqktIfPxWPdGxXVxM6I4IAUknY6XLJNCu3DunM2SPt7bTIH9fXaAGAPb9M-nQ0ZpSysGasElvFKr91M02bGAgmDqzqns6OFCdOOWh5q8FAfpptA3GUizDjB33ftc1E18g9Mk9LCHiyWsunQzsiMpBlR5Fuw09dtXXIZiQPkG7RDyJwsBH1xarBMXtMSOjA1jrRE1JlFIw1m7m77w"
 *     }
 *
 * @apiParam {String}password new password.
 * @apiParamExample {json} Request-Example:
 *     {
 *       "password": "1234567890"
 *     }
 *
 * @apiSuccess {Boolean} success Return true
 * @apiSuccess {String} message Return PASSWORD_UPDATED
 * @apiSuccessExample {json} Success-Response:
 * {
 *    "success": true,
 *    "message": "PASSWORD_UPDATED"
 * }
 *
 * @apiError PASSWORD_REQUIRED When <code>password</code> not exist in request.
 * @apiError AUTHORIZATION_FAILED When <code>JWT</code> expired or not exist.
 * @apiError OTHER Can return other message when caught other unexpected error.
 * @apiErrorExample {json} Error-Response:
 * {
 *    "success": false,
 *    "message": "PASSWORD_REQUIRED"
 * }
 */
