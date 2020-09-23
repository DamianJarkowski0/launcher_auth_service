'use strict';
const jwt = require('jsonwebtoken');
const passport = require('passport');
const fs = require('fs');
const config = require('config');
const logger = require('../utils/logger');

const privateKEY = fs.readFileSync(config.get('JWT.PRIVATEKEY'), 'utf8');

module.exports = (app) => {
    app.post('/user/login', (req, res, next) => {
        passport.authenticate('login', (err, user, info) => {
            if (err) {
                logger.error(err);

                return res.status(403)
                    .send({success: false, message: "UNEXPECTED_ERROR"});
            }

            if (info !== undefined) {
                logger.error(info.message);

                return res.status(401)
                    .send({success: false, message: info.message});
            }

            if (user !== undefined) {
                jwt.sign({id: user.id, username: user.username},
                    privateKEY,
                    {algorithm: config.get('JWT.ALGORITHM')},
                    function (err, token) {
                        if (err) {
                            logger.error(err);

                            return res.status(403)
                                .send({success: true, message: err});
                        }

                        return res.status(200)
                            .send({success: true, message: token});
                    });
            }
        })(req, res, next);
    });
};

/**
 * @api {post} /user/login Login to generate JWT token
 * @apiPermission none
 *
 * @apiName login
 * @apiGroup User
 *
 * @apiParam {String}username your login.
 * @apiParam {String}password your password.
 * @apiParamExample {json} Request-Example:
 *     {
 *       "username": "myLogin",
 *       "password": "1234567890"
 *     }
 *
 * @apiSuccess {Boolean} success Return true if login successful
 * @apiSuccess {String} message Return JWT token
 * @apiSuccessExample {json} Success-Response:
 * {
 *    "success": true,
 *    "message": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.
 * eyJpZCI6MSwidXNlcm5hbWUiOiJraXNpNjkiLCJpYXQiOjE1NjU1MTc4NjZ9.
 * RBUZLxMuhmbZKyPkb_CNQvmHK7cgDixqBDqmGzfmvJl5m1c2OVfX-TkwXO1iL
 * juKZc_ro1WeyVoGXyg_EEejNkq8AL_Nhiz31GB2gqOyriOdQWBMP-UY8Nrhb9r
 * UvMQIBvRoXXXqktIfPxWPdGxXVxM6I4IAUknY6XLJNCu3DunM2SPt7bTIH9fX
 * aAGAPb9M-nQ0ZpSysGasElvFKr91M02bGAgmDqzqns6OFCdOOWh5q8FAfpptA
 * 3GUizDjB33ftc1E18g9Mk9LCHiyWsunQzsiMpBlR5Fuw09dtXXIZiQPkG7RDy
 * JwsBH1xarBMXtMSOjA1jrRE1JlFIw1m7m77w"
 * }
 *
 * @apiError UNEXPECTED_ERROR Catch unexpected error.
 * @apiError USER_NOTFOUND The <code>user</code> does not exist in database.
 * @apiError EMAIL_NOTCONFIRMED Returned when <code>EMAIL ADDRESS</code>
 * is not confirmed.
 * @apiError INVALID_CREDENTIAL Wrong password.
 * @apiError OTHER Can return other message when caught other unexpected error.
 * @apiErrorExample {json} Error-Response:
 * {
 *    "success": false,
 *    "message": "USER_NOTFOUND"
 * }
 */
