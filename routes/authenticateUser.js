const jwt = require('jsonwebtoken');
const Sequelize = require('sequelize');
const config = require('config');
const fs = require('fs');
const logger = require('../utils/logger');
const {User} = require('../utils/sequelize');

const Op = Sequelize.Op;
const publicKEY = fs.readFileSync(config.get('JWT.PUBLICKEY'), 'utf8');

module.exports = (app) => {
    app.post('/auth', (req, res, next) => {
        try {
            if (req.headers.token === undefined) {
                throw 'TOKEN_NOTFOUND';
            }

            jwt.verify(req.headers.token,
                publicKEY,
                {algorithms: [config.get('JWT.ALGORITHM')]},
                function (err, pay) {
                    if (err) {
                        return res.status(200)
                            .send({success: true, message: err.name.toUpperCase()});
                    }

                    if (pay) {
                        User.findOne({
                            where: {
                                id: pay.id,
                                username: pay.username,
                                changePasswordDate: {[Op.lte]: (pay.iat*1000)},
                            },
                        }).then((user) => {
                            if (user) {
                                return res.status(200).send({success: true});
                            } else {
                                return res.status(200)
                                    .send({success: true, message: 'AUTHORIZATION_FAILED'});
                            }
                        });
                    }
                });
        } catch (e) {
            logger.error(e);

            return res.status(403).send({success: false, message: e});
        }
    },
    );
};

/**
 * @api {post} /auth Endpoint to verife if JWT token is valid.
 * @apiPermission none
 *
 * @apiName auth
 * @apiGroup User
 *
 * @apiHeader {String} token JWT token required to authorization
 * @apiHeaderExample {json} Header-Example:
 *     {
 *        "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJraXNpNjkiLCJpYXQiOjE1NjU1MTc4NjZ9.RBUZLxMuhmbZKyPkb_CNQvmHK7cgDixqBDqmGzfmvJl5m1c2OVfX-TkwXO1iLjuKZc_ro1WeyVoGXyg_EEejNkq8AL_Nhiz31GB2gqOyriOdQWBMP-UY8Nrhb9rUvMQIBvRoXXXqktIfPxWPdGxXVxM6I4IAUknY6XLJNCu3DunM2SPt7bTIH9fXaAGAPb9M-nQ0ZpSysGasElvFKr91M02bGAgmDqzqns6OFCdOOWh5q8FAfpptA3GUizDjB33ftc1E18g9Mk9LCHiyWsunQzsiMpBlR5Fuw09dtXXIZiQPkG7RDyJwsBH1xarBMXtMSOjA1jrRE1JlFIw1m7m77w"
 *     }
 *
 * @apiSuccess {Boolean} success Return true if login successful
 * @apiSuccess {String} message Return JWT token
 * @apiSuccessExample {json} Success-Response:
 * {
 *    "success": true
 * }
 *
 * @apiError TOKEN_NOTFOUND When header doesn't contain <code>token</code>.
 * @apiError AUTHORIZATION_FAILED When <code>JWT</code> expired or not exist.
 * @apiError OTHER Can return other message when caught other unexpected error.
 * @apiErrorExample {json} Error-Response:
 * {
 *    "success": false,
 *    "message": "TOKEN_NOTFOUND"
 * }
 */
