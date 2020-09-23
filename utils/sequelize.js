const Sequelize = require('sequelize');
const userModel = require('../models/user');
const config = require('config');

const db = config.get(config.get('DB_DIALECT'));

const sequelize = new Sequelize(
    db.SERVER,
    db.USER,
    db.PASSWORD, {
        host: db.HOST,
        dialect: config.get('DB_DIALECT').toLowerCase(),
        logging: ((config.get('ENV') === 'DEV') ? true : false),
    });

const User = userModel(sequelize, Sequelize);

sequelize.sync().then(() => {});

module.exports = {User: User};
