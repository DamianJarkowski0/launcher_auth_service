module.exports = (sequelize, type) => sequelize.define('user', {
    id: {
        type: type.INTEGER,
        primaryKey: true,
        autoIncrement: true,
    },
    username: {
        type: type.STRING,
        allowNull: false,
    },
    password: {
        type: type.STRING,
        allowNull: false,
    },
    email: {
        type: type.STRING,
        allowNull: false,
    },
    emailConfirmation: {
        field: 'email_confirmation',
        type: type.BOOLEAN,
        allowNull: false,
        defaultValue: false,
    },
    emailConfirmationToken: {
        field: 'email_confirmation_token',
        type: type.STRING,
    },
    emailConfirmationExpires: {
        field: 'email_confirmation_expires',
        type: type.DATE,
    },
    resetPasswordToken: {
        field: 'reset_password_token',
        type: type.STRING,
    },
    resetPasswordExpires: {
        field: 'reset_password_expires',
        type: type.DATE,
    },
    changePasswordDate: {
        field: 'change_password_date',
        type: type.DATE,
        allowNull: false,
    },
},
{
    underscored: true,
    createdAt: 'created_at',
    updatedAt: 'updated_at',
});
