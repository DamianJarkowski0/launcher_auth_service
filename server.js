const express = require("express");
const https = require("https");
const spdy = require("spdy");
const cors = require("cors");
const bodyParser = require("body-parser");
const compression = require("compression");

const passport = require("passport");

const fs = require("fs");
const path = require("path");
const rfs = require("rotating-file-stream");
const morgan = require("morgan");

const config = require("config");
const logger = require("./utils/logger");

const logDirectory = path.join(__dirname, "log");

fs.existsSync(logDirectory) || fs.mkdirSync(logDirectory);

const accessLogStream = rfs("requests.log", {
    interval: "1d",
    path: logDirectory,
});

const app = express();
const API_PORT = config.get("PORT") || 3000;

require("./utils/passport");

app.unsubscribe(compression());
app.use(cors());
app.use(bodyParser.urlencoded({extended: false}));
app.use(bodyParser.json());
app.use(morgan("combined", {stream: accessLogStream}));
app.use(passport.initialize());

require("./routes/loginUser")(app);
require("./routes/authenticateUser")(app);
require("./routes/registerUser")(app);
require("./routes/updatePassword")(app);
require("./routes/forgotPassword")(app);
require("./routes/updatePasswordViaToken")(app);
require("./routes/passwordTokenVerify")(app);
require("./routes/validateEmail")(app);
require("./routes/docs")(app);

const options = (config.get("PROTOCOL") === "https" || config.get("PROTOCOL") === "http/2") && {
    key: fs.readFileSync(config.get("SSL.KEY")),
    cert: fs.readFileSync(config.get("SSL.CERT")),
};

if (config.get("PROTOCOL") === "https") {
    https
        .createServer(options, app)
        .listen(API_PORT, () =>
            logger.info(`Listening on port ${API_PORT} using HTTPS`),
        );
} else if (config.get("PROTOCOL") === "http/2") {
    spdy
        .createServer(options, app)
        .listen(API_PORT, () =>
            logger.info(`Listening on port ${API_PORT} using HTTP/2`),
        );
} else {
    app.listen(API_PORT, () =>
        logger.info(`Listening on port ${API_PORT} using HTTP`),
    );
}

module.exports = app;
