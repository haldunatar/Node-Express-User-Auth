const express  = require('express');
const app      = express();
const path = require('path');
const port  	 = process.env.PORT || 8000;// set the port
const mongoose = require('mongoose');
const database = require('./config/database');
const morgan   = require('morgan');
const bodyParser = require('body-parser');
const passport = require('passport');
const cookieParser = require('cookie-parser');
const session      = require('express-session');

mongoose.connect(database.url);

app.set('view engine', 'ejs'); // set ejs to template
app.engine('html', require('ejs').renderFile); // revert to html
app.set('views', __dirname + '/public');
app.use(bodyParser.urlencoded({'extended':'true'})); // parse application/x-www-form-urlencoded
app.use(bodyParser.json()); // parse application/json
app.use(bodyParser.json({ type: 'application/vnd.api+json' })); // parse application/vnd.api+json as json

//Authentication
app.use(cookieParser()); // read cookies (needed for auth)
app.use(morgan('dev')); // log every request to the console
app.use( session( { secret: 'thisismyApp',
        cookie: { maxAge: 1200000 },
        rolling: true,
        resave: true,
        path: '/user',
        saveUninitialized: false
    }
    )
);
app.use(passport.initialize());
app.use(passport.session()); // persistent login sessions

// routes ======================================================================
require('./app/routes.js')(app, passport);
require('./config/passport')(passport); // pass passport for configuration

app.listen(port);
console.log("App is running on " + port);