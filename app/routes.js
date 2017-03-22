'use strict';

const mongoose = require('mongoose');
const async = require('async');
const fs = require('fs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const smtpTransport = require('nodemailer-smtp-transport');
const passport = require('passport');
const Users = require('./models/user');
const bcrypt = require('bcrypt-nodejs');

/*
    * TODO: Security checks
    * TODO: Unit tests
    * TODO: Sessions or token based?
*/

module.exports = (app, passport) => {

    // =============================================================================
    // TEST API's ======================================================
    // =============================================================================

    app.get('/', (req, res) => res.render('index.html'));

    app.get('/signUp', (req, res) => res.render('sign-up.html'));

    app.get('/signIn', (req, res) => res.render('sign-in.html'));

    app.get('/passwordForgot', (req, res) => res.render('password-forgot.html'));

    app.get('/restrictedArea', isLoggedIn, (req, res) => res.render('user.html'));

    // =============================================================================
    // SIGNING ======================================================
    // =============================================================================

    app.post('/signUp', (req, res, next) => signUp(req, res, next));

    app.post('/signIn', (req, res, next) => signIn(req, res, next));

    app.post('/signOut', isLoggedIn, (req, res) => signOut(req, res));

    // =============================================================================
    // Admin ======================================================
    // =============================================================================
    //

    app.get('/admin', isAdmin, (req, res, next) => getAllUsers(req, res, next));

    app.put('/changeUserRole', isAdmin, (req, res) => editUser (req, res));

    app.delete('/removeUser', isAdmin, (req, res) => removeUser (req, res));

    // =============================================================================
    // RESET PASSWORD ==============================================================
    // =============================================================================

    app.post('/passwordForgot', (req, res, next) => passwordForgot(req, res, next));

    app.get('/reset/:token', (req, res) => validateToken(req, res));

    app.post('/reset/:token', (req, res) => resetPassword(req, res));
};

function signUp (req, res, next) {
    passport.authenticate('local-signup', (err, user, info) => {

        if (err) {
            console.log('err!', err);
            return next(err);

        } else if(!user) {

            return res.send(info);
        } else {

            return res.send(200);
        }
    })(req, res, next);
}

function signIn (req, res, next) {

    passport.authenticate('local-login', (err, user, info) => {

        if (err) {
            return next(err);
        }
        else if (!user) {
            return res.send(info);
        }
        else {
            req.logIn(user, (err) => {

                if (err) {
                    return next(err);
                } else {
                    user.isAdmin = true;
                    res.redirect('/restrictedArea');
                }
            });
        }
    })(req, res, next);
}

function signOut (req, res) {

    req.logout();
    res.redirect('/');
}

function getAllUsers (req, res, next) {
    Users.find({}, (err, users) => {

        if (err) {
            res.send(err)
        } else {
            res.send(users)
        }
    });
}

function editUser (req, res) {
    Users.update({_id: req.body.userId}, {isAdmin: req.body.isAdmin}, (err, user) => {
        if (err) {
            res.send(err);
        } else {
            res.send(200);
        }
    });
}

function removeUser (req, res) {
    Users.remove({_id: req.body.userId}, (err, user) => {
        if (err) {
            res.send(err);
        } else {
            res.send(200);
        }
    });
}

function passwordForgot(req, res, next) {
    let token;

    async.waterfall([
        (done) => {
            crypto.randomBytes(20, (err, buf) => {
                token = buf.toString('hex');
                done(err, token);
            });
        },
        (token, done) => {
            Users.findOne({ 'local.email': req.body.email }, (err, user) => {
                if (!user) {
                    return res.send({
                        status: 401,
                        message: 'No account with that email address exists.'
                    });
                }

                user.resetPasswordToken = token;
                user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

                user.save((err) => {
                    done(err, token, user);
                });
            });
        },
        (token, user, done) => {

            const mailOptions = {
                to: req.body.email,
                from: 'yourEmailAddress',
                subject: 'Node.js Password Reset',
                text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
                'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
                'http://' + req.headers.host + '/reset/' + token + '\n\n' +
                'If you did not request this, please ignore this email and your password will remain unchanged.\n'
            };

            const smtpTransport = nodemailer.createTransport('SMTP', {
                service: 'gmail',
                auth: {
                    user: 'yourEmailAddress',
                    pass: 'yourPass'
                }
            });

            smtpTransport.sendMail(mailOptions, (err) => {
                return res.send({
                    status: 200,
                    message: 'Sent to ' + user.local.email
                });
                done(err, 'done');
            });
        }
    ], (err) => {

        if (err) return next(err);
        res.redirect('/passwordForgot');
    });
}

function validateToken (req, res) {
    Users.findOne({resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, (err, user) =>{
        if (!user) {
            res.send('Password reset token is invalid or has expired.');
        }
        res.redirect('/passwordForgot');
    });
}

function resetPassword(req, res) {

    async.waterfall([
        (done) => {
            Users.findOne({resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, (err, user) => {
                if (!user) {
                    res.writeHeader(200, {"Content-Type": "text/html"});
                    res.write('<h2>This link is expired! <a href="/#/forgot">create new</a></h2>');
                    res.end();
                }

                user.local.password = bcrypt.hashSync(req.body.password, bcrypt.genSaltSync(8), null);
                user.resetPasswordToken = undefined;
                user.resetPasswordExpires = undefined;

                user.save((err) => {
                    req.logIn(user, (err) => {
                        done(err, user);
                    });
                });
            });
        },
        (user, done) => {
            var mailOptions = {
                to: user.local.email,
                from: 'yourEmailAddress',
                subject: 'Your password has been changed',
                text: 'Hello,\n\n' +
                'This is a confirmation that the password for your account ' + user.local.email + ' has just been changed.\n'
            };

            var smtpTransport = nodemailer.createTransport('SMTP', {
                service: 'gmail',
                auth: {
                    user: 'yourEmailAddress',
                    pass: 'yourPass'
                }
            });
            smtpTransport.sendMail(mailOptions, (err) => {
                // password changed and a confirmation email is sent to user
                return res.redirect('/signIn');
                done(err);
            });
        }
    ], (err) => {
        res.redirect('/');
    });
}

function isLoggedIn(req, res, next) {

    if (req.isAuthenticated()){
        return next();
    } else{
        res.redirect('/signIn');
    }
}

function isAdmin(req, res, next) {

    if(req.isAuthenticated()) {

        if (req.user && req.user.isAdmin === true) {
            return next();
        } else {
            res.send(401, 'Unauthorized');
        }
    } else {
        res.redirect('/signIn');
    }
}