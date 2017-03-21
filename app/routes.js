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

// TODO: Security checks

module.exports = (app, passport) => {

    // =============================================================================
    // TEST API's ======================================================
    // =============================================================================

    app.get('/', (req, res) => res.render('index.html'));

    app.get('/signUp', (req, res) => res.render('sign-up.html'));

    app.get('/signIn', (req, res) => res.render('sign-in.html'));

    // app.get('/passwordForgot', (req, res) => res.render('password-forgot.html'));

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
    // TODO: Admin add user (as logged in)

    app.get('/admin', isAdmin, (req, res, next) => getAllUsers(req, res, next));

    app.put('/changeUserRole', isAdmin, (req, res) => editUser (req, res));

    app.delete('/removeUser', isAdmin, (req, res) => removeUser (req, res));

    // =============================================================================
    // RESET PASSWORD ==============================================================
    // =============================================================================

    // app.post('/passwordForgot', (req, res, next) => passwordForgot(req, res, next));
    //
    // app.get('/reset/:token', (req, res) => validateToken(req, res));
    //
    // app.post('/reset/:token', (req, res) => resetPassword(req, res));
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

function passwordForgot(req, res, next) {}

function validateToken (req, res) {}

function resetPassword(req, res) {}

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