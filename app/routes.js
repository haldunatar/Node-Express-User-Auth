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
    // TODO: Admin add user (as logged in)

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

function signUp (req, res, next) {}

function signIn (req, res, next) {}

function signOut (req, res) {}

function getAllUsers (req, res, next) {}

function editUser (req, res) {}

function removeUser (req, res) {}

function passwordForgot(req, res, next) {}

function validateToken (req, res) {}

function resetPassword(req, res) {}

function isLoggedIn(req, res, next) {}

function isAdmin(req, res, next) {}