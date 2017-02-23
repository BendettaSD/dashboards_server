/**
 * Copyright (c) Jupyter Development Team.
 * Distributed under the terms of the Modified BSD License.
 */
 /**
  * Passport JS strategy for LDAP authentication.
  */
var config = require('./config');
var bodyParser = require('body-parser');
var passport = require('passport');
var LdapStrategy = require('passport-ldapauth');
var fs = require('fs');

// create application/x-www-form-urlencoded parser
var urlencodedParser = bodyParser.urlencoded({ extended: false });

var LDAP_OPTS = {
        server: {
            url:               config.get('LDAP_URL'),
            bindDn:            config.get('LDAP_BIND_DN'),
            bindCredentials:   config.get('LDAP_BIND_CREDENTIALS'),
            searchBase:        config.get('LDAP_SEARCH_BASE'),
            searchFilter:      config.get('LDAP_SEARCH_FILTER'),
            tlsOptions: {
                ca: [
                    fs.readFileSync(config.get('LDAP_ROOT_CA')),
                ]
            }
        }
    }

module.exports = function(app) {
    // Render local login form.
    app.get('/login', function(req, res) {
        if(req.user) {
            return res.redirect('/');
        }
        res.render('login', {
            title: 'Log in',
            formAuth: true,
            authError: req.flash('error').length > 0
        });
    });


    // Validate login values
    app.post('/login', urlencodedParser,
        passport.authenticate(
            'ldapauth',
            {
                failureRedirect: '/login',
                successReturnToOrRedirect: '/',
                failureFlash: true
            }
        )
    );

    var strategy = new LdapStrategy(LDAP_OPTS,
        function(user, done) {
            return done(null, {username: user.sAMAccountName});
        }
    );

    return strategy;
};
