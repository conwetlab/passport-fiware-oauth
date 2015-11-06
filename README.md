# Passport-FIWARE-OAuth

[![Build Status](https://build.conwet.fi.upm.es/jenkins/job/passport-fiware-oauth/badge/icon)](https://build.conwet.fi.upm.es/jenkins/job/passport-fiware-oauth/)

[Passport](http://passportjs.org/) strategies for authenticating with [FIWARE](http://www.fiware.org/)
using OAuth 2.0.

**NOTE:**
This module is based on [Passport-Google-OAuth](https://github.com/jaredhanson/passport-google-oauth)
created by [Jared Hanson](https://github.com/jaredhanson).

This module lets you authenticate using FIWARE in your Node.js applications.
By plugging into Passport, FIWARE authentication can be easily and
unobtrusively integrated into any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, including
[Express](http://expressjs.com/).

The client id and client secret needed to authenticate with FIWARE can be set up from the [FIWARE IdM](https://account.lab.fiware.org/idm/myApplications/).

## Install

    $ npm install passport-fiware-oauth


## Usage of OAuth 2.0

#### Configure Strategy

The FIWARE OAuth 2.0 authentication strategy authenticates users using a FIWARE
account and OAuth 2.0 tokens.  The strategy requires a `verify` callback, which
accepts these credentials and calls `done` providing a user, as well as
`options` specifying a client ID, client secret, and callback URL.

```Javascript
var FIWAREStrategy = require('passport-fiware-oauth').OAuth2Strategy;

passport.use(new FIWAREStrategy({
    clientID: FIWARE_CLIENT_ID,
    clientSecret: FIWARE_CLIENT_SECRET,
    callbackURL: "http://127.0.0.1:3000/auth/fiware/callback"
  },
  function(accessToken, refreshToken, profile, done) {
    User.findOrCreate({ fiwareID: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));
```

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'fiware'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

```Javascript
app.get('/auth/fiware',
  passport.authenticate('fiware', { scope: 'all_info' }));

app.get('/auth/fiware/callback', 
  passport.authenticate('fiware', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/');
  });
```

## Examples

For a complete, working example, refer to the [OAuth 2.0 example](https://github.com/conwetlab/passport-fiware-oauth/tree/master/examples/oauth2).

## Tests

    $ npm install --dev
    $ npm test

## Credits

  - [Jared Hanson](https://github.com/jaredhanson)
  - [Aitor Magan](https://github.com/aitormagan)

## License

[The MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2012-2013 Jared Hanson [http://jaredhanson.net/](http://jaredhanson.net/)

Copyright (c) 2015 CoNWeT Lab. Universidad Politécnica de Madrid

