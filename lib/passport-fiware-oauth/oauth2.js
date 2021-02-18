/**
 * Module dependencies.
 */
var util = require('util')
  , OAuth2Strategy = require('passport-oauth').OAuth2Strategy
  , InternalOAuthError = require('passport-oauth').InternalOAuthError
  , request = require('request')
  , jwt = require('jsonwebtoken');

/**
 * `Strategy` constructor.
 *
 * The FIWARE authentication strategy authenticates requests by delegating to
 * FIWARE using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your FIWARE application's client id
 *   - `clientSecret`  your FIWARE application's client secret
 *   - `callbackURL`   URL to which FIWARE will redirect the user after granting authorization
 *   - `serverURL` URL of the FIWARE IdM to be used. If not provided the FIWARE Lab IdM is used
 *   - `isLegacy`      Whether the IDM version is lower than 7.0.0
 *
 * Examples:
 *
 *     passport.use(new FIWAREStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret',
 *         callbackURL: 'https://www.example.net/auth/fiware/callback',
 *         isLegacy: false
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};

  this.serverURL = options.serverURL || 'https://account.lab.fiware.org';

  if (this.serverURL.endsWith('/')) {
    this.serverURL = this.serverURL.slice(0, -1);
  }

  options.authorizationURL = this.serverURL + '/oauth2/authorize';
  options.tokenURL = this.serverURL + '/oauth2/token';

  this.key = options.key;

  // Authorization: Basic BASE64(CLIENT_ID:CLIENT_SECRET)
  var authorizationHeader = 'Basic ' + new Buffer(options.clientID + ':' + options.clientSecret).toString('base64')

  options.customHeaders = {
    'Authorization': authorizationHeader
  }

  OAuth2Strategy.call(this, options, verify);
  this.name = 'fiware';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


function buildProfile(body, done) {
    let profile = { provider: 'fiware' };
    let json = JSON.parse(body);

    profile.id = json.id;
    profile.displayName = json.displayName;
    profile.emails = [
      {
        value: json.email
      }
    ];
    profile.email = json.email;
    profile.roles = json.roles;
    profile.organizations = json.organizations;
    profile.appId = json.app_id;

    // The entire profile
    profile._raw = body;
    profile._json = json;

    done(null, profile);
}

function getUserProfile(serverUrl, accessToken, done) {
  let url = serverUrl + '/user?access_token=' + accessToken
  let reqHandler = (err, body, res) => {
    if (err) {
      return done(new InternalOAuthError('failed to fetch user profile', err));
    }

    try {
      buildProfile(body, done);
    } catch(e) {
      done(e);
    }
  }

  request({url: url, method: 'GET'}, (err, res, body) => {
    reqHandler(err, body, res)
  });
}

/**
 * Retrieve user profile from FIWARE.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `fiware`
 *   - `id`
 *   - `username`
 *   - `displayName`
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  if (this.key != null && this.key.length > 0) {
    // JWT
    try {
      let decoded = jwt.verify(accessToken, this.key);

      let profile = { provider: 'fiware' };
      profile.id = decoded.id;
      profile.displayName = decoded.displayName;
      profile.emails = [
        {
          value: decoded.email
        }
      ];
      profile.email = decoded.email;
      profile.appId = decoded.app_id;

      profile.roles = decoded.roles;
      profile.organizations = decoded.organizations;

      // The entire profile
      profile._raw = JSON.stringify(decoded);
      profile._json = decoded;
      done(null, profile);
    } catch (e) {
      done(e);
    }
  } else {
    getUserProfile(this.serverURL, accessToken, done);
  }
}


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
