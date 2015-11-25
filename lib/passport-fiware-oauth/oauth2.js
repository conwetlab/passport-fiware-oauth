/**
 * Module dependencies.
 */
var util = require('util')
  , OAuth2Strategy = require('passport-oauth').OAuth2Strategy
  , InternalOAuthError = require('passport-oauth').InternalOAuthError;

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
 *
 * Examples:
 *
 *     passport.use(new FIWAREStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/fiware/callback'
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
  options.authorizationURL = options.authorizationURL || 'https://account.lab.fiware.org/oauth2/authorize';
  options.tokenURL = options.tokenURL || 'https://account.lab.fiware.org/oauth2/token';

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
  this._oauth2.get('https://account.lab.fiware.org/user?access_token=' + accessToken, accessToken, function (err, body, res) {
    if (err) { 
      return done(new InternalOAuthError('failed to fetch user profile', err)); 
    }

    try {
      var json = JSON.parse(body)
        , i, len;

      var profile = { provider: 'fiware' };
      profile.id = json.id;
      profile.displayName = json.displayName;
      profile.email = json.email;
      profile.roles = json.roles;
      profile.organizations = json.organizations;
      profile.appId = json.app_id;

      // The entire profile
      profile._raw = body;
      profile._json = json;

      done(null, profile);
    } catch(e) {
      done(e);
    }
  });
}


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
