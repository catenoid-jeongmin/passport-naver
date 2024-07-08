/**
 * Module dependencies.
 */
const util = require("util"),
  OAuth2Strategy = require("passport-oauth").OAuth2Strategy,
  InternalOAuthError = require("passport-oauth").InternalOAuthError,
  NaverAPIError = require("./errors/naverapierror");
/**
 * `Strategy` constructor
 */
function Strategy(options, verify) {
  options = options || {};

  options.authorizationURL =
    options.authorizationURL || "https://nid.naver.com/oauth2.0/authorize";
  options.tokenURL = options.tokenURL || "https://nid.naver.com/oauth2.0/token";

  this.__options = options;

  OAuth2Strategy.call(this, options, verify);
  this.name = "naver";

  this._profileURL =
    options.profileURL || "https://openapi.naver.com/v1/nid/me";
  this._oauth2.setAccessTokenName("access_token");
}
/**
 * Inherit from `OAuthStrategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

/**
 * Return extra parameters to be included in the authorization request.
 */
Strategy.prototype.authorizationParams = function (options) {
  // Do not modify `options` object.
  // It will hurts original options object which in `passport.authenticate(..., options)`
  const params = Object.assign({}, options);
  params["response_type"] = "code";

  // @see https://github.com/naver/passport-naver#re-authentication
  if (this.__options.authType !== undefined)
    params["auth_type"] = this.__options.authType;

  return params;
};

/**
 * Retrieve user profile from Naver.
 */
Strategy.prototype.userProfile = function (accessToken, done) {
  // Need to use 'Authorization' header to save the access token information
  // If this header is not specified, the access token is passed in GET method.
  this._oauth2.useAuthorizationHeaderforGET(true);
  // User profile API
  this._oauth2.get(this._profileURL, accessToken, function (err, body, res) {
    // @note Naver API will response with status code 200 even API request was rejected.
    // Thus, below line will not executed until Naver API changes.
    if (err) {
      return done(new InternalOAuthError("Failed to fetch user profile", err));
    }

    // parse the user profile API Response to JSON object
    let json = null;
    try {
      json = JSON.parse(body);
    } catch (err) {
      return done(new InternalOAuthError("Failed to parse API response", err));
    }
    const resultcode = json.resultcode;
    const resultmessage = json.message;
    const resultbody = json.response;

    // API Response was parsed successfully, but there are no informative data.
    // e.g. API Server was respond with empty response
    if (!(resultcode && resultmessage)) {
      return done(new InternalOAuthError("Empty API Response"));
    }

    // Naver API Server was respond with unsuccessful result code.
    // See detail response code to https://developers.naver.com/docs/login/profile
    if (resultcode != "00") {
      return done(new NaverAPIError(resultmessage, resultcode));
    }

    const profile = {
      provider: "naver",
      id: resultbody.id,
      nickname: resultbody.nickname,
      name: resultbody.name,
      email: resultbody.email,
      gender: resultbody.gender,
      age: resultbody.age,
      birthday: resultbody.birthday,
      profile_image: resultbody.profile_image,
      birthyear: resultbody.birthyear,
      mobile: resultbody.mobile,
      mobile_e164: resultbody.mobile_e164,
      _raw: body,
      _json: json,
    };

    done(null, profile);
  });
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
