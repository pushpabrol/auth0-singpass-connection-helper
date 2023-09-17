var express = require('express');
var Request = require('superagent');
var ManagementClient = require("auth0").ManagementClient;
var jwt = require('jsonwebtoken');
var hooks = express.Router();
module.exports = hooks;

function validateJwt(path) {
  return function(req, res, next) {
    console.log('jwt')
    if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
      var token = req.headers.authorization.split(' ')[1];
      var isValid = jwt.verify(token, req.webtaskContext.data.EXTENSION_SECRET, {
        audience: `${req.webtaskContext.data.WT_URL}${path}`,
        issuer: 'https://' + req.webtaskContext.data.AUTH0_DOMAIN
      });

      if (!isValid) {
        return res.sendStatus(401);
      }

      return next();
    }

    return res.sendStatus(401);
  }
}


// Validate JWT for on-install
hooks.use('/on-install', validateJwt('/.extensions/on-install'));
hooks.use('/on-uninstall', validateJwt('/.extensions/on-uninstall'));
hooks.use('/on-update', validateJwt('/.extensions/on-update'));

// Getting Auth0 APIV2 access_token
hooks.use(function(req, res, next) {
  console.log('here');

  getToken(req, function(access_token, err) {
    if (err) return next(err);

    var management = new ManagementClient({
      domain: req.webtaskContext.data.AUTH0_DOMAIN,
      token: access_token
    });

    req.auth0 = management;

    next();
  });
});

// This endpoint would be called by webtask-gallery
hooks.post('/on-install', async function(req, res) {
    await updateConnectionTokenEndpoint(req);
    res.sendStatus(204);

});

// This endpoint would be called by webtask-gallery
hooks.put('/on-update', function(req, res) {
  res.sendStatus(204);
});

// This endpoint would be called by webtask-gallery
hooks.delete('/on-uninstall', function(req, res) {
    res.sendStatus(204);
});

function getToken(req, cb) {
  var apiUrl = 'https://' + req.webtaskContext.data.AUTH0_DOMAIN + '/oauth/token';
  var audience = 'https://' + req.webtaskContext.data.AUTH0_DOMAIN + '/api/v2/';
  var clientId = req.webtaskContext.data.AUTH0_CLIENT_ID;
  var clientSecret = req.webtaskContext.data.AUTH0_CLIENT_SECRET;

  Request
    .post(apiUrl)
    .send({
      audience: audience,
      grant_type: 'client_credentials',
      client_id: clientId,
      client_secret: clientSecret
    })
    .type('application/json')
    .end(function(err, res) {
      if (err || !res.ok) {
        cb(null, err);
      } else {
        cb(res.body.access_token);
      }
    });
}

async function updateConnectionTokenEndpoint(req){
    try {
    var connection = await req.auth0.getConnections({ name : req.webtaskContext.data.AUTH0_CONNECTION_NAME });
    console.log(connection.id);
    var options = connection.options;
    if(options) options.token_endpoint = req.webtaskContext.data.PUBLIC_WT_URL + "/token";
    if(options && options.oidc_metadata) options.oidc_metadata.token_endpoint = req.webtaskContext.data.PUBLIC_WT_URL + "/token";
    connection = await req.auth0.updateConnection({ id: connection.id }, { options: options });
    console.log("Updated connection!");
    }
    catch(e){
        console.log(e);
    }

}
