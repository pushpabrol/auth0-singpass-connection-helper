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
    await updateConnectionTokenEndpoint(req,"install");
    res.sendStatus(204);

});

// This endpoint would be called by webtask-gallery
hooks.put('/on-update', function(req, res) {
  res.sendStatus(204);
});

// This endpoint would be called by webtask-gallery
hooks.delete('/on-uninstall', async function(req, res) {
    await updateConnectionTokenEndpoint(req,"uninstall");
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

async function updateConnectionTokenEndpoint(req, action){
    try {
        console.log(req.webtaskContext.data);
        console.log(req.webtaskContext.secrets);

    var connections = await req.auth0.getConnections({ name : req.webtaskContext.data.AUTH0_CONNECTION_NAME });
    if(connections.length === 1){
    const connection = connections[0];
    if(action === "install") {    
    console.log(connection.id);
    var options = connection.options;
    if(options)  { 
        options.token_endpoint = req.webtaskContext.data.PUBLIC_WT_URL + "/token";
        options.jwks_uri = req.webtaskContext.data.PUBLIC_WT_URL + "/jwks";
    }
    if(options && options.oidc_metadata) {
         options.oidc_metadata.token_endpoint = req.webtaskContext.data.PUBLIC_WT_URL + "/token";
         options.oidc_metadata.jwks_uri = req.webtaskContext.data.PUBLIC_WT_URL + "/jwks";
    }
    }
    if(action === "uninstall"){
        console.log(connection.id);
        var options = connection.options;
        if(options)  { 
            options.token_endpoint = "https://" + req.webtaskContext.data.IDP_DOMAIN + "/token";
            options.jwks_uri = "https://" + req.webtaskContext.data.IDP_DOMAIN + "/jwks";
        }
        if(options && options.oidc_metadata) {
             options.oidc_metadata.token_endpoint = req.webtaskContext.data.IDP_DOMAIN + "/token";
             options.oidc_metadata.jwks_uri = req.webtaskContext.data.IDP_DOMAIN + "/jwks";
        }
      
    }
    connection = await req.auth0.updateConnection({ id: connection.id }, { options: options });
    console.log("Updated connection!: " + action);
    }
    else console.log("Connection with that name not found. Skipping connection updates!");
    }
    catch(e){
        console.log(e);
    }

}
