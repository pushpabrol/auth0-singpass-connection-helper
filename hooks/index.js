var express  = require('express');
var hooks    = express.Router();

module.exports = hooks;

function validateJwt (path) {
  return function (req, res, next) {
      return next();
  }
}

// Validate JWT for on-install
hooks.use('/on-install', validateJwt('/.extensions/on-install'));
hooks.use('/on-uninstall', validateJwt('/.extensions/on-uninstall'));
hooks.use('/on-update',    validateJwt('/.extensions/on-update'));


// This endpoint would be called by webtask-gallery
hooks.post('/on-install', function (req, res) {
    res.sendStatus(204);
});

// This endpoint would be called by webtask-gallery
hooks.put('/on-update', function (req, res) {
  res.sendStatus(204);
});

// This endpoint would be called by webtask-gallery
hooks.delete('/on-uninstall', function (req, res) {
    res.sendStatus(204);
});

