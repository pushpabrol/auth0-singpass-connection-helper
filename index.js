var Webtask = require('webtask-tools');
const express = require('express');
const relyingPartyJWKS = require('./spkis/relyingPartyJWKS.json');
const intermediaryJWKS = require('./spkis/intermediaryJWKS.json');
const { JWK, JWE } = require('node-jose');
const { SignJWT, importJWK, importPKCS8, jwtVerify, createRemoteJWKSet } = require('jose'); 
const axios = require('axios');
const uuid = require('uuid');
const qs = require('querystring');
const dotenv = require('dotenv');
const metadata = require('./webtask.json');
const cors = require('cors');


dotenv.config();

const app = express(); // Create an Express application

// Middleware to parse JSON request bodies
app.use(express.json());

// Middleware to parse URL-encoded request bodies
app.use(express.urlencoded({ extended: true }));

app.options('*', cors())

app.use('/.extensions', require('./hooks'));

// Create a route for /.well-known/keys
// Used by the relying party of IDP to provide an ES256 public key for client authentication
app.get('/.well-known/keys', async (req, res) => {
  res.json(relyingPartyJWKS);
});

// This route returns the RS256 public key, used as the JWKS URL by auth0 to verify RS256 tokens
app.get('/jwks', async (req, res) => {
  res.json(intermediaryJWKS);
});

app.get('/meta', async (req, res) => {
  res.status(200).send(metadata)
});

app.get('/', async (req, res) => {
   
  res.json({
    "token": {
        "url" : `${req.webtaskContext.data.PUBLIC_WT_URL}/token`,
        "use" :  "Endpoint used by the Auth0 connection as a token wrapper"
    } ,

    "jwks" : { 
        "url" : `${req.webtaskContext.data.PUBLIC_WT_URL}/jwks`,
        "use" : "Since this wrapper issues its own token for auth0 after verifying with the IDP, this JSON Web Keys(jwks) is used by the connection."
    },
 "keys" : {
    "url": `${req.webtaskContext.data.PUBLIC_WT_URL}/.well-known/keys`,
    "use" : "JSON Web keys(JWKS) used by the IDP for client assertion validation & JWE. Key with alg: ES256 is used for client assertion validation & Key with alg: ECDH-ES+A128KW is used for token encryption"
 }
});
});

// Start the Express server and listen on the specified port
module.exports = Webtask.fromExpress(app);

// Start the Express server and listen on the specified port
app.post('/token', async (req, res) => {
    const context = req.webtaskContext ? req.webtaskContext.data : process.env;
    console.log(req.body);
  
    // Retrieve parameters from the request body
    const { client_id, code, code_verifier, redirect_uri } = req.body;
  
    // Check if the client_id is missing
    if (!client_id) {
      return res.status(400).send('Missing client_id');
    }
  
    // Check if the provided client_id matches the expected one
    if (context.IDP_CLIENT_ID === client_id) {
      try {
        // Generate a client_assertion (JWT) for client authentication
        const client_assertion = await generatePrivateKeyJWTForClientAssertion(context);
        console.log(client_assertion);
  
        // Prepare the request to exchange the authorization code for tokens
        const options = {
          method: 'POST',
          url: `https://${context.IDP_DOMAIN}${context.IDP_TOKEN_PATH}`,
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          data: qs.stringify({
            grant_type: 'authorization_code',
            client_id: context.IDP_CLIENT_ID,
            client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            client_assertion,
            code,
            code_verifier,
            redirect_uri,
          }),
        };
  
        // Send the token request to the authorization server
        const response = await axios.request(options);
        console.log(response.data);
  
        // Extract the id_token from the response
        const { id_token } = response.data;
  
        // Extract the id_token from the response
        const decryted_id_token = await decryptJWE(id_token, context);
  
        const publicKeyIDP = createRemoteJWKSet(new URL(`https://${context.IDP_DOMAIN}${context.IDP_JWKS_PATH}`))
  
        // Verify the id_token with the public key
        const { payload, protectedHeader } = await jwtVerify(decryted_id_token, publicKeyIDP, {
          issuer: `https://${context.IDP_DOMAIN}`,
          audience: context.IDP_CLIENT_ID,
        });
  
        console.log(payload);
        console.log(protectedHeader);
        // Remove the nonce from the payload and replace the id_token with a new RS256 token
        //if (payload.nonce) delete payload.nonce;
        if (context.REMOVE_NONCE === "Y" && payload.nonce) delete payload.nonce;

        response.data.payload = payload;
        delete response.data.id_token;
  
        // Generate an RS256 token from the payload for auth0
        const jwt = await generateRS256Token(payload, context);
        response.data.id_token = jwt;
  
        // Send the response with the updated id_token
        return res.status(200).send(response.data);
  
      } catch (error) {
        if (error.response) {
          // Handle errors with HTTP responses
          return res.status(error.response.status).send(error.response.data);
        } else {
          console.error('Error:', error.message);
          return res.status(500).send(error.message);
        }
      }
    } else {
      // Return an error response for invalid client_id
      return res.status(401).send('Invalid request, client_id is incorrect!');
    }
  });
  
  
  // Function to load the private key for client_assertion - ES256
  async function loadPrivateKeyForClientAssertion(context) {
    try {
  
      var jsonData = relyingPartyJWKS.keys.find(spki => spki.use === "sig");
      jsonData.d = context.RELYING_PARTY_PRIVATE_KEY_SIGNING;
      return await importJWK(jsonData, context.RELYING_PARTY_CLIENT_ASSERTION_SIGNING_ALG);
    } catch (e) {
      return e;
    }
  }
  
  // Function to load the RS256 private key
  async function loadRS256PrivateKey(context) {
    try {
      const privateKeyFromSecrets = context.INTERMEDIARY_PRIVATE_KEY.replace(/\\n/gm, '\n');
      console.log("from secrets:", privateKeyFromSecrets);
      var key = await importPKCS8(privateKeyFromSecrets, context.INTERMEDIARY_SIGNING_ALG);
      //console.log("Loaded private key from hard coding:, ", privateKey);
      return key;
    } catch (e) {
      console.log(e);
      return e;
    }
  }
  
  
  
  // Function to generate a client_assertion (JWT) for client authentication
  async function generatePrivateKeyJWTForClientAssertion(context) {
    try {
      const key = await loadPrivateKeyForClientAssertion(context);
      console.log(key);
      const jwt = await new SignJWT({})
        .setProtectedHeader({ alg: context.RELYING_PARTY_CLIENT_ASSERTION_SIGNING_ALG, kid: context.RELYING_PARTY_KID, typ: "JWT" })
        .setIssuedAt()
        .setIssuer(context.IDP_CLIENT_ID)
        .setSubject(context.IDP_CLIENT_ID)
        .setAudience([`https://${context.IDP_DOMAIN}`, `https://${context.IDP_DOMAIN}/token`])
        .setExpirationTime('2m') // Expiration time
        .setJti(uuid.v4())
        .sign(key);
      console.log(jwt);
      return jwt;
    } catch (error) {
      console.log(error);
      return error;
    }
  }
  
  // Function to generate an RS256 token by the intermediary
  async function generateRS256Token(payload, context) {
    if (payload.nonce) delete payload.nonce;
    try {
      const key = await loadRS256PrivateKey(context);
      console.log(key);

      const jwt = await new SignJWT(payload)
        .setProtectedHeader({ alg: context.INTERMEDIARY_SIGNING_ALG, kid: context.INTERMEDIARY_KEY_KID, typ: "JWT" })
        .setIssuedAt()
        .setIssuer(`https://${context.IDP_DOMAIN}`)
        .setAudience(context.IDP_CLIENT_ID)
        .setExpirationTime('2m') // Expiration time
        .setJti(uuid.v4())
        .sign(key);
      console.log(jwt);
      return jwt;
    } catch (error) {
      console.log(error);
      return error;
    }
  }
  
  async function decryptJWE(jwe, context) {
  
    var jsonData = relyingPartyJWKS.keys.find(spki => spki.use === "enc" && spki.alg === context.RELYING_PARTY_PRIVATE_KEY_ENC_ALG);
    if (jsonData) {
      jsonData.d = context.RELYING_PARTY_PRIVATE_KEY_ENC;
      try {
  
        const decryptor = JWE.createDecrypt(await JWK.asKey(jsonData, "json"));
        const decryptedData = await decryptor.decrypt(jwe);
        const idToken = decryptedData.plaintext.toString('utf8');
        console.log(idToken);
        return idToken;
      }
  
      catch (e) {
        console.log(e);
        throw e;
      }
    } else {
      console.log("Either not encrypted or the right key is not available!, returning token as is!")
      return jwe;
    }
  
  }
  