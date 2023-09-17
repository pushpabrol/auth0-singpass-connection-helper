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
        "use" : "Since this wrapper issues its own token for auth0 after verifying with the IDP, this endpoint allows for token signature verification public key that is used as the jwks url"
    },
 "keys" : {
    "url": `${req.webtaskContext.data.PUBLIC_WT_URL}/.well-known/keys`,
    "use" : "Used by the IDP for client assertion validation & JWE. Key with alg: ES256 is used for client assertion validation & Key with alg: ECDH-ES+A128KW is used for token encryption"
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
          url: `https://${context.IDP_DOMAIN}/token`,
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
  
        const publicKeyIDP = createRemoteJWKSet(new URL(`https://${context.IDP_DOMAIN}/jwks`))
  
        // Verify the id_token with the public key
        const { payload, protectedHeader } = await jwtVerify(decryted_id_token, publicKeyIDP, {
          issuer: `https://${context.IDP_DOMAIN}`,
          audience: context.IDP_CLIENT_ID,
        });
  
        console.log(payload);
        console.log(protectedHeader);
        // Remove the nonce from the payload and replace the id_token with a new RS256 token
        if (payload.nonce) delete payload.nonce;
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
      //var privateKey = "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC/s+Jg6d1vXEjS\n8Vpe1DslbrqWtFt4WuPSEUvfNgQyCxyMGDkp8bYS3BqTxbjUBDPZ5YA6EO1fjZrx\nNvsPnXG4SkUcGgSo6gsHU2xTknW/W7EUZQZPSD+8xM3sxTEFTN2CGIjVrdO6BmxO\ndANdPhHSaxBTWEKLvJeg8RMH4BBv/SuJ8FgreSDB4ZnmEU6+S7L59mKEkas0SgC3\nf/Xt0SLy4CiqIAA3hc+nPgyZiLME2NjTKQUrCj5JZ254d7oWfAmR5Zg3M80WMG9q\nIc/tJjI+w9ypX9zdLWNQez156rnUaIpG6jMtFTaS0M/3j/5+irB9jRqKTbEqRhw3\nsrj8yzg3AgMBAAECggEAK3kRp0ShsLVO1ndhNQwP9acsrSxtadfCvkqp2A6Z2Pdo\nG+UKYZas4Y4EgOpfxcTGNW20LHbWPcsRDg6X1Kyxs0c0cPD9iYi5w4mJkVIvXZvf\nhm56hdQukBJZWI5HVZpeyTfjIAHxd8gpG4l3kdeXlw4sf5oOTT4RbK/+ztRjJeHx\nUxqnzYgXGUWY0wM9rRsJzj3vL/zi4L3Xx47GFQGgbVAnBO+wg7wwDEKgiVEStP9P\nTbXUX8wuIX8t9DVRlMOcPjksDBULepKjeK3ljkORAEuIzjeSYYxwvSQmGIdotwcE\n9+KXL/nlGo4hMhEULGSzWHtCFeLvHvWQKP91brMl4QKBgQDiraU1ZbJPyTmNHz6q\nPmYo0Oi+956yNAKVaAwDPwqN2d13PRzW4sMb0P54ZFXdxo0Jo1w7k2nGr1QUcjPF\nUdaNm7PzeA5w5m5yv5LfPGdePSv8h1ZlspST/b02QVDpKGKHTzym/d10V4cr2NYB\nVOgAODqRatP2utBlbTGS4rB2eQKBgQDYgAk3gicPO+QyzJv+GUqZ4dCIrkLh5DCJ\nBE6t0gX7DehVN9fmv6XNbP27EZVt5CyF9loRDHArTNDEy+J/+vQ4X4S7om4Xmkan\ne4KaWvHlZ++RJIubu7jGVsH3+36cyEb8IXlEnxf6GijiF7p3ktTjGVp739QKHuc+\nK8OhZZM4LwKBgAHDlCuMNQ0F5drBSX2NqsHajlUeHDAK05JSEvXbgbuE3IJXCWhq\nr1YCFFjffwOQzfwrN0aHaSVQq/jUwq5gaqkDcy0L3CDoyic+cmgmUi+bjkIS04tL\nDnjwWo6Xh4eo9stSxIgQJa8IF1cyAshT3tJRnbMP/8JFxeVkKiSYewMRAoGADy+j\n9d3OSZZE4n9RrdguUG7zhrLahCfSc7n2nuCthLesBVY+cbQduDQd9CI+ng+0Q81M\n8gcyUwc3WaaHg7yhptakY9j36fXrYNIcDiG0+Ad7WW370Pew9VCemHtunSa7O/JJ\nJFQYhXWSSpGphbup7SgZHblMkU0roUPGnCqY0gcCgYAu3PBaK22IMQwKpbVY5yHg\nz0mfNx8uMLPaUEVOUaiIXoLGc4RB48p+ZNnvArstWLmeFIeH48CQ2sGE0y3gAQZQ\nnQMH3YUwicCeSdqv8YIrrssLtsyjklEuBWQY1d4MOlbJYS+BeK2phjOPB8tQPkwV\niiCJHk5cUt1Nr+Z/ISmz/Q==\n-----END PRIVATE KEY-----\n".replace(/\n/g, "\r\n");
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
        .setAudience([`https://${context.IDP_DOMAIN}/`, `https://${context.IDP_DOMAIN}/token`])
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
      //const key = "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC/s+Jg6d1vXEjS\n8Vpe1DslbrqWtFt4WuPSEUvfNgQyCxyMGDkp8bYS3BqTxbjUBDPZ5YA6EO1fjZrx\nNvsPnXG4SkUcGgSo6gsHU2xTknW/W7EUZQZPSD+8xM3sxTEFTN2CGIjVrdO6BmxO\ndANdPhHSaxBTWEKLvJeg8RMH4BBv/SuJ8FgreSDB4ZnmEU6+S7L59mKEkas0SgC3\nf/Xt0SLy4CiqIAA3hc+nPgyZiLME2NjTKQUrCj5JZ254d7oWfAmR5Zg3M80WMG9q\nIc/tJjI+w9ypX9zdLWNQez156rnUaIpG6jMtFTaS0M/3j/5+irB9jRqKTbEqRhw3\nsrj8yzg3AgMBAAECggEAK3kRp0ShsLVO1ndhNQwP9acsrSxtadfCvkqp2A6Z2Pdo\nG+UKYZas4Y4EgOpfxcTGNW20LHbWPcsRDg6X1Kyxs0c0cPD9iYi5w4mJkVIvXZvf\nhm56hdQukBJZWI5HVZpeyTfjIAHxd8gpG4l3kdeXlw4sf5oOTT4RbK/+ztRjJeHx\nUxqnzYgXGUWY0wM9rRsJzj3vL/zi4L3Xx47GFQGgbVAnBO+wg7wwDEKgiVEStP9P\nTbXUX8wuIX8t9DVRlMOcPjksDBULepKjeK3ljkORAEuIzjeSYYxwvSQmGIdotwcE\n9+KXL/nlGo4hMhEULGSzWHtCFeLvHvWQKP91brMl4QKBgQDiraU1ZbJPyTmNHz6q\nPmYo0Oi+956yNAKVaAwDPwqN2d13PRzW4sMb0P54ZFXdxo0Jo1w7k2nGr1QUcjPF\nUdaNm7PzeA5w5m5yv5LfPGdePSv8h1ZlspST/b02QVDpKGKHTzym/d10V4cr2NYB\nVOgAODqRatP2utBlbTGS4rB2eQKBgQDYgAk3gicPO+QyzJv+GUqZ4dCIrkLh5DCJ\nBE6t0gX7DehVN9fmv6XNbP27EZVt5CyF9loRDHArTNDEy+J/+vQ4X4S7om4Xmkan\ne4KaWvHlZ++RJIubu7jGVsH3+36cyEb8IXlEnxf6GijiF7p3ktTjGVp739QKHuc+\nK8OhZZM4LwKBgAHDlCuMNQ0F5drBSX2NqsHajlUeHDAK05JSEvXbgbuE3IJXCWhq\nr1YCFFjffwOQzfwrN0aHaSVQq/jUwq5gaqkDcy0L3CDoyic+cmgmUi+bjkIS04tL\nDnjwWo6Xh4eo9stSxIgQJa8IF1cyAshT3tJRnbMP/8JFxeVkKiSYewMRAoGADy+j\n9d3OSZZE4n9RrdguUG7zhrLahCfSc7n2nuCthLesBVY+cbQduDQd9CI+ng+0Q81M\n8gcyUwc3WaaHg7yhptakY9j36fXrYNIcDiG0+Ad7WW370Pew9VCemHtunSa7O/JJ\nJFQYhXWSSpGphbup7SgZHblMkU0roUPGnCqY0gcCgYAu3PBaK22IMQwKpbVY5yHg\nz0mfNx8uMLPaUEVOUaiIXoLGc4RB48p+ZNnvArstWLmeFIeH48CQ2sGE0y3gAQZQ\nnQMH3YUwicCeSdqv8YIrrssLtsyjklEuBWQY1d4MOlbJYS+BeK2phjOPB8tQPkwV\niiCJHk5cUt1Nr+Z/ISmz/Q==\n-----END PRIVATE KEY-----\n".replace(/\n/g, "\r\n");
    //   var key = await importJWK({
    //     "kty": "RSA",
    //     "kid": "QVBKtPRpC9s2cynBuEI7DMjXwtinIkdMQ-ZMUX2BKZg",
    //     "n": "v7PiYOndb1xI0vFaXtQ7JW66lrRbeFrj0hFL3zYEMgscjBg5KfG2Etwak8W41AQz2eWAOhDtX42a8Tb7D51xuEpFHBoEqOoLB1NsU5J1v1uxFGUGT0g_vMTN7MUxBUzdghiI1a3TugZsTnQDXT4R0msQU1hCi7yXoPETB-AQb_0rifBYK3kgweGZ5hFOvkuy-fZihJGrNEoAt3_17dEi8uAoqiAAN4XPpz4MmYizBNjY0ykFKwo-SWdueHe6FnwJkeWYNzPNFjBvaiHP7SYyPsPcqV_c3S1jUHs9eeq51GiKRuozLRU2ktDP94_-foqwfY0aik2xKkYcN7K4_Ms4Nw",
    //     "e": "AQAB",
    //     "d": "K3kRp0ShsLVO1ndhNQwP9acsrSxtadfCvkqp2A6Z2PdoG-UKYZas4Y4EgOpfxcTGNW20LHbWPcsRDg6X1Kyxs0c0cPD9iYi5w4mJkVIvXZvfhm56hdQukBJZWI5HVZpeyTfjIAHxd8gpG4l3kdeXlw4sf5oOTT4RbK_-ztRjJeHxUxqnzYgXGUWY0wM9rRsJzj3vL_zi4L3Xx47GFQGgbVAnBO-wg7wwDEKgiVEStP9PTbXUX8wuIX8t9DVRlMOcPjksDBULepKjeK3ljkORAEuIzjeSYYxwvSQmGIdotwcE9-KXL_nlGo4hMhEULGSzWHtCFeLvHvWQKP91brMl4Q",
    //     "p": "4q2lNWWyT8k5jR8-qj5mKNDovveesjQClWgMAz8Kjdnddz0c1uLDG9D-eGRV3caNCaNcO5Npxq9UFHIzxVHWjZuz83gOcOZucr-S3zxnXj0r_IdWZbKUk_29NkFQ6Shih088pv3ddFeHK9jWAVToADg6kWrT9rrQZW0xkuKwdnk",
    //     "q": "2IAJN4InDzvkMsyb_hlKmeHQiK5C4eQwiQROrdIF-w3oVTfX5r-lzWz9uxGVbeQshfZaEQxwK0zQxMvif_r0OF-Eu6JuF5pGp3uCmlrx5WfvkSSLm7u4xlbB9_t-nMhG_CF5RJ8X-hoo4he6d5LU4xlae9_UCh7nPivDoWWTOC8",
    //     "dp": "AcOUK4w1DQXl2sFJfY2qwdqOVR4cMArTklIS9duBu4TcglcJaGqvVgIUWN9_A5DN_Cs3RodpJVCr-NTCrmBqqQNzLQvcIOjKJz5yaCZSL5uOQhLTi0sOePBajpeHh6j2y1LEiBAlrwgXVzICyFPe0lGdsw__wkXF5WQqJJh7AxE",
    //     "dq": "Dy-j9d3OSZZE4n9RrdguUG7zhrLahCfSc7n2nuCthLesBVY-cbQduDQd9CI-ng-0Q81M8gcyUwc3WaaHg7yhptakY9j36fXrYNIcDiG0-Ad7WW370Pew9VCemHtunSa7O_JJJFQYhXWSSpGphbup7SgZHblMkU0roUPGnCqY0gc",
    //     "qi": "LtzwWittiDEMCqW1WOch4M9JnzcfLjCz2lBFTlGoiF6CxnOEQePKfmTZ7wK7LVi5nhSHh-PAkNrBhNMt4AEGUJ0DB92FMInAnknar_GCK67LC7bMo5JRLgVkGNXeDDpWyWEvgXitqYYzjwfLUD5MFYogiR5OXFLdTa_mfyEps_0"
    // },"RS256");
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
  