"use strict";
module.exports=function(e){var t={};function n(o){if(t[o])return t[o].exports;var s=t[o]={i:o,l:!1,exports:{}};return e[o].call(s.exports,s,s.exports,n),s.l=!0,s.exports}return n.m=e,n.c=t,n.d=function(e,t,o){n.o(e,t)||Object.defineProperty(e,t,{enumerable:!0,get:o})},n.r=function(e){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})},n.t=function(e,t){if(1&t&&(e=n(e)),8&t)return e;if(4&t&&"object"==typeof e&&e&&e.__esModule)return e;var o=Object.create(null);if(n.r(o),Object.defineProperty(o,"default",{enumerable:!0,value:e}),2&t&&"string"!=typeof e)for(var s in e)n.d(o,s,function(t){return e[t]}.bind(null,s));return o},n.n=function(e){var t=e&&e.__esModule?function(){return e.default}:function(){return e};return n.d(t,"a",t),t},n.o=function(e,t){return Object.prototype.hasOwnProperty.call(e,t)},n.p="",n(n.s=0)}([function(e,t,n){var o=n(1);const s=n(2),r=n(3),i=n(4),{JWK:a,JWE:u}=n(5),{SignJWT:c,importJWK:l,importPKCS8:d,jwtVerify:p,createRemoteJWKSet:I}=n(6),E=n(7),_=n(8),g=n(9),A=n(10),N=n(11),f=n(12);A.config();const y=s();y.use(s.json()),y.use(s.urlencoded({extended:!0})),y.use("/.extensions",n(13)),y.get("/.well-known/keys",async(e,t)=>{t.json(r)}),y.get("/jwks",async(e,t)=>{t.json(i)}),y.get("/meta",f(),async(e,t)=>{t.status(200).send(N)}),e.exports=o.fromExpress(y),y.post("/token",async(e,t)=>{const n=e.webtaskContext?e.webtaskContext.data:Object({NODE_ENV:"production",CLIENT_VERSION:"1.2.0"});console.log(e.body);const{client_id:o,code:s,code_verifier:i,redirect_uri:A}=e.body;if(!o)return t.status(400).send("Missing client_id");if(n.IDP_CLIENT_ID!==o)return t.status(401).send("Invalid request, client_id is incorrect!");try{const e=await async function(e){try{const t=await async function(e){try{var t=r.keys.find(e=>"sig"===e.use);return t.d=e.RELYING_PARTY_PRIVATE_KEY_SIGNING,await l(t,e.RELYING_PARTY_CLIENT_ASSERTION_SIGNING_ALG)}catch(e){return e}}(e);console.log(t);const n=await new c({}).setProtectedHeader({alg:e.RELYING_PARTY_CLIENT_ASSERTION_SIGNING_ALG,kid:e.RELYING_PARTY_KID,typ:"JWT"}).setIssuedAt().setIssuer(e.IDP_CLIENT_ID).setSubject(e.IDP_CLIENT_ID).setAudience([`https://${e.IDP_DOMAIN}/`,`https://${e.IDP_DOMAIN}/token`]).setExpirationTime("2m").setJti(_.v4()).sign(t);return console.log(n),n}catch(e){return console.log(e),e}}(n);console.log(e);const o={method:"POST",url:`https://${n.IDP_DOMAIN}/token`,headers:{"content-type":"application/x-www-form-urlencoded"},data:g.stringify({grant_type:"authorization_code",client_id:n.IDP_CLIENT_ID,client_assertion_type:"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",client_assertion:e,code:s,code_verifier:i,redirect_uri:A})},N=await E.request(o);console.log(N.data);const{id_token:f}=N.data,y=await async function(e,t){var n=r.keys.find(e=>"enc"===e.use&&e.alg===t.RELYING_PARTY_PRIVATE_KEY_ENC_ALG);if(!n)return console.log("Either not encrypted or the right key is not available!, returning token as is!"),e;n.d=t.RELYING_PARTY_PRIVATE_KEY_ENC;try{const t=u.createDecrypt(await a.asKey(n,"json")),o=await t.decrypt(e),s=o.plaintext.toString("utf8");return console.log(s),s}catch(e){throw console.log(e),e}}(f,n),P=I(new URL(`https://${n.IDP_DOMAIN}/jwks`)),{payload:T,protectedHeader:R}=await p(y,P,{issuer:`https://${n.IDP_DOMAIN}`,audience:n.IDP_CLIENT_ID});console.log(T),console.log(R),T.nonce&&delete T.nonce,N.data.payload=T,delete N.data.id_token;const S=await async function(e,t){e.nonce&&delete e.nonce;try{const n=await async function(e){try{const o=e.INTERMEDIARY_PRIVATE_KEY.replace(/\\n/gm,"\n");console.log("from secrets:",o);var t="-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC/s+Jg6d1vXEjS\n8Vpe1DslbrqWtFt4WuPSEUvfNgQyCxyMGDkp8bYS3BqTxbjUBDPZ5YA6EO1fjZrx\nNvsPnXG4SkUcGgSo6gsHU2xTknW/W7EUZQZPSD+8xM3sxTEFTN2CGIjVrdO6BmxO\ndANdPhHSaxBTWEKLvJeg8RMH4BBv/SuJ8FgreSDB4ZnmEU6+S7L59mKEkas0SgC3\nf/Xt0SLy4CiqIAA3hc+nPgyZiLME2NjTKQUrCj5JZ254d7oWfAmR5Zg3M80WMG9q\nIc/tJjI+w9ypX9zdLWNQez156rnUaIpG6jMtFTaS0M/3j/5+irB9jRqKTbEqRhw3\nsrj8yzg3AgMBAAECggEAK3kRp0ShsLVO1ndhNQwP9acsrSxtadfCvkqp2A6Z2Pdo\nG+UKYZas4Y4EgOpfxcTGNW20LHbWPcsRDg6X1Kyxs0c0cPD9iYi5w4mJkVIvXZvf\nhm56hdQukBJZWI5HVZpeyTfjIAHxd8gpG4l3kdeXlw4sf5oOTT4RbK/+ztRjJeHx\nUxqnzYgXGUWY0wM9rRsJzj3vL/zi4L3Xx47GFQGgbVAnBO+wg7wwDEKgiVEStP9P\nTbXUX8wuIX8t9DVRlMOcPjksDBULepKjeK3ljkORAEuIzjeSYYxwvSQmGIdotwcE\n9+KXL/nlGo4hMhEULGSzWHtCFeLvHvWQKP91brMl4QKBgQDiraU1ZbJPyTmNHz6q\nPmYo0Oi+956yNAKVaAwDPwqN2d13PRzW4sMb0P54ZFXdxo0Jo1w7k2nGr1QUcjPF\nUdaNm7PzeA5w5m5yv5LfPGdePSv8h1ZlspST/b02QVDpKGKHTzym/d10V4cr2NYB\nVOgAODqRatP2utBlbTGS4rB2eQKBgQDYgAk3gicPO+QyzJv+GUqZ4dCIrkLh5DCJ\nBE6t0gX7DehVN9fmv6XNbP27EZVt5CyF9loRDHArTNDEy+J/+vQ4X4S7om4Xmkan\ne4KaWvHlZ++RJIubu7jGVsH3+36cyEb8IXlEnxf6GijiF7p3ktTjGVp739QKHuc+\nK8OhZZM4LwKBgAHDlCuMNQ0F5drBSX2NqsHajlUeHDAK05JSEvXbgbuE3IJXCWhq\nr1YCFFjffwOQzfwrN0aHaSVQq/jUwq5gaqkDcy0L3CDoyic+cmgmUi+bjkIS04tL\nDnjwWo6Xh4eo9stSxIgQJa8IF1cyAshT3tJRnbMP/8JFxeVkKiSYewMRAoGADy+j\n9d3OSZZE4n9RrdguUG7zhrLahCfSc7n2nuCthLesBVY+cbQduDQd9CI+ng+0Q81M\n8gcyUwc3WaaHg7yhptakY9j36fXrYNIcDiG0+Ad7WW370Pew9VCemHtunSa7O/JJ\nJFQYhXWSSpGphbup7SgZHblMkU0roUPGnCqY0gcCgYAu3PBaK22IMQwKpbVY5yHg\nz0mfNx8uMLPaUEVOUaiIXoLGc4RB48p+ZNnvArstWLmeFIeH48CQ2sGE0y3gAQZQ\nnQMH3YUwicCeSdqv8YIrrssLtsyjklEuBWQY1d4MOlbJYS+BeK2phjOPB8tQPkwV\niiCJHk5cUt1Nr+Z/ISmz/Q==\n-----END PRIVATE KEY-----\n".replace(/\n/g,"\r\n"),n=await d(t,e.INTERMEDIARY_SIGNING_ALG);return console.log("Loaded private key from hard coding:, ",t),n}catch(e){return console.log(e),e}}(t);console.log(n);const o=await new c(e).setProtectedHeader({alg:t.INTERMEDIARY_SIGNING_ALG,kid:t.INTERMEDIARY_KEY_KID,typ:"JWT"}).setIssuedAt().setIssuer(`https://${t.IDP_DOMAIN}`).setAudience(t.IDP_CLIENT_ID).setExpirationTime("2m").setJti(_.v4()).sign(n);return console.log(o),o}catch(e){return console.log(e),e}}(T,n);return N.data.id_token=S,t.status(200).send(N.data)}catch(e){return e.response?t.status(e.response.status).send(e.response.data):(console.error("Error:",e.message),t.status(500).send(e.message))}})},function(e,t){e.exports=require("webtask-tools")},function(e,t){e.exports=require("express@4.17.1")},function(e){e.exports=JSON.parse('{"keys":[{"kty":"EC","kid":"Al93ssyWpZ2yOoLxbDohuTigc1i5XNt1PKMyvU8aVgY","use":"sig","crv":"P-256","x":"6-l6udWD4kVDnoa8xDYNf9GHJXQXTNPEU8qfkiFHCBE","y":"TTXy1kprqhMA7bRy9v14C741tkOXkU36OtOuTKx6X80"},{"kty":"EC","kid":"UAzl2k6tGnj0bJBh5AimmGVd68QDrNyc9UTADv6dcc8","use":"enc","alg":"ECDH-ES+A128KW","crv":"P-256","x":"VexWR3Lb2dmnzuZeSNzS58XtM6bFpJOr2QN-p_WKN48","y":"7x7Vywcy8qZqE3SIaP-K7FAgrCECKJ_xoxr-zc6Wi4Y"}]}')},function(e){e.exports=JSON.parse('{"keys":[{"kty":"RSA","use":"sig","kid":"QVBKtPRpC9s2cynBuEI7DMjXwtinIkdMQ-ZMUX2BKZg","n":"v7PiYOndb1xI0vFaXtQ7JW66lrRbeFrj0hFL3zYEMgscjBg5KfG2Etwak8W41AQz2eWAOhDtX42a8Tb7D51xuEpFHBoEqOoLB1NsU5J1v1uxFGUGT0g_vMTN7MUxBUzdghiI1a3TugZsTnQDXT4R0msQU1hCi7yXoPETB-AQb_0rifBYK3kgweGZ5hFOvkuy-fZihJGrNEoAt3_17dEi8uAoqiAAN4XPpz4MmYizBNjY0ykFKwo-SWdueHe6FnwJkeWYNzPNFjBvaiHP7SYyPsPcqV_c3S1jUHs9eeq51GiKRuozLRU2ktDP94_-foqwfY0aik2xKkYcN7K4_Ms4Nw","e":"AQAB"}]}')},function(e,t){e.exports=require("node-jose@2.0.0")},function(e,t){e.exports=require("jose@4.10.0")},function(e,t){e.exports=require("axios@0.27.2")},function(e,t){e.exports=require("uuid@8.3.1")},function(e,t){e.exports=require("querystring")},function(e,t){e.exports=require("dotenv@16.0.1")},function(e){e.exports=JSON.parse('{"title":"Auth0 Singpass Connection Helper","name":"auth0-singpass-connection-extension","version":"1.2.0","author":"Pushp Abrol","useHashName":false,"description":"singpass token wrapper and other endpoints to support private key jwt / client assertion","type":"application","logoUrl":"https://app.singpass.gov.sg/static/og_image.png","initialUrlPath":"/","repository":"https://github.com/pushpabrol/auth0-singpass-connection-helper","keywords":["auth0","extension","singpass"],"auth0":{"createClient":true,"scopes":"create:connections read:connections delete:connections update:connections","onInstallPath":"/.extensions/on-install","onUninstallPath":"/.extensions/on-uninstall","onUpdatePath":"/.extensions/on-update"},"secrets":{"IDP_DOMAIN":{"description":"The domain for your IDP","example":"stg-id.singpass.gov.sg","required":true,"default":"login.pushp.me"},"IDP_CLIENT_ID":{"description":"Client ID from your IDP","example":"client_pkce_pk_jwt_ES256","default":"client_pkce_pk_jwt_ES256","required":true},"RELYING_PARTY_KID":{"default":"Al93ssyWpZ2yOoLxbDohuTigc1i5XNt1PKMyvU8aVgY","description":"Relying Party KID","required":true},"RELYING_PARTY_PRIVATE_KEY_SIGNING":{"default":"Fc5okytOO6sHmxFw0YPIT4qE7ojv7V-2nuvr9KhEKy8","description":"RELYING_PARTY_PRIVATE_KEY for SIGNING","required":true},"RELYING_PARTY_PRIVATE_KEY_ENC":{"default":"JzbVVPBsdmtNRyAKizBd6z5pLy3sZapAfwJwDNWmQbM","description":"RELYING_PARTY_PRIVATE_KEY for ENCRYPTION","required":true},"RELYING_PARTY_PRIVATE_KEY_ENC_ALG":{"description":"Algorithm for RELYING_PARTY_PRIVATE_KEY_ENC","type":"select","allowMultiple":false,"default":"ECDH-ES+A128KW","options":[{"value":"ECDH-ES+A128KW","text":"ECDH-ES+A128KW"}],"required":true},"RELYING_PARTY_CLIENT_ASSERTION_SIGNING_ALG":{"description":"Algorithm for RELYING_PARTY_CLIENT_ASSERTION_SIGNING","type":"select","allowMultiple":false,"default":"ES256","options":[{"value":"ES256","text":"ES256"}],"required":true},"INTERMEDIARY_PRIVATE_KEY":{"description":"INTERMEDIARY PRIVATE KEY(internal processing)","default":"","required":true},"INTERMEDIARY_KEY_KID":{"description":"Key for Intermediary signing key","required":true},"INTERMEDIARY_SIGNING_ALG":{"description":"Intermediary Signing key\'s Algorithm","type":"select","allowMultiple":false,"default":"RS256","required":true,"options":[{"value":"RS256","text":"RS256"}]}}}')},function(e,t){e.exports=require("cors@2.8.1")},function(e,t,n){var o=n(2),s=n(14),r=n(15).ManagementClient,i=n(16),a=o.Router();function u(e){return function(t,n,o){if(console.log("jwt"),t.headers.authorization&&"Bearer"===t.headers.authorization.split(" ")[0]){var s=t.headers.authorization.split(" ")[1];return i.verify(s,t.webtaskContext.data.EXTENSION_SECRET,{audience:`${t.webtaskContext.data.WT_URL}${e}`,issuer:"https://"+t.webtaskContext.data.AUTH0_DOMAIN})?o():n.sendStatus(401)}return n.sendStatus(401)}}e.exports=a,a.use("/on-install",u("/.extensions/on-install")),a.use("/on-uninstall",u("/.extensions/on-uninstall")),a.use("/on-update",u("/.extensions/on-update")),a.use(function(e,t,n){console.log("here"),function(e,t){var n="https://"+e.webtaskContext.data.AUTH0_DOMAIN+"/oauth/token",o="https://"+e.webtaskContext.data.AUTH0_DOMAIN+"/api/v2/",r=e.webtaskContext.data.AUTH0_CLIENT_ID,i=e.webtaskContext.data.AUTH0_CLIENT_SECRET;s.post(n).send({audience:o,grant_type:"client_credentials",client_id:r,client_secret:i}).type("application/json").end(function(e,n){e||!n.ok?t(null,e):t(n.body.access_token)})}(e,function(t,o){if(o)return n(o);var s=new r({domain:e.webtaskContext.data.AUTH0_DOMAIN,token:t});e.auth0=s,n()})}),a.post("/on-install",function(e,t){t.sendStatus(204)}),a.put("/on-update",function(e,t){t.sendStatus(204)}),a.delete("/on-uninstall",function(e,t){t.sendStatus(204)})},function(e,t){e.exports=require("superagent@5.3.1")},function(e,t){e.exports=require("auth0@3.0.1")},function(e,t){e.exports=require("jsonwebtoken@9.0.0")}]);