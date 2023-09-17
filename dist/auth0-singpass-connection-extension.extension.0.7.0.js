"use strict";
module.exports=function(t){var e={};function n(o){if(e[o])return e[o].exports;var s=e[o]={i:o,l:!1,exports:{}};return t[o].call(s.exports,s,s.exports,n),s.l=!0,s.exports}return n.m=t,n.c=e,n.d=function(t,e,o){n.o(t,e)||Object.defineProperty(t,e,{enumerable:!0,get:o})},n.r=function(t){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(t,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(t,"__esModule",{value:!0})},n.t=function(t,e){if(1&e&&(t=n(t)),8&e)return t;if(4&e&&"object"==typeof t&&t&&t.__esModule)return t;var o=Object.create(null);if(n.r(o),Object.defineProperty(o,"default",{enumerable:!0,value:t}),2&e&&"string"!=typeof t)for(var s in t)n.d(o,s,function(e){return t[e]}.bind(null,s));return o},n.n=function(t){var e=t&&t.__esModule?function(){return t.default}:function(){return t};return n.d(e,"a",e),e},n.o=function(t,e){return Object.prototype.hasOwnProperty.call(t,e)},n.p="",n(n.s=0)}([function(t,e,n){var o=n(1);const s=n(2),a=n(3),i=n(4),{JWK:r,JWE:c}=n(5),{SignJWT:u,importJWK:d,importPKCS8:l,jwtVerify:p,createRemoteJWKSet:_}=n(6),I=n(7),E=n(8),y=n(9),N=n(10),f=n(11),g=n(12);N.config();const k=s();k.use(s.json()),k.use(s.urlencoded({extended:!0})),k.options("*",g()),k.use("/.extensions",n(13)),k.get("/.well-known/keys",async(t,e)=>{e.json(a)}),k.get("/jwks",async(t,e)=>{e.json(i)}),k.get("/meta",async(t,e)=>{e.status(200).send(f)}),k.get("/",async(t,e)=>{e.json({token:{url:`${t.webtaskContext.data.PUBLIC_WT_URL}/token`,use:"Used by the Auth0 connection as a token wrapper"},jwks:{url:`${t.webtaskContext.data.PUBLIC_WT_URL}/jwks`,use:"Used by Auth0 for token signature verification. This is used instead of the jwks of the IDP"},keys:{url:`${t.webtaskContext.data.PUBLIC_WT_URL}/.well-known/keys`,use:"Used by the IDP for client assertion validation & JWE. Key with alg: ES256 is used for client assertion validation & Key with alg: ECDH-ES+A128KW is used for token encryption"}})}),t.exports=o.fromExpress(k),k.post("/token",async(t,e)=>{const n=t.webtaskContext?t.webtaskContext.data:Object({NODE_ENV:"production",CLIENT_VERSION:"0.7.0"});console.log(t.body);const{client_id:o,code:s,code_verifier:i,redirect_uri:N}=t.body;if(!o)return e.status(400).send("Missing client_id");if(n.IDP_CLIENT_ID!==o)return e.status(401).send("Invalid request, client_id is incorrect!");try{const t=await async function(t){try{const e=await async function(t){try{var e=a.keys.find(t=>"sig"===t.use);return e.d=t.RELYING_PARTY_PRIVATE_KEY_SIGNING,await d(e,t.RELYING_PARTY_CLIENT_ASSERTION_SIGNING_ALG)}catch(t){return t}}(t);console.log(e);const n=await new u({}).setProtectedHeader({alg:t.RELYING_PARTY_CLIENT_ASSERTION_SIGNING_ALG,kid:t.RELYING_PARTY_KID,typ:"JWT"}).setIssuedAt().setIssuer(t.IDP_CLIENT_ID).setSubject(t.IDP_CLIENT_ID).setAudience([`https://${t.IDP_DOMAIN}/`,`https://${t.IDP_DOMAIN}/token`]).setExpirationTime("2m").setJti(E.v4()).sign(e);return console.log(n),n}catch(t){return console.log(t),t}}(n);console.log(t);const o={method:"POST",url:`https://${n.IDP_DOMAIN}/token`,headers:{"content-type":"application/x-www-form-urlencoded"},data:y.stringify({grant_type:"authorization_code",client_id:n.IDP_CLIENT_ID,client_assertion_type:"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",client_assertion:t,code:s,code_verifier:i,redirect_uri:N})},f=await I.request(o);console.log(f.data);const{id_token:g}=f.data,k=await async function(t,e){var n=a.keys.find(t=>"enc"===t.use&&t.alg===e.RELYING_PARTY_PRIVATE_KEY_ENC_ALG);if(!n)return console.log("Either not encrypted or the right key is not available!, returning token as is!"),t;n.d=e.RELYING_PARTY_PRIVATE_KEY_ENC;try{const e=c.createDecrypt(await r.asKey(n,"json")),o=await e.decrypt(t),s=o.plaintext.toString("utf8");return console.log(s),s}catch(t){throw console.log(t),t}}(g,n),A=_(new URL(`https://${n.IDP_DOMAIN}/jwks`)),{payload:x,protectedHeader:T}=await p(k,A,{issuer:`https://${n.IDP_DOMAIN}`,audience:n.IDP_CLIENT_ID});console.log(x),console.log(T),x.nonce&&delete x.nonce,f.data.payload=x,delete f.data.id_token;const w=await async function(t,e){t.nonce&&delete t.nonce;try{const n=await async function(t){try{const n=t.INTERMEDIARY_PRIVATE_KEY.replace(/\\n/gm,"\n");console.log("from secrets:",n);var e=await l(n,t.INTERMEDIARY_SIGNING_ALG);return e}catch(t){return console.log(t),t}}(e);console.log(n);const o=await new u(t).setProtectedHeader({alg:e.INTERMEDIARY_SIGNING_ALG,kid:e.INTERMEDIARY_KEY_KID,typ:"JWT"}).setIssuedAt().setIssuer(`https://${e.IDP_DOMAIN}`).setAudience(e.IDP_CLIENT_ID).setExpirationTime("2m").setJti(E.v4()).sign(n);return console.log(o),o}catch(t){return console.log(t),t}}(x,n);return f.data.id_token=w,e.status(200).send(f.data)}catch(t){return t.response?e.status(t.response.status).send(t.response.data):(console.error("Error:",t.message),e.status(500).send(t.message))}})},function(t,e){t.exports=require("webtask-tools")},function(t,e){t.exports=require("express@4.17.1")},function(t){t.exports=JSON.parse('{"keys":[{"kty":"EC","kid":"Al93ssyWpZ2yOoLxbDohuTigc1i5XNt1PKMyvU8aVgY","use":"sig","alg":"ES256","crv":"P-256","x":"6-l6udWD4kVDnoa8xDYNf9GHJXQXTNPEU8qfkiFHCBE","y":"TTXy1kprqhMA7bRy9v14C741tkOXkU36OtOuTKx6X80"},{"kty":"EC","kid":"UAzl2k6tGnj0bJBh5AimmGVd68QDrNyc9UTADv6dcc8","use":"enc","alg":"ECDH-ES+A128KW","crv":"P-256","x":"VexWR3Lb2dmnzuZeSNzS58XtM6bFpJOr2QN-p_WKN48","y":"7x7Vywcy8qZqE3SIaP-K7FAgrCECKJ_xoxr-zc6Wi4Y"}]}')},function(t){t.exports=JSON.parse('{"keys":[{"kty":"RSA","use":"sig","kid":"QVBKtPRpC9s2cynBuEI7DMjXwtinIkdMQ-ZMUX2BKZg","n":"v7PiYOndb1xI0vFaXtQ7JW66lrRbeFrj0hFL3zYEMgscjBg5KfG2Etwak8W41AQz2eWAOhDtX42a8Tb7D51xuEpFHBoEqOoLB1NsU5J1v1uxFGUGT0g_vMTN7MUxBUzdghiI1a3TugZsTnQDXT4R0msQU1hCi7yXoPETB-AQb_0rifBYK3kgweGZ5hFOvkuy-fZihJGrNEoAt3_17dEi8uAoqiAAN4XPpz4MmYizBNjY0ykFKwo-SWdueHe6FnwJkeWYNzPNFjBvaiHP7SYyPsPcqV_c3S1jUHs9eeq51GiKRuozLRU2ktDP94_-foqwfY0aik2xKkYcN7K4_Ms4Nw","e":"AQAB","alg":"RS256"}]}')},function(t,e){t.exports=require("node-jose@2.0.0")},function(t,e){t.exports=require("jose@4.10.0")},function(t,e){t.exports=require("axios@0.27.2")},function(t,e){t.exports=require("uuid@8.3.1")},function(t,e){t.exports=require("querystring")},function(t,e){t.exports=require("dotenv@16.0.1")},function(t){t.exports=JSON.parse('{"title":"Auth0 Singpass Connection Helper","name":"auth0-singpass-connection-extension","version":"0.7.0","author":"auth0","useHashName":false,"description":"singpass token wrapper and other endpoints to support private key jwt / client assertion","type":"application","category":"end_user","initialUrlPath":"/","logoUrl":"https://cdn.auth0.com/extensions/auth0-sso-dashboard/assets/logo.svg","repository":"https://github.com/pushpabrol/auth0-singpass-connection-helper","keywords":["auth0","extension","singpass"],"auth0":{"createClient":true,"scopes":"create:connections read:connections delete:connections update:connections","onInstallPath":"/.extensions/on-install","onUninstallPath":"/.extensions/on-uninstall","onUpdatePath":"/.extensions/on-update"},"secrets":{"IDP_DOMAIN":{"description":"The domain for your IDP","example":"stg-id.singpass.gov.sg","required":true,"type":"text"},"IDP_CLIENT_ID":{"description":"Client ID from your IDP","example":"client_pkce_pk_jwt_ES256","required":true,"type":"text"},"RELYING_PARTY_KID":{"example":"Al93ssyWpZ2yOoLxbDohuTigc1i5XNt1PKMyvU8aVgY","description":"Relying Party KID","required":true,"type":"text"},"RELYING_PARTY_PRIVATE_KEY_SIGNING":{"example":"Fc5okytOO6sHmxFw0YPIT4qE7ojv7V-2nuvr9KhEKy8","description":"RELYING_PARTY_PRIVATE_KEY for SIGNING","required":true,"type":"text"},"RELYING_PARTY_PRIVATE_KEY_ENC":{"example":"JzbVVPBsdmtNRyAKizBd6z5pLy3sZapAfwJwDNWmQbM","description":"RELYING_PARTY_PRIVATE_KEY for ENCRYPTION","required":true,"type":"text"},"RELYING_PARTY_PRIVATE_KEY_ENC_ALG":{"description":"Algorithm for RELYING_PARTY_PRIVATE_KEY_ENC","type":"select","allowMultiple":false,"default":"ECDH-ES+A128KW","options":[{"value":"ECDH-ES+A128KW","text":"ECDH-ES+A128KW"}]},"RELYING_PARTY_CLIENT_ASSERTION_SIGNING_ALG":{"description":"Algorithm for RELYING_PARTY_CLIENT_ASSERTION_SIGNING","type":"select","allowMultiple":false,"default":"ES256","options":[{"value":"ES256","text":"ES256"}]},"INTERMEDIARY_PRIVATE_KEY":{"description":"Intermediary signing key(RS256 & used within the connection)","required":true,"type":"text"},"INTERMEDIARY_KEY_KID":{"description":"Key for Intermediary signing key","required":true,"type":"text"},"INTERMEDIARY_SIGNING_ALG":{"description":"Intermediary Signing key\'s Algorithm","type":"select","allowMultiple":false,"default":"RS256","options":[{"value":"RS256","text":"RS256"}]},"AUTH0_CONNECTION_NAME":{"description":"name of singpass connection","required":true,"type":"text"}}}')},function(t,e){t.exports=require("cors@2.8.1")},function(t,e,n){var o=n(2),s=n(14),a=n(15).ManagementClient,i=n(16),r=o.Router();function c(t){return function(e,n,o){if(console.log("jwt"),e.headers.authorization&&"Bearer"===e.headers.authorization.split(" ")[0]){var s=e.headers.authorization.split(" ")[1];return i.verify(s,e.webtaskContext.data.EXTENSION_SECRET,{audience:`${e.webtaskContext.data.WT_URL}${t}`,issuer:"https://"+e.webtaskContext.data.AUTH0_DOMAIN})?o():n.sendStatus(401)}return n.sendStatus(401)}}async function u(t,e){try{console.log(t.webtaskContext.data),console.log(t.webtaskContext.secrets);var n=await t.auth0.getConnections({name:"pushp"});if(console.log(n.id),n=await t.auth0.getConnection({id:"con_GLdOAROQAA2XspgN"})){var o;if("install"===e)console.log(n.id),(o=n.options)&&(o.token_endpoint=t.webtaskContext.data.PUBLIC_WT_URL+"/token",o.jwks_uri=t.webtaskContext.data.PUBLIC_WT_URL+"/jwks"),o&&o.oidc_metadata&&(o.oidc_metadata.token_endpoint=t.webtaskContext.data.PUBLIC_WT_URL+"/token",o.oidc_metadata.jwks_uri=t.webtaskContext.data.PUBLIC_WT_URL+"/jwks");if("uninstall"===e)console.log(n.id),(o=n.options)&&(o.token_endpoint="https://"+t.webtaskContext.data.IDP_DOMAIN+"/token",o.jwks_uri="https://"+t.webtaskContext.data.IDP_DOMAIN+"/jwks"),o&&o.oidc_metadata&&(o.oidc_metadata.token_endpoint=t.webtaskContext.data.IDP_DOMAIN+"/token",o.oidc_metadata.jwks_uri=t.webtaskContext.data.IDP_DOMAIN+"/jwks");n=await t.auth0.updateConnection({id:n.id},{options:o}),console.log("Updated connection!: "+e)}else console.log("Connection with that name not found. Skipping connection updates!")}catch(t){console.log(t)}}t.exports=r,r.use("/on-install",c("/.extensions/on-install")),r.use("/on-uninstall",c("/.extensions/on-uninstall")),r.use("/on-update",c("/.extensions/on-update")),r.use(function(t,e,n){console.log("here"),function(t,e){var n="https://"+t.webtaskContext.data.AUTH0_DOMAIN+"/oauth/token",o="https://"+t.webtaskContext.data.AUTH0_DOMAIN+"/api/v2/",a=t.webtaskContext.data.AUTH0_CLIENT_ID,i=t.webtaskContext.data.AUTH0_CLIENT_SECRET;s.post(n).send({audience:o,grant_type:"client_credentials",client_id:a,client_secret:i}).type("application/json").end(function(t,n){t||!n.ok?e(null,t):e(n.body.access_token)})}(t,function(e,o){if(o)return n(o);var s=new a({domain:t.webtaskContext.data.AUTH0_DOMAIN,token:e});t.auth0=s,n()})}),r.post("/on-install",async function(t,e){await u(t,"install"),e.sendStatus(204)}),r.put("/on-update",function(t,e){e.sendStatus(204)}),r.delete("/on-uninstall",async function(t,e){await u(t,"uninstall"),e.sendStatus(204)})},function(t,e){t.exports=require("superagent@5.3.1")},function(t,e){t.exports=require("auth0@3.0.1")},function(t,e){t.exports=require("jsonwebtoken@9.0.0")}]);