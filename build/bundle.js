"use strict";
module.exports=function(e){var t={};function n(r){if(t[r])return t[r].exports;var o=t[r]={i:r,l:!1,exports:{}};return e[r].call(o.exports,o,o.exports,n),o.l=!0,o.exports}return n.m=e,n.c=t,n.d=function(e,t,r){n.o(e,t)||Object.defineProperty(e,t,{enumerable:!0,get:r})},n.r=function(e){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})},n.t=function(e,t){if(1&t&&(e=n(e)),8&t)return e;if(4&t&&"object"==typeof e&&e&&e.__esModule)return e;var r=Object.create(null);if(n.r(r),Object.defineProperty(r,"default",{enumerable:!0,value:e}),2&t&&"string"!=typeof e)for(var o in e)n.d(r,o,function(t){return e[t]}.bind(null,o));return r},n.n=function(e){var t=e&&e.__esModule?function(){return e.default}:function(){return e};return n.d(t,"a",t),t},n.o=function(e,t){return Object.prototype.hasOwnProperty.call(e,t)},n.p="",n(n.s=0)}([function(e,t,n){var r=n(1);const o=n(2),s=n(3),i=n(4),{JWK:a,JWE:u}=n(5),{SignJWT:c,importJWK:d,importPKCS8:l,jwtVerify:_,createRemoteJWKSet:I,parseJwk:p}=n(6),E=n(7),N=n(8),g=n(9);n(10).config();const A=o();A.use(o.json()),A.use(o.urlencoded({extended:!0})),A.get("/.well-known/keys",async(e,t)=>{t.json(s)}),A.get("/jwks",async(e,t)=>{t.json(i)}),A.get("/meta",async(e,t)=>{t.status(200).send(n(11))}),e.exports=r.fromExpress(A),A.post("/token",async(e,t)=>{const n=e.webtaskContext?e.webtaskContext.data:Object({NODE_ENV:"production",CLIENT_VERSION:"0.0.7"});console.log(e.body);const{client_id:r,code:o,code_verifier:i,redirect_uri:l}=e.body;if(!r)return t.status(400).send("Missing client_id");if(n.IDP_CLIENT_ID!==r)return t.status(401).send("Invalid request, client_id is incorrect!");try{const e=await async function(e){try{const t=await async function(e){try{var t=s.keys.find(e=>"sig"===e.use);return t.d=e.RELYING_PARTY_PRIVATE_KEY_SIGNING,await d(t,e.RELYING_PARTY_CLIENT_ASSERTION_SIGNING_ALG)}catch(e){return e}}(e);console.log(t);const n=await new c({}).setProtectedHeader({alg:e.RELYING_PARTY_CLIENT_ASSERTION_SIGNING_ALG,kid:e.RELYING_PARTY_KID,typ:"JWT"}).setIssuedAt().setIssuer(e.IDP_CLIENT_ID).setSubject(e.IDP_CLIENT_ID).setAudience([`https://${e.IDP_DOMAIN}/`,`https://${e.IDP_DOMAIN}/token`]).setExpirationTime("2m").setJti(N.v4()).sign(t);return console.log(n),n}catch(e){return console.log(e),e}}(n);console.log(e);const r={method:"POST",url:`https://${n.IDP_DOMAIN}/token`,headers:{"content-type":"application/x-www-form-urlencoded"},data:g.stringify({grant_type:"authorization_code",client_id:n.IDP_CLIENT_ID,client_assertion_type:"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",client_assertion:e,code:o,code_verifier:i,redirect_uri:l})},p=await E.request(r);console.log(p.data);const{id_token:A}=p.data,y=await async function(e,t){var n=s.keys.find(e=>"enc"===e.use&&e.alg===t.RELYING_PARTY_PRIVATE_KEY_ENC_ALG);if(!n)return console.log("Either not encrypted or the right key is not available!, returning token as is!"),e;n.d=t.RELYING_PARTY_PRIVATE_KEY_ENC;try{const t=u.createDecrypt(await a.asKey(n,"json")),r=await t.decrypt(e),o=r.plaintext.toString("utf8");return console.log(o),o}catch(e){throw console.log(e),e}}(A,n),f=I(new URL(`https://${n.IDP_DOMAIN}/jwks`)),{payload:R,protectedHeader:T}=await _(y,f,{issuer:`https://${n.IDP_DOMAIN}`,audience:n.IDP_CLIENT_ID});console.log(R),console.log(T),R.nonce&&delete R.nonce,p.data.payload=R,delete p.data.id_token;const P=await async function(e,t){e.nonce&&delete e.nonce;try{const n=await d({kty:"RSA",kid:"QVBKtPRpC9s2cynBuEI7DMjXwtinIkdMQ-ZMUX2BKZg",n:"v7PiYOndb1xI0vFaXtQ7JW66lrRbeFrj0hFL3zYEMgscjBg5KfG2Etwak8W41AQz2eWAOhDtX42a8Tb7D51xuEpFHBoEqOoLB1NsU5J1v1uxFGUGT0g_vMTN7MUxBUzdghiI1a3TugZsTnQDXT4R0msQU1hCi7yXoPETB-AQb_0rifBYK3kgweGZ5hFOvkuy-fZihJGrNEoAt3_17dEi8uAoqiAAN4XPpz4MmYizBNjY0ykFKwo-SWdueHe6FnwJkeWYNzPNFjBvaiHP7SYyPsPcqV_c3S1jUHs9eeq51GiKRuozLRU2ktDP94_-foqwfY0aik2xKkYcN7K4_Ms4Nw",e:"AQAB",d:"K3kRp0ShsLVO1ndhNQwP9acsrSxtadfCvkqp2A6Z2PdoG-UKYZas4Y4EgOpfxcTGNW20LHbWPcsRDg6X1Kyxs0c0cPD9iYi5w4mJkVIvXZvfhm56hdQukBJZWI5HVZpeyTfjIAHxd8gpG4l3kdeXlw4sf5oOTT4RbK_-ztRjJeHxUxqnzYgXGUWY0wM9rRsJzj3vL_zi4L3Xx47GFQGgbVAnBO-wg7wwDEKgiVEStP9PTbXUX8wuIX8t9DVRlMOcPjksDBULepKjeK3ljkORAEuIzjeSYYxwvSQmGIdotwcE9-KXL_nlGo4hMhEULGSzWHtCFeLvHvWQKP91brMl4Q",p:"4q2lNWWyT8k5jR8-qj5mKNDovveesjQClWgMAz8Kjdnddz0c1uLDG9D-eGRV3caNCaNcO5Npxq9UFHIzxVHWjZuz83gOcOZucr-S3zxnXj0r_IdWZbKUk_29NkFQ6Shih088pv3ddFeHK9jWAVToADg6kWrT9rrQZW0xkuKwdnk",q:"2IAJN4InDzvkMsyb_hlKmeHQiK5C4eQwiQROrdIF-w3oVTfX5r-lzWz9uxGVbeQshfZaEQxwK0zQxMvif_r0OF-Eu6JuF5pGp3uCmlrx5WfvkSSLm7u4xlbB9_t-nMhG_CF5RJ8X-hoo4he6d5LU4xlae9_UCh7nPivDoWWTOC8",dp:"AcOUK4w1DQXl2sFJfY2qwdqOVR4cMArTklIS9duBu4TcglcJaGqvVgIUWN9_A5DN_Cs3RodpJVCr-NTCrmBqqQNzLQvcIOjKJz5yaCZSL5uOQhLTi0sOePBajpeHh6j2y1LEiBAlrwgXVzICyFPe0lGdsw__wkXF5WQqJJh7AxE",dq:"Dy-j9d3OSZZE4n9RrdguUG7zhrLahCfSc7n2nuCthLesBVY-cbQduDQd9CI-ng-0Q81M8gcyUwc3WaaHg7yhptakY9j36fXrYNIcDiG0-Ad7WW370Pew9VCemHtunSa7O_JJJFQYhXWSSpGphbup7SgZHblMkU0roUPGnCqY0gc",qi:"LtzwWittiDEMCqW1WOch4M9JnzcfLjCz2lBFTlGoiF6CxnOEQePKfmTZ7wK7LVi5nhSHh-PAkNrBhNMt4AEGUJ0DB92FMInAnknar_GCK67LC7bMo5JRLgVkGNXeDDpWyWEvgXitqYYzjwfLUD5MFYogiR5OXFLdTa_mfyEps_0"},"RS256");console.log(n);const r=await new c(e).setProtectedHeader({alg:t.INTERMEDIARY_SIGNING_ALG,kid:t.INTERMEDIARY_KEY_KID,typ:"JWT"}).setIssuedAt().setIssuer(`https://${t.IDP_DOMAIN}`).setAudience(t.IDP_CLIENT_ID).setExpirationTime("2m").setJti(N.v4()).sign(n);return console.log(r),r}catch(e){return console.log(e),e}}(R,n);return p.data.id_token=P,t.status(200).send(p.data)}catch(e){return e.response?t.status(e.response.status).send(e.response.data):(console.error("Error:",e.message),t.status(500).send(e.message))}})},function(e,t){e.exports=require("webtask-tools")},function(e,t){e.exports=require("express@4.17.1")},function(e){e.exports=JSON.parse('{"keys":[{"kty":"EC","kid":"Al93ssyWpZ2yOoLxbDohuTigc1i5XNt1PKMyvU8aVgY","use":"sig","crv":"P-256","x":"6-l6udWD4kVDnoa8xDYNf9GHJXQXTNPEU8qfkiFHCBE","y":"TTXy1kprqhMA7bRy9v14C741tkOXkU36OtOuTKx6X80"},{"kty":"EC","kid":"UAzl2k6tGnj0bJBh5AimmGVd68QDrNyc9UTADv6dcc8","use":"enc","alg":"ECDH-ES+A128KW","crv":"P-256","x":"VexWR3Lb2dmnzuZeSNzS58XtM6bFpJOr2QN-p_WKN48","y":"7x7Vywcy8qZqE3SIaP-K7FAgrCECKJ_xoxr-zc6Wi4Y"}]}')},function(e){e.exports=JSON.parse('{"keys":[{"kty":"RSA","use":"sig","kid":"QVBKtPRpC9s2cynBuEI7DMjXwtinIkdMQ-ZMUX2BKZg","n":"v7PiYOndb1xI0vFaXtQ7JW66lrRbeFrj0hFL3zYEMgscjBg5KfG2Etwak8W41AQz2eWAOhDtX42a8Tb7D51xuEpFHBoEqOoLB1NsU5J1v1uxFGUGT0g_vMTN7MUxBUzdghiI1a3TugZsTnQDXT4R0msQU1hCi7yXoPETB-AQb_0rifBYK3kgweGZ5hFOvkuy-fZihJGrNEoAt3_17dEi8uAoqiAAN4XPpz4MmYizBNjY0ykFKwo-SWdueHe6FnwJkeWYNzPNFjBvaiHP7SYyPsPcqV_c3S1jUHs9eeq51GiKRuozLRU2ktDP94_-foqwfY0aik2xKkYcN7K4_Ms4Nw","e":"AQAB"}]}')},function(e,t){e.exports=require("node-jose@2.0.0")},function(e,t){e.exports=require("jose@4.10.0")},function(e,t){e.exports=require("axios@0.27.2")},function(e,t){e.exports=require("uuid@8.3.1")},function(e,t){e.exports=require("querystring")},function(e,t){e.exports=require("dotenv@16.0.1")},function(e){e.exports=JSON.parse('{"title":"Auth0 Singpass Connection Extension","name":"auth0-singpass-connection-extension","version":"0.0.7","author":"Auth0","useHashName":false,"description":"singpass token wrapper and other endpoints to support private key jwt / client assertion","type":"application","category":"end_user","logoUrl":"https://app.singpass.gov.sg/static/og_image.png","initialUrlPath":"/","keywords":["auth0","extension","singpass"],"secrets":{"IDP_DOMAIN":{"description":"The domain for your IDP","example":"stg-id.singpass.gov.sg","required":true},"IDP_CLIENT_ID":{"description":"Client ID from your IDP","example":"client_pkce_pk_jwt_ES256","required":true},"RELYING_PARTY_KID":{"default":"Al93ssyWpZ2yOoLxbDohuTigc1i5XNt1PKMyvU8aVgY","description":"Relying Party KID","required":true},"RELYING_PARTY_PRIVATE_KEY_SIGNING":{"default":"Fc5okytOO6sHmxFw0YPIT4qE7ojv7V-2nuvr9KhEKy8","description":"RELYING_PARTY_PRIVATE_KEY for SIGNING","required":true},"RELYING_PARTY_PRIVATE_KEY_ENC":{"default":"JzbVVPBsdmtNRyAKizBd6z5pLy3sZapAfwJwDNWmQbM","description":"RELYING_PARTY_PRIVATE_KEY for ENCRYPTION","required":true},"RELYING_PARTY_PRIVATE_KEY_ENC_ALG":{"description":"Algorithm for RELYING_PARTY_PRIVATE_KEY_ENC","type":"select","allowMultiple":false,"default":"ECDH-ES+A128KW","options":[{"value":"ECDH-ES+A128KW","text":"ECDH-ES+A128KW"}],"required":true},"RELYING_PARTY_CLIENT_ASSERTION_SIGNING_ALG":{"description":"Algorithm for RELYING_PARTY_CLIENT_ASSERTION_SIGNING","type":"select","allowMultiple":false,"default":"ES256","options":[{"value":"ES256","text":"ES256"}],"required":true},"INTERMEDIARY_PRIVATE_KEY":{"description":"INTERMEDIARY PRIVATE KEY(internal processing)","default":"","required":true},"INTERMEDIARY_KEY_KID":{"description":"Key for Intermediary signing key","required":true},"INTERMEDIARY_SIGNING_ALG":{"description":"Intermediary Signing key\'s Algorithm","type":"select","allowMultiple":false,"default":"RS256","required":true,"options":[{"value":"RS256","text":"RS256"}]}}}')}]);