var fs = require('fs');
var http = require('http');
var httpSignature = require('http-signature');

var loc = (process.argv[2] || 'localhost:8080').split(/\:/);
var alg = (process.argv[3] || 'rsa-sha256').toLowerCase().split(/\-/);
var key = alg[0] == 'hmac' ? 'sooper-seekrit-kee' : fs.readFileSync(alg[0] + '_private.pem', 'ascii');

var options = {
  host: loc[0],
  port: loc[1],
  path: '/',
  method: 'GET',
  headers: {}
};

// Adds a 'Date' header in, signs it, and adds the
// 'Authorization' header in.
var req = http.request(options, function(res) {
  console.log(res.statusCode);
});


httpSignature.sign(req, {
  key: key,
  keyId: alg[0] + '_public.pem',
  algorithm: alg.join('-'),
  headers: ["date", "(request-target)"]
});

req.end();
