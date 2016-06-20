var fs = require('fs');
var http = require('http');
var httpSignature = require('http-signature');

var port = process.argv[2] || 8080;

http.createServer(function (req, res) {
  var rc = 200;
  var parsed = httpSignature.parseRequest(req);
  if (parsed.algorithm.indexOf('HMAC') >= 0) {
    if (!httpSignature.verifyHMAC(parsed, parsed.keyId))
      rc = 401;
  } else {
    var pubKey = fs.readFileSync(parsed.keyId, 'ascii');
    if (!httpSignature.verifySignature(parsed, pubKey))
      rc = 401;
  }

  console.log("request: " + rc);
  res.writeHead(rc);
  res.end();
}).listen(port, function(){
  console.log("Listening")
});
