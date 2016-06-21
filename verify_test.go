package httpsig

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func getTestPublicKey(alg string) string {
	parts, _ := validateAlgorithm(alg)
	if parts.sign == "hmac" {
		return getPrivateKeyForTests(alg)
	}
	return getTestKey(fmt.Sprintf("%s_public.pem", parts.sign))
}

func TestVerifyRequests(t *testing.T) {
	// hmac
	signVerifyAndAssert(t, "hmac-sha1", false)
	signVerifyAndAssert(t, "hmac-sha256", false)
	signVerifyAndAssert(t, "hmac-sha512", false)
	signVerifyAndAssert(t, "hmac-sha1", true)
	signVerifyAndAssert(t, "hmac-sha256", true)
	signVerifyAndAssert(t, "hmac-sha512", true)
	// rsa
	signVerifyAndAssert(t, "rsa-sha1", false)
	signVerifyAndAssert(t, "rsa-sha256", false)
	signVerifyAndAssert(t, "rsa-sha512", false)
	signVerifyAndAssert(t, "rsa-sha1", true)
	signVerifyAndAssert(t, "rsa-sha256", true)
	signVerifyAndAssert(t, "rsa-sha512", true)
	// dsa
	signVerifyAndAssert(t, "dsa-sha1", false)
	signVerifyAndAssert(t, "dsa-sha256", false)
	signVerifyAndAssert(t, "dsa-sha512", false)
	signVerifyAndAssert(t, "dsa-sha1", true)
	signVerifyAndAssert(t, "dsa-sha256", true)
	signVerifyAndAssert(t, "dsa-sha512", true)
	// ecdsa
	signVerifyAndAssert(t, "ecdsa-sha1", false)
	signVerifyAndAssert(t, "ecdsa-sha256", false)
	signVerifyAndAssert(t, "ecdsa-sha512", false)
	signVerifyAndAssert(t, "ecdsa-sha1", true)
	signVerifyAndAssert(t, "ecdsa-sha256", true)
	signVerifyAndAssert(t, "ecdsa-sha512", true)
}

func signVerifyAndAssert(t *testing.T, alg string, withJWT bool) {
	var ext map[string]string = nil
	if withJWT {
		ext = getJWT()
	}
	req, err := getExampleSignedRequest(alg, ext)
	// this is only needed to simulate an actual request
	req.RequestURI = getPathAndQueryFromURL(req.URL)
	assert.Nil(t, err)
	parsed, err := ParseRequest(req)
	assert.Nil(t, err)
	verified, err := VerifySignature(parsed, getTestPublicKey(alg))
	assert.Nil(t, err)
	assert.True(t, verified)
}
