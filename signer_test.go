package httpsig

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"net/http"
	"testing"
	"time"
)

// These tests just verify that a signature is made, the verify tests will verify that the signature was valid
func TestSignRequests(t *testing.T) {
	// hmac
	signAndAssert(t, "hmac-sha1", false)
	signAndAssert(t, "hmac-sha256", false)
	signAndAssert(t, "hmac-sha512", false)
	signAndAssert(t, "hmac-sha1", true)
	signAndAssert(t, "hmac-sha256", true)
	signAndAssert(t, "hmac-sha512", true)
	// rsa
	signAndAssert(t, "rsa-sha1", false)
	signAndAssert(t, "rsa-sha256", false)
	signAndAssert(t, "rsa-sha512", false)
	signAndAssert(t, "rsa-sha1", true)
	signAndAssert(t, "rsa-sha256", true)
	signAndAssert(t, "rsa-sha512", true)
	// dsa
	signAndAssert(t, "dsa-sha1", false)
	signAndAssert(t, "dsa-sha256", false)
	signAndAssert(t, "dsa-sha512", false)
	signAndAssert(t, "dsa-sha1", true)
	signAndAssert(t, "dsa-sha256", true)
	signAndAssert(t, "dsa-sha512", true)
	// ecdsa
	signAndAssert(t, "ecdsa-sha1", false)
	signAndAssert(t, "ecdsa-sha256", false)
	signAndAssert(t, "ecdsa-sha512", false)
	signAndAssert(t, "ecdsa-sha1", true)
	signAndAssert(t, "ecdsa-sha256", true)
	signAndAssert(t, "ecdsa-sha512", true)
}

func signAndAssert(t *testing.T, alg string, withJWT bool) {
	var ext map[string]string = nil
	if withJWT {
		ext = getJWT()
	}
	req, err := getExampleSignedRequest(alg, ext)
	assert.Nil(t, err)
	authz := req.Header.Get("Authorization")
	assert.NotEmpty(t, authz)
}

func getExampleSignedRequest(alg string, ext map[string]string) (req *http.Request, err error) {
	req, _ = http.NewRequest("GET", "http://example.com/path/to/resource", nil)
	signer, _ := NewRequestSigner(SampleKeyId, getPrivateKeyForTests(alg), alg)
	err = signer.SignRequest(req, []string{"date", "(request-target)"}, ext)
	return
}

func getJWT() map[string]string {
	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"foo": "bar",
		"exp": time.Now().Unix() + 30000,
	})

	tokenString, _ := token.SignedString("ignored")
	return map[string]string{
		"jwt": tokenString,
	}
}

func getPrivateKeyForTests(alg string) string {
	algorithm, _ := validateAlgorithm(alg)
	if algorithm.sign == "hmac" {
		return "sooper-seekrit-kee"
	}
	return getTestKey(fmt.Sprintf("%s_private.pem", algorithm.sign))
}

func getTestKey(file string) string {
	f, err := ioutil.ReadFile(fmt.Sprintf("test/%s", file))
	if err != nil {
		panic(err)
	}
	return string(f)
}
