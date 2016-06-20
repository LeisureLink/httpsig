package httpsigtests

import (
	"bytes"
	"fmt"
	"github.com/LeisureLink/httpsig"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
)

func nodeClient(address string, algorithm string) string {
	cmd := exec.Command("node", "client.js", address, algorithm)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	rs, _ := out.ReadString(byte(0))
	if err != nil {
		fmt.Print(rs)
		panic(err)
	}
	return rs
}

func lookupPubKey(algorithm string, keyId string) string {
	if strings.Contains(strings.ToLower(algorithm), "hmac") {
		return "sooper-seekrit-kee"
	}
	f, err := ioutil.ReadFile(keyId)
	if err != nil {
		panic(err)
	}
	return string(f)
}

type TestHandler struct {
}

func (h *TestHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	parsed, err := httpsig.ParseRequest(req)
	if err != nil {
		fmt.Print(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	publicKey := lookupPubKey(parsed.Algorithm(), parsed.KeyId())
	verified, err := httpsig.VerifySignature(parsed, publicKey)
	if err != nil || !verified {
		fmt.Printf("Unverified: %v\n", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Authoirzation Passed"))
}

func TestNodeClientCanCallServer(t *testing.T) {
	handler := &TestHandler{}
	server := httptest.NewServer(handler)
	address := server.Listener.Addr().String()
	defer server.Close()

	verifyNodeClientCanCallServer(t, address, "hmac-sha1")
	verifyNodeClientCanCallServer(t, address, "hmac-sha256")
	verifyNodeClientCanCallServer(t, address, "hmac-sha512")
	verifyNodeClientCanCallServer(t, address, "rsa-sha1")
	verifyNodeClientCanCallServer(t, address, "rsa-sha256")
	verifyNodeClientCanCallServer(t, address, "rsa-sha512")
	verifyNodeClientCanCallServer(t, address, "dsa-sha1")
	verifyNodeClientCanCallServer(t, address, "dsa-sha256")
	verifyNodeClientCanCallServer(t, address, "dsa-sha512")
	verifyNodeClientCanCallServer(t, address, "ecdsa-sha1")
	verifyNodeClientCanCallServer(t, address, "ecdsa-sha256")
	verifyNodeClientCanCallServer(t, address, "ecdsa-sha512")
}

func verifyNodeClientCanCallServer(t *testing.T, address string, algorithm string) {
	fmt.Printf("Calling go server with %s algorithm\n", algorithm)
	output := nodeClient(address, algorithm)
	fmt.Println(output)
	assert.Equal(t, "200\n", output)
}
