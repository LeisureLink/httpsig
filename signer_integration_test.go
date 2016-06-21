package httpsig

import (
	"bytes"
	"fmt"
	"github.com/stretchr/testify/assert"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestClientCanCallNodeServer(t *testing.T) {
	npmInstall()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	cmd := startNodeServer(t, port)
	defer cmd.Process.Kill()

	verifyClientCanCallNodeServer(t, port, "hmac-sha1")
	verifyClientCanCallNodeServer(t, port, "hmac-sha256")
	verifyClientCanCallNodeServer(t, port, "hmac-sha512")
	verifyClientCanCallNodeServer(t, port, "rsa-sha1")
	verifyClientCanCallNodeServer(t, port, "rsa-sha256")
	verifyClientCanCallNodeServer(t, port, "rsa-sha512")
	verifyClientCanCallNodeServer(t, port, "dsa-sha1")
	verifyClientCanCallNodeServer(t, port, "dsa-sha256")
	verifyClientCanCallNodeServer(t, port, "dsa-sha512")
	verifyClientCanCallNodeServer(t, port, "ecdsa-sha1")
	verifyClientCanCallNodeServer(t, port, "ecdsa-sha256")
	verifyClientCanCallNodeServer(t, port, "ecdsa-sha512")
}

func verifyClientCanCallNodeServer(t *testing.T, port string, algorithm string) {
	defer readServerOut(t)
	t.Logf("Calling node server with %s algorithm", algorithm)
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://localhost:%s/", port), nil)
	signer, _ := NewRequestSigner(getKeyIdForTests(algorithm), getPrivateKeyForTests(algorithm), algorithm)
	err := signer.SignRequest(req, []string{"date", "(request-target)"}, nil)
	if err != nil {
		t.Error(err)
		return
	}

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		t.Error(err)
		return
	}
	assert.Equal(t, http.StatusOK, res.StatusCode)
	t.Log(res.StatusCode)
}

func getKeyIdForTests(alg string) string {
	algorithm, _ := validateAlgorithm(alg)
	if algorithm.sign == "hmac" {
		return getPrivateKeyForTests(alg)
	}
	return fmt.Sprintf("%s_public.pem", algorithm.sign)
}

var serverOut bytes.Buffer

func startNodeServer(t *testing.T, port string) (cmd *exec.Cmd) {
	cmd = exec.Command("node", "server.js", port)
	cmd.Dir = "./test"
	cmd.Stdout = &serverOut
	cmd.Stderr = &serverOut
	cmd.Start()

	for i := 0; i < 10; i++ {
		if strings.Contains(readServerOut(t), "Listening") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	return
}

func npmInstall() {
	cmd := exec.Command("npm", "install")
	cmd.Dir = "./test"
	err := cmd.Run()
	if err != nil {
		panic(err)
	}
}

func readServerOut(t *testing.T) string {
	out, _ := serverOut.ReadString(0)
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		t.Logf("server: %s\n", line)
	}
	return out
}
