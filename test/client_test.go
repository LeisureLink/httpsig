package httpsigtests

import (
	"bytes"
	"fmt"
	"github.com/LeisureLink/httpsig"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

var serverOut bytes.Buffer

func startNodeServer(port string) (cmd *exec.Cmd) {
	cmd = exec.Command("node", "server.js", port)
	cmd.Stdout = &serverOut
	cmd.Stderr = &serverOut
	cmd.Start()
	return
}

func printOut() string {
	out, _ := serverOut.ReadString(0)
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		fmt.Printf("server: %s\n", line)
	}
	return out
}

func getKeyId(algorithm string) string {
	alg := strings.Split(strings.ToLower(algorithm), "-")[0]
	if alg == "hmac" {
		return "sooper-seekrit-kee"
	}
	return fmt.Sprintf("%s_public.pem", alg)
}

func getKey(algorithm string) string {
	alg := strings.Split(strings.ToLower(algorithm), "-")[0]
	if alg == "hmac" {
		return "sooper-seekrit-kee"
	}
	f, err := ioutil.ReadFile(fmt.Sprintf("%s_private.pem", alg))
	if err != nil {
		panic(err)
	}
	return string(f)
}

func TestClientCanCallNodeServer(t *testing.T) {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	cmd := startNodeServer(port)
	// defer printOut()
	defer cmd.Process.Kill()
	for i := 0; i < 10; i++ {
		if strings.Contains(printOut(), "Listening") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

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
	fmt.Printf("Calling node server with %s algorithm\n", algorithm)
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://localhost:%s/", port), nil)
	signer, _ := httpsig.NewRequestSigner(getKeyId(algorithm), getKey(algorithm), algorithm)
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
	fmt.Println(res.StatusCode)
}
