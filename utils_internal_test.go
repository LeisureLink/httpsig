package httpsig

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDetectAlgorithmFromRSAKey(t *testing.T) {
	key := getTestKey("rsa_private.pem")
	alg, err := autoDetectAlgorithm(key)
	assert.Nil(t, err)
	assert.Equal(t, "rsa-sha256", alg.String())
}

func TestDetectAlgorithmFromDSAKey(t *testing.T) {
	key := getTestKey("dsa_private.pem")
	alg, err := autoDetectAlgorithm(key)
	assert.Nil(t, err)
	assert.Equal(t, "dsa-sha256", alg.String())
}

func TestDetectAlgorithmFromECDSAKey(t *testing.T) {
	key := getTestKey("ecdsa_private.pem")
	alg, err := autoDetectAlgorithm(key)
	assert.Nil(t, err)
	assert.Equal(t, "ecdsa-sha256", alg.String())
}

func TestDetectAlgorithmFromNonPEMKey(t *testing.T) {
	alg, err := autoDetectAlgorithm("NOT A PEM KEY")
	assert.Nil(t, alg)
	assert.Contains(t, err.Error(), "PEM format")
}

func TestDetectAlgorithmFromPublicKey(t *testing.T) {
	key := getTestKey("rsa_public.pem")
	alg, err := autoDetectAlgorithm(key)
	assert.Nil(t, alg)
	assert.Contains(t, err.Error(), "(pem block type 'PUBLIC KEY')")
}
