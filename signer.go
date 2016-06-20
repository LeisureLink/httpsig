package httpsig

import (
	"crypto"
	"crypto/dsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	u "net/url"
	"strings"
	"time"
)

type Signer func(string) ([]byte, error)

type RequestSigner struct {
	keyId     string
	algorithm string
	signer    Signer
}

var SignStrict bool = false

func NewRequestSigner(keyId string, key string, algorithm string) (*RequestSigner, error) {
	signer, err := getSigner(algorithm, key)
	if err != nil {
		return nil, err
	}
	return &RequestSigner{
		keyId:     keyId,
		algorithm: algorithm,
		signer:    signer,
	}, nil
}

func NewCustomRequestSigner(keyId string, algorithm string, signer Signer) *RequestSigner {
	return &RequestSigner{
		keyId:     keyId,
		algorithm: algorithm,
		signer:    signer,
	}
}

func (rs *RequestSigner) SignRequest(request *http.Request, headers []string, jwt string) error {
	if _, ok := request.Header["Date"]; !ok {
		request.Header["Date"] = []string{time.Now().Format(time.RFC1123)}
	}
	if len(headers) == 0 {
		headers = []string{"date"}
	}
	lines := make([]string, 0, len(headers))
	for _, h := range headers {
		h = strings.ToLower(h)
		if h == "request-line" {
			if SignStrict {
				return errors.New("request-line is not a valid header with strict parsing enabled.")
			}
			lines = append(lines, fmt.Sprintf("%s %s %s", request.Method, getPathAndQueryFromURL(request.URL), request.Proto))
		} else if h == "(request-target)" {
			lines = append(lines, fmt.Sprintf("(request-target): %s %s", strings.ToLower(request.Method), getPathAndQueryFromURL(request.URL)))
		} else {
			values, ok := request.Header[headerCase(h)]
			if !ok {
				return errors.New(fmt.Sprintf("No value for header \"%s\"", h))
			}
			lines = append(lines, fmt.Sprintf("%s: %s", h, values[0]))
		}
	}
	stringToSign := strings.Join(lines, "\n")
	signature, err := rs.signer(stringToSign)
	if err != nil {
		return err
	}
	request.Header["Authorization"] = []string{formatSignature(rs.keyId, rs.algorithm, headers, jwt, signature)}
	return nil
}

func getPathAndQueryFromURL(url *u.URL) (pathAndQuery string) {
	pathAndQuery = url.Path
	if pathAndQuery == "" {
		pathAndQuery = "/"
	}
	if url.RawQuery != "" {
		pathAndQuery += "?" + url.RawQuery
	}
	return pathAndQuery
}

func formatSignature(keyId string, algorithm string, headers []string, jwt string, signature []byte) string {
	sig := fmt.Sprintf("Signature keyId=\"%s\",algorithm=\"%s\",headers=\"%s\"", keyId, algorithm, strings.Join(headers, " "))
	if jwt != "" {
		sig += fmt.Sprintf(",jwt=\"%s\"", jwt)
	}
	sig += fmt.Sprintf(",signature=\"%s\"", base64.StdEncoding.EncodeToString(signature))
	return sig
}

func hmacSigner(secret string, hash crypto.Hash) (Signer, error) {
	return func(data string) ([]byte, error) {
		h := hmac.New(hash.New, []byte(secret))
		h.Write([]byte(data))
		return h.Sum(nil), nil
	}, nil
}

func rsaSigner(key string, hash crypto.Hash) (Signer, error) {
	block, _ := pem.Decode([]byte(key))
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return noSigner, err
	}
	privateKey.Precompute()
	return func(data string) ([]byte, error) {
		hashed := calcHash(data, hash)
		return rsa.SignPKCS1v15(rand.Reader, privateKey, hash, hashed)
	}, nil
}

func dsaSigner(key string, hash crypto.Hash) (Signer, error) {
	privateKey, err := getDsaKey(key)
	if err != nil {
		return noSigner, err
	}
	return func(data string) ([]byte, error) {
		hashed := calcHash(data, hash)
		qlen := len(privateKey.Q.Bytes())
		if len(hashed) > qlen {
			hashed = hashed[:qlen]
		}
		r, s, err := dsa.Sign(rand.Reader, privateKey, hashed)
		if err != nil {
			return nil, err
		}

		return asn1.Marshal(dsaSignature{r, s})
	}, nil
}

func ecdsaSigner(key string, hash crypto.Hash) (Signer, error) {
	block, _ := pem.Decode([]byte(key))
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return noSigner, err
	}
	return func(data string) ([]byte, error) {
		hashed := calcHash(data, hash)
		return privateKey.Sign(rand.Reader, hashed, nil)
	}, nil
}

func getSigner(algorithm string, key string) (Signer, error) {
	alg, err := validateAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}
	switch alg.sign {
	case "hmac":
		return hmacSigner(key, alg.hash)
	case "rsa":
		return rsaSigner(key, alg.hash)
	case "dsa":
		return dsaSigner(key, alg.hash)
	case "ecdsa":
		return ecdsaSigner(key, alg.hash)
	}
	return nil, errors.New(fmt.Sprintf("Unsupported signing algorithm: %s", algorithm))
}

func noSigner(data string) ([]byte, error) {
	return nil, errors.New("Invalid signer")
}
