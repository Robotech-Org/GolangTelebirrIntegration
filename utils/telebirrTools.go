package utils

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// CreateTimestamp generates a timestamp in seconds, matching the Python reference.
func CreateTimestamp() string {
	return fmt.Sprintf("%d", time.Now().Unix())
}

// CreateNonceStr generates a random UUID string.
// Note: Python uses uuid1 (time-based), Go uses uuid.New() (v4, random).
// This is generally acceptable and unlikely to be the source of an error.
func CreateNonceStr() string {
	return uuid.New().String()
}

// CreateMerchantOrderID generates an order ID from the Unix timestamp in SECONDS.
func CreateMerchantOrderID() string {
	// CHANGE: Was time.Now().UnixNano(), which is incorrect. Must be seconds.
	return fmt.Sprintf("%d", time.Now().Unix())
}

// SignRequestObject prepares the canonical string and signs it using RSA-PSS.
func SignRequestObject(req map[string]any, privateKeyBase64 string) (string, error) {
	// 1. Create the canonical string to be signed.
	unsignedString, err := createCanonicalString(req)
	if err != nil {
		return "", fmt.Errorf("failed to create canonical string: %w", err)
	}

	fmt.Printf("--- Canonical String to be Signed ---\n%s\n-------------------------------------\n", unsignedString)

	// 2. Sign the string using the corrected RSA-PSS function.
	signedString, err := signWithRSA_PSS(unsignedString, privateKeyBase64)
	if err != nil {
		return "", fmt.Errorf("failed to sign data with RSA-PSS: %w", err)
	}
	return signedString, nil
}

// signWithRSA_PSS signs data using the RSA-PSS padding scheme to match the Python reference.
func signWithRSA_PSS(data string, privateKeyPEM string) (string, error) {
	// CHANGE: Use standard Base64 decoding for better compatibility.
	privateKeyDER, err := base64.StdEncoding.DecodeString(privateKeyPEM)
	if err != nil {
		return "", fmt.Errorf("failed to decode private key: %w", err)
	}

	// Key parsing logic is robust and can remain as is.
	var key *rsa.PrivateKey
	pkcs8Key, err := x509.ParsePKCS8PrivateKey(privateKeyDER)
	if err == nil {
		var ok bool
		key, ok = pkcs8Key.(*rsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("key is not a valid RSA private key (parsed as pkcs8)")
		}
	} else {
		pkcs1Key, err2 := x509.ParsePKCS1PrivateKey(privateKeyDER)
		if err2 != nil {
			return "", fmt.Errorf("failed to parse private key: pkcs8 error (%v), pkcs1 error (%v)", err, err2)
		}
		key = pkcs1Key
	}

	hashed := sha256.Sum256([]byte(data))

	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	signature, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, hashed[:], opts)
	if err != nil {
		return "", fmt.Errorf("failed to sign data with PSS padding: %w", err)
	}

	signedString := base64.StdEncoding.EncodeToString(signature)
	fmt.Printf("--- Generated Signature (Base64) ---\n%s\n------------------------------------\n", signedString)
	return signedString, nil
}

func createCanonicalString(req map[string]any) (string, error) {
	flatParams := make(map[string]string)

	excludeFields := map[string]bool{
		"sign":      true,
		"sign_type": true,
	}

	for key, value := range req {
		if _, excluded := excludeFields[key]; excluded {
			continue
		}
		if key == "biz_content" {
			bizContentMap, ok := value.(map[string]any)
			if !ok {
				return "", fmt.Errorf("'biz_content' is not a valid map[string]any")
			}
			for k, v := range bizContentMap {
				flatParams[k] = fmt.Sprintf("%v", v)
			}
		} else {
			flatParams[key] = fmt.Sprintf("%v", value)
		}
	}

	// This is the full logic from the Python example: flatten, sort, join.
	keys := make([]string, 0, len(flatParams))
	for k := range flatParams {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var stringBuilder strings.Builder
	for i, k := range keys {
		if i > 0 {
			stringBuilder.WriteString("&")
		}
		stringBuilder.WriteString(k)
		stringBuilder.WriteString("=")
		stringBuilder.WriteString(flatParams[k])
	}

	return stringBuilder.String(), nil
}
