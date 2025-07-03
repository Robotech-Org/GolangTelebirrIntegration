package utils

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

func CreateTimestamp() string {
	return fmt.Sprintf("%d", time.Now().Unix())
}

func CreateNonceStr() string {
	return uuid.New().String()
}

func CreateMerchantOrderID() string {
	return fmt.Sprintf("%d", time.Now().Unix())
}

func SignRequestObject(req map[string]any, privateKeyBase64 string) (string, error) {
	unsignedString, err := createCanonicalString(req)
	if err != nil {
		return "", fmt.Errorf("failed to create canonical string: %w", err)
	}

	signedString, err := signWithRSA_PSS(unsignedString, privateKeyBase64)
	if err != nil {
		return "", fmt.Errorf("failed to sign data with RSA-PSS: %w", err)
	}
	return signedString, nil
}

func signWithRSA_PSS(data string, privateKeyPEM string) (string, error) {
	privateKeyDER, err := base64.StdEncoding.DecodeString(privateKeyPEM)
	if err != nil {
		return "", fmt.Errorf("failed to decode private key: %w", err)
	}

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

func VerifyNotificationSignature(notificationData map[string]any, telebirrPublicKeyPEM string) error {
	sign, ok := notificationData["sign"].(string)
	if !ok || sign == "" {
		return errors.New("signature is missing from notification data")
	}
	delete(notificationData, "sign")
	delete(notificationData, "sign_type")

	keys := make([]string, 0, len(notificationData))
	for k := range notificationData {
		if v := notificationData[k]; v != nil && v != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	var builder strings.Builder
	for i, k := range keys {
		val := fmt.Sprintf("%v", notificationData[k])
		builder.WriteString(k)
		builder.WriteString("=")
		builder.WriteString(val)
		if i < len(keys)-1 {
			builder.WriteString("&")
		}
	}
	canonicalString := builder.String()
	fmt.Printf("Canonical String for Verification: %s\n", canonicalString)

	block, _ := pem.Decode([]byte(telebirrPublicKeyPEM))
	if block == nil {
		return errors.New("failed to parse PEM block containing the public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return errors.New("key is not a valid RSA public key")
	}

	decodedSign, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return fmt.Errorf("failed to decode base64 signature: %w", err)
	}

	hashed := sha256.Sum256([]byte(canonicalString))

	err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hashed[:], decodedSign)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

func StructToMap(data any) (map[string]any, error) {
	out := make(map[string]any)
	v := reflect.ValueOf(data)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	if v.Kind() != reflect.Struct {
		return nil, fmt.Errorf("StructToMap only accepts structs; got %T", v)
	}

	typ := v.Type()
	for i := 0; i < v.NumField(); i++ {
		fi := typ.Field(i)
		jsonTag := fi.Tag.Get("json")
		if jsonTag != "" && jsonTag != "-" {
			// Use the json tag name as the map key
			out[jsonTag] = v.Field(i).Interface()
		}
	}
	return out, nil
}
