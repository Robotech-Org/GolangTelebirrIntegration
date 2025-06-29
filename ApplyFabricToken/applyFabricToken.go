package ApplyFabricToken

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type ApplyFabricTokenService struct {
	BaseURL     string
	FabricAppId string
	AppSecret   string
	MerchantId  string
}

func NewApplyFabricTokenService(baseURL, fabricAppId, appSecret, merchantId string) *ApplyFabricTokenService {
	return &ApplyFabricTokenService{
		BaseURL:     baseURL,
		FabricAppId: fabricAppId,
		AppSecret:   appSecret,
		MerchantId:  merchantId,
	}
}

type TokenResponse struct {
	Token          string `json:"token"`
	EffectiveDate  string `json:"effectiveDate"`
	ExpirationDate string `json:"expirationDate"`
}

func (a *ApplyFabricTokenService) ApplyFabricToken() (string, error) {
	fullURL := a.BaseURL + "/payment/v1/token"
	payload := map[string]string{
		"appSecret": a.AppSecret,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, fullURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-APP-Key", a.FabricAppId)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: transport}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("received non-200 status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	var tokenResponse TokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return "", fmt.Errorf("failed to unmarshal response JSON: %w", err)
	}

	if tokenResponse.Token == "" {
		return "", fmt.Errorf("API returned a successful status but the fabric token was empty. Check your FabricAppId and AppSecret.")
	}

	return tokenResponse.Token, nil
}
