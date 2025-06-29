package AuthToken

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/Robotech-Org/GolangTelebirrIntegration/ApplyFabricToken"
	"github.com/Robotech-Org/GolangTelebirrIntegration/utils"
)

// === Auth token ===
type AuthTokenResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		AccessToken string `json:"access_token"`
	} `json:"data"`
}

type AuthenticationService struct {
	BaseURl                 string
	FabricID                string
	AppSecret               string
	MerchantID              string
	PrivateKeyPEM           string
	ApplyFabricTokenService *ApplyFabricToken.ApplyFabricTokenService
}

func NewAuthenticationService(baseURL, fabricID, appSecret, merchantID, token, privateKeyPEM string, applyFabricTokenService *ApplyFabricToken.ApplyFabricTokenService) *AuthenticationService {
	return &AuthenticationService{
		BaseURl:                 baseURL,
		FabricID:                fabricID,
		AppSecret:               appSecret,
		MerchantID:              merchantID,
		PrivateKeyPEM:           privateKeyPEM,
		ApplyFabricTokenService: applyFabricTokenService,
	}
}

func (at *AuthenticationService) AuthToken(appToken string) (string, error) {
	fabricTokenResponse, err := at.ApplyFabricTokenService.ApplyFabricToken()
	if err != nil {
		return "", fmt.Errorf("failed to get fabric token: %w", err)
	}
	fmt.Println("Successfully received Fabric Token.")

	authToken, err := at.RequestAuthToken(fabricTokenResponse, appToken)
	if err != nil {
		return "", fmt.Errorf("failed to get auth token: %w", err)
	}
	return authToken.Data.AccessToken, nil
}

func (at *AuthenticationService) RequestAuthToken(fabricTokenResponse string, appToken string) (*AuthTokenResponse, error) {
	fullURL := at.BaseURl + "/payment/v1/auth/authToken"
	payload, err := at.createRequestObject(appToken)
	if err != nil {
		return nil, fmt.Errorf("failed to create signed request object: %w", err)
	}

	requestData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request object: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, fullURL, bytes.NewBuffer(requestData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-APP-Key", at.FabricID)
	req.Header.Set("Authorization", fabricTokenResponse)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: transport}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read auth token response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-200 status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var authTokenResp AuthTokenResponse
	if err := json.Unmarshal(body, &authTokenResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal auth token response: %w", err)
	}

	if authTokenResp.Code != 0 {
		return nil, fmt.Errorf("API error: code %d, message: %s", authTokenResp.Code, authTokenResp.Msg)
	}

	return &authTokenResp, nil
}

func (at *AuthenticationService) createRequestObject(appToken string) (map[string]any, error) {
	req := map[string]any{
		"timestamp": utils.CreateTimestamp(),
		"nonce_str": utils.CreateNonceStr(),
		"method":    "payment.authtoken",
		"version":   "1.0",
	}

	biz := map[string]any{
		"access_token":  appToken,
		"trade_type":    "InApp",
		"appid":         at.MerchantID,
		"resource_type": "OpenId",
	}
	req["biz_content"] = biz

	signedString, err := utils.SignRequestObject(req, at.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("error signing request object: %w", err)
	}

	req["sign"] = signedString
	req["sign_type"] = "SHA256WithRSA"

	reqJSON, _ := json.MarshalIndent(req, "", "    ")
	fmt.Println("Request Object:", string(reqJSON))

	return req, nil
}
