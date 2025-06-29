package CreateOrderService

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/Robotech-Org/GolangTelebirrIntegration/ApplyFabricToken"
	"github.com/Robotech-Org/GolangTelebirrIntegration/utils"
)

type PreOrderResponse struct {
	Result     string             `json:"result"`
	Code       string             `json:"code"`
	Msg        string             `json:"msg"`
	BizContent PreOrderBizContent `json:"biz_content"`
	NonceStr   string             `json:"nonce_str"`
	Sign       string             `json:"sign"`
	SignType   string             `json:"sign_type"`
}

type PreOrderBizContent struct {
	PrepayID     string `json:"prepay_id"`
	MerchOrderID string `json:"merch_order_id"`
}

// ===CreateOrderService===
type CreateOrderService struct {
	BaseURL                 string
	WebBaseURL              string
	FabricID                string
	MerchantID              string
	MerchantCode            string
	NotifyPath              string
	PrivateKeyPEM           string
	ReturnURL               string
	ApplyFabricTokenService *ApplyFabricToken.ApplyFabricTokenService
}

func NewCreateOrderService(
	baseURL, webBaseURL, fabricID, merchantID, merchantCode, notifyPath, privateKeyPEM, returnURL string,
	applyFabricTokenService *ApplyFabricToken.ApplyFabricTokenService,
) *CreateOrderService {
	return &CreateOrderService{
		BaseURL:                 baseURL,
		WebBaseURL:              webBaseURL,
		FabricID:                fabricID,
		MerchantID:              merchantID,
		MerchantCode:            merchantCode,
		NotifyPath:              notifyPath,
		PrivateKeyPEM:           privateKeyPEM,
		ReturnURL:               returnURL,
		ApplyFabricTokenService: applyFabricTokenService,
	}
}

func (s *CreateOrderService) CreateOrder(title, amount string) (string, error) {
	fabricToken, err := s.ApplyFabricTokenService.ApplyFabricToken()
	if err != nil {
		return "", fmt.Errorf("failed to get fabric token for order creation: %w", err)
	}

	preOrderResponse, err := s.requestCreateOrder(fabricToken, title, amount)
	if err != nil {
		return "", fmt.Errorf("failed to create pre-order: %w", err)
	}

	prepayID := preOrderResponse.BizContent.PrepayID
	if prepayID == "" {
		return "", fmt.Errorf("prepay_id not found in pre-order response")
	}
	rawRequest, err := s.createWebCheckoutRawRequest(prepayID)
	if err != nil {
		return "", fmt.Errorf("failed to create raw request: %w", err)
	}

	return rawRequest, nil
}

func (s *CreateOrderService) requestCreateOrder(fabricToken, title, amount string) (*PreOrderResponse, error) {
	fullURL := s.BaseURL + "/payment/v1/merchant/preOrder"

	payload, err := s.createRequestObject(title, amount)
	if err != nil {
		return nil, err
	}

	requestData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal pre-order payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, fullURL, bytes.NewBuffer(requestData))
	if err != nil {
		return nil, fmt.Errorf("failed to create pre-order request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-APP-Key", s.FabricID)
	req.Header.Set("Authorization", fabricToken)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send pre-order request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read pre-order response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-200 status code for pre-order: %d, body: %s", resp.StatusCode, string(body))
	}

	var preOrderResp PreOrderResponse
	if err := json.Unmarshal(body, &preOrderResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pre-order response: %w", err)
	}

	if preOrderResp.Code != "0" {
		return nil, fmt.Errorf("pre-order API error: code %s, message: %s", preOrderResp.Code, preOrderResp.Msg)
	}

	return &preOrderResp, nil
}

func (s *CreateOrderService) createRequestObject(title, amount string) (map[string]any, error) {
	req := map[string]any{
		"nonce_str": utils.CreateNonceStr(),
		"method":    "payment.preorder",
		"timestamp": utils.CreateTimestamp(),
		"version":   "1.0",
	}

	biz := map[string]any{
		"notify_url":            "https://www.google.com",
		"redirect_url":          s.ReturnURL,
		"trade_type":            "Checkout",
		"appid":                 s.MerchantID,
		"merch_code":            s.MerchantCode,
		"merch_order_id":        utils.CreateMerchantOrderID(),
		"title":                 title,
		"total_amount":          amount,
		"trans_currency":        "ETB",
		"timeout_express":       "120m",
		"business_type":         "BuyGoods",
		"payee_identifier":      s.MerchantCode,
		"payee_identifier_type": "04",
		"payee_type":            "5000",
		"callback_info":         "From Go Backend",
	}

	req["biz_content"] = biz

	signedString, err := utils.SignRequestObject(req, s.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("error signing pre-order object: %w", err)
	}

	req["sign"] = signedString
	req["sign_type"] = "SHA256WithRSA"

	return req, nil
}
func (s *CreateOrderService) createWebCheckoutRawRequest(prepayID string) (string, error) {
	maps := map[string]any{
		"appid":      s.MerchantID,
		"merch_code": s.MerchantCode,
		"nonce_str":  utils.CreateNonceStr(),
		"prepay_id":  prepayID,
		"timestamp":  utils.CreateTimestamp(),
	}

	sign, err := utils.SignRequestObject(maps, s.PrivateKeyPEM)
	if err != nil {
		return "", fmt.Errorf("error signing web checkout data: %w", err)
	}
	encodedSign := url.QueryEscape(sign)

	rawRequest := fmt.Sprintf(
		"%sappid=%s&merch_code=%s&nonce_str=%s&prepay_id=%s&timestamp=%s&sign=%s&sign_type=SHA256WithRSA&version=1.0&trade_type=Checkout",
		s.WebBaseURL,
		maps["appid"],
		maps["merch_code"],
		maps["nonce_str"],
		maps["prepay_id"],
		maps["timestamp"],
		encodedSign,
	)

	return rawRequest, nil
}
