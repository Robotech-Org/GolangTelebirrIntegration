package NotificationService

type PaymentNotification struct {
	AppID               string `json:"appid"`
	NotifyTime          string `json:"notify_time"`
	MerchCode           string `json:"merch_code"`
	MerchOrderID        string `json:"merch_order_id"`
	PaymentOrderID      string `json:"payment_order_id"`
	TotalAmount         string `json:"total_amount"`
	TransactionID       string `json:"trans_id"`
	TransactionCurrency string `json:"trans_currency"`
	TradeStatus         string `json:"trade_status"`
	TransactionEndTime  string `json:"trans_end_time"`
	Sign                string `json:"sign"`
	SignType            string `json:"sign_type"`
	NotifyURL           string `json:"notify_url"`
}
