# Telebirr Integration for Go

This Go module provides a client library for integrating with the Telebirr payment gateway. It simplifies common operations such as applying for a fabric token, requesting an authentication token, and creating payment orders.

## Table of Contents

*   [Features](#features)
*   [Installation](#installation)
*   [Configuration](#configuration)
*   [Usage Examples](#usage-examples)
    *   [Initializing Services](#initializing-services)
    *   [Applying for a Fabric Token](#applying-for-a-fabric-token)
    *   [Requesting an Authentication Token](#requesting-an-authentication-token)
    *   [Creating a Payment Order](#creating-a-payment-order)
*   [Error Handling](#error-handling)
*   [Dependencies](#dependencies)
*   [Contributing](#contributing)
*   [License](#license)

## Features

*   **Fabric Token Management**: Obtain and manage the `Authorization` token required for subsequent API calls.
*   **Authentication Token**: Securely request an `access_token` for in-app payments.
*   **Order Creation**: Create pre-orders for goods, generating a payment URL for user checkout.
*   **RSA-PSS Signature**: Handles cryptographic signing of requests using SHA256WithRSA-PSS, as required by Telebirr.

## Installation

To include this library in your Go project, use `go get`:

```bash
go get github.com/Robotech-Org/GolangTelebirrIntegration
```

## Configuration

Before using the services, you need to set up several parameters obtained from your Telebirr merchant account. It is highly recommended to manage these securely using environment variables or a configuration management system, rather than hardcoding them.

The following parameters are required:

*   `TELEBIRR_BASE_URL`: The base URL for the Telebirr API (e.g., `https://openapi.telebirr.com`).
*   `TELEBIRR_WEB_BASE_URL`: The base URL for the Telebirr web checkout (e.g., `https://web.telebirr.com/wap/cashier/index`).
*   `TELEBIRR_FABRIC_APP_ID`: Your Telebirr Fabric application ID (`X-APP-Key`).
*   `TELEBIRR_APP_SECRET`: Your Telebirr application secret.
*   `TELEBIRR_MERCHANT_ID`: Your Telebirr Merchant ID (appid).
*   `TELEBIRR_MERCHANT_CODE`: Your Telebirr Merchant Code (merch\_code, also referred to as Short Code).
*   `TELEBIRR_PRIVATE_KEY_PEM`: Your RSA private key, Base64 encoded, used for signing requests. This should be the PKCS#8 or PKCS#1 format.
*   `TELEBIRR_RETURN_URL`: The URL where Telebirr should redirect the user after payment completion.
*   `TELEBIRR_NOTIFY_PATH`: The notification URL endpoint for payment results (callback_url). Note: As of the current implementation, `notify_url` in `CreateOrderService` is hardcoded to `https://www.google.com`. Ensure you update this in the code to your actual notification endpoint.

Example of setting environment variables (for development/testing):

```bash
export TELEBIRR_BASE_URL="https://openapi.telebirr.com"
export TELEBIRR_WEB_BASE_URL="https://web.telebirr.com/wap/cashier/index"
export TELEBIRR_FABRIC_APP_ID="your_fabric_app_id_here"
export TELEBIRR_APP_SECRET="your_app_secret_here"
export TELEBIRR_MERCHANT_ID="your_merchant_id_here"
export TELEBIRR_MERCHANT_CODE="your_merchant_code_here"
export TELEBIRR_PRIVATE_KEY_PEM="your_base64_encoded_private_key"
export TELEBIRR_RETURN_URL="https://yourdomain.com/payment/return"
export TELEBIRR_NOTIFY_PATH="https://yourdomain.com/payment/notify" # Update this in code
```

## Usage Examples

This library provides three main services: `ApplyFabricTokenService`, `AuthenticationService`, and `CreateOrderService`.

### Initializing Services

It's recommended to initialize these services once, perhaps during your application's startup, and then inject them where needed.

```go /dev/null/main.go#L1-37
package main

import (
	"log"
	"os"

	"github.com/Robotech-Org/GolangTelebirrIntegration/ApplyFabricToken"
	"github.com/Robotech-Org/GolangTelebirrIntegration/AuthToken"
	"github.com/Robotech-Org/GolangTelebirrIntegration/CreateOrderService"
)

func main() {
	// Load configuration from environment variables
	baseURL := os.Getenv("TELEBIRR_BASE_URL")
	webBaseURL := os.Getenv("TELEBIRR_WEB_BASE_URL")
	fabricAppID := os.Getenv("TELEBIRR_FABRIC_APP_ID")
	appSecret := os.Getenv("TELEBIRR_APP_SECRET")
	merchantID := os.Getenv("TELEBIRR_MERCHANT_ID")
	merchantCode := os.Getenv("TELEBIRR_MERCHANT_CODE")
	privateKeyPEM := os.Getenv("TELEBIRR_PRIVATE_KEY_PEM")
	returnURL := os.Getenv("TELEBIRR_RETURN_URL")
	notifyPath := os.Getenv("TELEBIRR_NOTIFY_PATH") // Remember to use this in your CreateOrderService internally!

	// 1. Initialize ApplyFabricTokenService
	applyFabricTokenService := ApplyFabricToken.NewApplyFabricTokenService(
		baseURL,
		fabricAppID,
		appSecret,
		merchantID, // Merchant ID is not used by ApplyFabricTokenService currently but passed for consistency
	)

	// 2. Initialize AuthenticationService
	// Note: The 'token' parameter in NewAuthenticationService is not currently used internally.
	authenticationService := AuthToken.NewAuthenticationService(
		baseURL,
		fabricAppID,
		appSecret,
		merchantID,
		"", // placeholder for 'token' - currently not utilized in AuthToken logic
		privateKeyPEM,
		applyFabricTokenService,
	)

	// 3. Initialize CreateOrderService
	createOrderService := CreateOrderService.NewCreateOrderService(
		baseURL,
		webBaseURL,
		fabricAppID,
		merchantID,
		merchantCode,
		notifyPath,
		privateKeyPEM,
		returnURL,
		applyFabricTokenService, // This service depends on ApplyFabricTokenService
	)

	log.Println("Telebirr services initialized successfully.")

	// Example usage calls would follow here...
}
```

### Applying for a Fabric Token

The fabric token is a short-lived authorization token required for almost all subsequent Telebirr API calls. It's automatically handled internally by `AuthenticationService` and `CreateOrderService`, but you can also get it directly.

```go /dev/null/fabric_token_example.go#L1-17
package main

import (
	"log"
	"os"

	"github.com/Robotech-Org/GolangTelebirrIntegration/ApplyFabricToken"
)

func main() {
	baseURL := os.Getenv("TELEBIRR_BASE_URL")
	fabricAppID := os.Getenv("TELEBIRR_FABRIC_APP_ID")
	appSecret := os.Getenv("TELEBIRR_APP_SECRET")
	merchantID := os.Getenv("TELEBIRR_MERCHANT_ID") // Not used for this service, but common init parameter

	service := ApplyFabricToken.NewApplyFabricTokenService(baseURL, fabricAppID, appSecret, merchantID)

	token, err := service.ApplyFabricToken()
	if err != nil {
		log.Fatalf("Failed to apply for Fabric Token: %v", err)
	}
	log.Printf("Successfully obtained Fabric Token: %s", token)
}
```

### Requesting an Authentication Token

This token is typically used for in-app payment scenarios.

```go /dev/null/auth_token_example.go#L1-20
package main

import (
	"log"
	"os"

	"github.com/Robotech-Org/GolangTelebirrIntegration/ApplyFabricToken"
	"github.com/Robotech-Org/GolangTelebirrIntegration/AuthToken"
)

func main() {
	baseURL := os.Getenv("TELEBIRR_BASE_URL")
	fabricAppID := os.Getenv("TELEBIRR_FABRIC_APP_ID")
	appSecret := os.Getenv("TELEBIRR_APP_SECRET")
	merchantID := os.Getenv("TELEBIRR_MERCHANT_ID")
	privateKeyPEM := os.Getenv("TELEBIRR_PRIVATE_KEY_PEM")
	appToken := "your_app_specific_token_if_any" // This 'appToken' maps to 'access_token' in biz_content

	applyFabricTokenService := ApplyFabricToken.NewApplyFabricTokenService(baseURL, fabricAppID, appSecret, merchantID)

	service := AuthToken.NewAuthenticationService(baseURL, fabricAppID, appSecret, merchantID, "", privateKeyPEM, applyFabricTokenService)

	accessToken, err := service.AuthToken(appToken)
	if err != nil {
		log.Fatalf("Failed to get Auth Token: %v", err)
	}
	log.Printf("Successfully obtained Access Token: %s", accessToken)
}
```

### Creating a Payment Order

This is the primary function for initiating a payment flow where the user will be redirected to Telebirr's checkout page.

```go /dev/null/create_order_example.go#L1-27
package main

import (
	"log"
	"os"

	"github.com/Robotech-Org/GolangTelebirrIntegration/ApplyFabricToken"
	"github.com/Robotech-Org/GolangTelebirrIntegration/CreateOrderService"
)

func main() {
	baseURL := os.Getenv("TELEBIRR_BASE_URL")
	webBaseURL := os.Getenv("TELEBIRR_WEB_BASE_URL")
	fabricAppID := os.Getenv("TELEBIRR_FABRIC_APP_ID")
	appSecret := os.Getenv("TELEBIRR_APP_SECRET")
	merchantID := os.Getenv("TELEBIRR_MERCHANT_ID")
	merchantCode := os.Getenv("TELEBIRR_MERCHANT_CODE")
	privateKeyPEM := os.Getenv("TELEBIRR_PRIVATE_KEY_PEM")
	returnURL := os.Getenv("TELEBIRR_RETURN_URL")
	notifyPath := os.Getenv("TELEBIRR_NOTIFY_PATH") // Ensure this is reflected in the code if needed

	applyFabricTokenService := ApplyFabricToken.NewApplyFabricTokenService(baseURL, fabricAppID, appSecret, merchantID)

	service := CreateOrderService.NewCreateOrderService(
		baseURL,
		webBaseURL,
		fabricAppID,
		merchantID,
		merchantCode,
		notifyPath,
		privateKeyPEM,
		returnURL,
		applyFabricTokenService,
	)

	title := "My Awesome Product"
	amount := "100.00" // Amount as a string, e.g., "100.00" for 100 ETB

	rawRequestURL, err := service.CreateOrder(title, amount)
	if err != nil {
		log.Fatalf("Failed to create payment order: %v", err)
	}
	log.Printf("Successfully created payment order. Redirect user to: %s", rawRequestURL)
	// You would typically return this rawRequestURL to your frontend to redirect the user.
}
```

## Error Handling

All public methods in this library return an `error` type. It is crucial to check for errors after every call and handle them appropriately in your application. The errors often provide descriptive messages about what went wrong (e.g., network issues, API responses with non-200 status codes, or Telebirr specific error codes and messages).

Example:

```go /dev/null/error_handling_example.go#L1-6
result, err := someService.SomeMethod()
if err != nil {
    log.Printf("An error occurred: %v", err)
    // Handle the error (e.g., return an HTTP 500, log to monitoring system)
    return err
}
// Proceed with result
```

## Dependencies

This module depends on:

*   `github.com/google/uuid`: For generating unique identifiers.

## Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.