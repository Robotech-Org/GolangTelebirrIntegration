package GolangTelebirrIntegration

import (
	"github.com/Robotech-Org/GolangTelebirrIntegration/ApplyFabricToken"
	"github.com/Robotech-Org/GolangTelebirrIntegration/AuthToken"
	"github.com/Robotech-Org/GolangTelebirrIntegration/CreateOrderService"
)

var (
	NewApplyFabricTokenService = ApplyFabricToken.NewApplyFabricTokenService
	NewAuthenticationService   = AuthToken.NewAuthenticationService
	NewCreateOrderService      = CreateOrderService.NewCreateOrderService
)
