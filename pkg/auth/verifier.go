package auth

import (
	"fmt"
	"time"

	"connector-auth/pkg/models"
)

// Verifier 凭证验证器接口
type Verifier interface {
	VerifyVC(vc models.VerifiableCredential) error
	VerifyAAC(aac models.AuthorizationCredential) error
}

// SimpleVerifier 简单凭证验证器
type SimpleVerifier struct{}

func NewSimpleVerifier() *SimpleVerifier {
	return &SimpleVerifier{}
}

// VerifyVC 验证可验证凭证
func (sv *SimpleVerifier) VerifyVC(vc models.VerifiableCredential) error {
	// 模拟VC验证逻辑
	if vc.Expiration.Before(time.Now()) {
		return fmt.Errorf("verifiable credential has expired")
	}
	// 更多验证逻辑，例如签名、颁发者等
	return nil
}

// VerifyAAC 验证身份授权凭证
func (sv *SimpleVerifier) VerifyAAC(aac models.AuthorizationCredential) error {
	// 模拟AAC验证逻辑
	if aac.ExpirationDate.Before(time.Now()) {
		return fmt.Errorf("authorization credential has expired")
	}
	// 更多验证逻辑，例如权限范围、颁发者等
	return nil
}
