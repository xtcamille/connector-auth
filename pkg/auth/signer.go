package auth

import (
	"fmt"
	"time"

	"connector-auth/pkg/crypto"
	"connector-auth/pkg/models"
)

// Signer 凭证签名器接口
type Signer interface {
	SignVC(vc *models.VerifiableCredential, keyID string) error
	SignAAC(aac *models.AuthorizationCredential, keyID string) error
}

// SimpleSigner 简单凭证签名器
type SimpleSigner struct {
	signatureManager *crypto.SignatureManager
}

func NewSimpleSigner(sm *crypto.SignatureManager) *SimpleSigner {
	return &SimpleSigner{
		signatureManager: sm,
	}
}

// SignVC 签名可验证凭证
func (ss *SimpleSigner) SignVC(vc *models.VerifiableCredential, keyID string) error {
	// 模拟VC签名逻辑
	vacData := map[string]interface{}{
		"id":         vc.ID,
		"issuer":     string(vc.Issuer),
		"subject":    string(vc.Subject),
		"issuance":   vc.IssuanceDate.Format(time.RFC3339),
		"expiration": vc.Expiration.Format(time.RFC3339),
		"context":    vc.Context,
		"type":       vc.Type,
	}

	signature, err := ss.signatureManager.SignData(vacData, keyID)
	if err != nil {
		return fmt.Errorf("failed to sign VC: %w", err)
	}

	vc.Proof.SignatureValue = signature
	vc.Proof.Created = time.Now().Format(time.RFC3339)
	vc.Proof.Type = "ECDSA"
	vc.Proof.VerificationMethod = keyID

	return nil
}

// SignAAC 签名身份授权凭证
func (ss *SimpleSigner) SignAAC(aac *models.AuthorizationCredential, keyID string) error {
	// 模拟AAC签名逻辑
	aacData := map[string]interface{}{
		"id":             aac.ID,
		"issuer":         string(aac.Issuer),
		"subject":        string(aac.Subject),
		"issuance":       aac.IssuanceDate.Format(time.RFC3339),
		"expiration":     aac.ExpirationDate.Format(time.RFC3339),
		"permissions":    aac.Permissions,
		"resource_scope": aac.ResourceScope,
	}

	signature, err := ss.signatureManager.SignData(aacData, keyID)
	if err != nil {
		return fmt.Errorf("failed to sign AAC: %w", err)
	}

	aac.Proof.SignatureValue = signature
	aac.Proof.Created = time.Now().Format(time.RFC3339)
	aac.Proof.Type = "ECDSA"
	aac.Proof.VerificationMethod = keyID

	return nil
}
