package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"connector-auth/pkg/models"
)

// SignatureManager 签名管理器
type SignatureManager struct {
	keyManager *KeyManager
}

func NewSignatureManager(km *KeyManager) *SignatureManager {
	return &SignatureManager{
		keyManager: km,
	}
}

// CreateUserSignature 创建用户签名
func (sm *SignatureManager) CreateUserSignature(
	didConnector, didTarget models.DID,
	timestamp time.Time,
	nonce string,
	aac models.AuthorizationCredential,
	certThumbprint string,
	userKeyID string,
) (string, error) {

	// 计算AAC摘要
	aacHash, err := sm.calculateAACHash(aac)
	if err != nil {
		return "", err
	}

	// 构造签名数据
	signatureData := map[string]interface{}{
		"did_connector":   string(didConnector),
		"did_target":      string(didTarget),
		"timestamp":       timestamp.Format(time.RFC3339),
		"nonce":           nonce,
		"aac_digest":      aacHash,
		"cert_thumbprint": certThumbprint,
	}

	return sm.SignData(signatureData, userKeyID)
}

// CreateConnectorSignature 创建连接器签名
func (sm *SignatureManager) CreateConnectorSignature(
	didConnector, didTarget models.DID,
	timestamp time.Time,
	nonce string,
	userSignature string,
	certThumbprint string,
	connectorKeyID string,
) (string, error) {

	signatureData := map[string]interface{}{
		"did_connector":   string(didConnector),
		"did_target":      string(didTarget),
		"timestamp":       timestamp.Format(time.RFC3339),
		"nonce":           nonce,
		"user_signature":  userSignature,
		"cert_thumbprint": certThumbprint,
	}

	return sm.SignData(signatureData, connectorKeyID)
}

// VerifyUserSignature 验证用户签名
func (sm *SignatureManager) VerifyUserSignature(
	signature string,
	didConnector, didTarget models.DID,
	timestamp time.Time,
	nonce string,
	aac models.AuthorizationCredential,
	certThumbprint string,
	publicKey *ecdsa.PublicKey,
) (bool, error) {

	aacHash, err := sm.calculateAACHash(aac)
	if err != nil {
		return false, err
	}

	signatureData := map[string]interface{}{
		"did_connector":   string(didConnector),
		"did_target":      string(didTarget),
		"timestamp":       timestamp.Format(time.RFC3339),
		"nonce":           nonce,
		"aac_digest":      aacHash,
		"cert_thumbprint": certThumbprint,
	}

	return sm.verifySignature(signatureData, signature, publicKey)
}

// VerifyConnectorSignature 验证连接器签名
func (sm *SignatureManager) VerifyConnectorSignature(
	signature string,
	didConnector, didTarget models.DID,
	timestamp time.Time,
	nonce string,
	userSignature string,
	certThumbprint string,
	publicKey *ecdsa.PublicKey,
) (bool, error) {

	signatureData := map[string]interface{}{
		"did_connector":   string(didConnector),
		"did_target":      string(didTarget),
		"timestamp":       timestamp.Format(time.RFC3339),
		"nonce":           nonce,
		"user_signature":  userSignature,
		"cert_thumbprint": certThumbprint,
	}

	return sm.verifySignature(signatureData, signature, publicKey)
}

// 计算数据的SHA256哈希
func (sm *SignatureManager) calculateHash(data map[string]interface{}) ([]byte, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data: %w", err)
	}

	hash := sha256.Sum256(jsonData)
	return hash[:], nil
}

// 计算AAC哈希
func (sm *SignatureManager) calculateAACHash(aac models.AuthorizationCredential) (string, error) {
	// 简化处理：使用ID和权限计算哈希
	hashData := map[string]interface{}{
		"id":          aac.ID,
		"permissions": aac.Permissions,
		"scope":       aac.ResourceScope,
		"expires":     aac.ExpirationDate.Format(time.RFC3339),
	}

	hashBytes, err := sm.calculateHash(hashData)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(hashBytes), nil
}

// SignData 签名数据
func (sm *SignatureManager) SignData(data map[string]interface{}, keyID string) (string, error) {
	hashBytes, err := sm.calculateHash(data)
	if err != nil {
		return "", err
	}

	privateKey, err := sm.keyManager.GetPrivateKey(keyID)
	if err != nil {
		return "", err
	}

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashBytes)
	if err != nil {
		return "", fmt.Errorf("failed to sign data: %w", err)
	}

	// 将r和s组合成签名
	signature := append(r.Bytes(), s.Bytes()...)
	return hex.EncodeToString(signature), nil
}

// 验证签名
func (sm *SignatureManager) verifySignature(data map[string]interface{}, signature string, publicKey *ecdsa.PublicKey) (bool, error) {
	hashBytes, err := sm.calculateHash(data)
	if err != nil {
		return false, err
	}

	signatureBytes, err := hex.DecodeString(signature)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %w", err)
	}

	if len(signatureBytes) != 64 {
		return false, fmt.Errorf("invalid signature length: %d", len(signatureBytes))
	}

	rBytes := signatureBytes[:32]
	sBytes := signatureBytes[32:]

	var r, s big.Int
	r.SetBytes(rBytes)
	s.SetBytes(sBytes)

	return ecdsa.Verify(publicKey, hashBytes, &r, &s), nil
}
