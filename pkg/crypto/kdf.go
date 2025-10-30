package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/hkdf"
)

// KDFManager 密钥派生管理器
type KDFManager struct{}

func NewKDFManager() *KDFManager {
	return &KDFManager{}
}

// DeriveSessionKey 派生会话密钥
func (km *KDFManager) DeriveSessionKey(nonceA, nonceB string, tlsMasterSecret []byte, info string) ([]byte, string, error) {
	// 组合nonce作为盐
	salt := append([]byte(nonceA), []byte(nonceB)...)

	// 使用HKDF派生密钥
	hkdf := hkdf.New(sha256.New, tlsMasterSecret, salt, []byte(info))

	// 派生32字节的会话密钥
	sessionKey := make([]byte, 32)
	n, err := hkdf.Read(sessionKey)
	if err != nil {
		return nil, "", fmt.Errorf("failed to derive session key: %w", err)
	}
	if n != 32 {
		return nil, "", fmt.Errorf("invalid key length: %d", n)
	}

	// 生成密钥ID（基于密钥的哈希）
	keyID := km.generateKeyID(sessionKey, nonceA, nonceB)

	return sessionKey, keyID, nil
}

// 生成密钥ID
func (km *KDFManager) generateKeyID(key []byte, nonceA, nonceB string) string {
	data := append(key, append([]byte(nonceA), []byte(nonceB)...)...)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:16]) // 使用前16字节作为ID
}
