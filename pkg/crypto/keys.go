package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"connector-auth/pkg/models"
)

// KeyManager 密钥管理器
type KeyManager struct {
	keys map[string]*ecdsa.PrivateKey
}

func NewKeyManager() *KeyManager {
	return &KeyManager{
		keys: make(map[string]*ecdsa.PrivateKey),
	}
}

// GenerateKeyPair 生成ECDSA密钥对
func (km *KeyManager) GenerateKeyPair(keyID string) (*models.KeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// 序列化私钥
	privKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	// 序列化公钥
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	keyPair := &models.KeyPair{
		PrivateKey: privKeyBytes,
		PublicKey:  pubKeyBytes,
		KeyID:      keyID,
	}

	// 存储到内存
	km.keys[keyID] = privateKey

	return keyPair, nil
}

// GetPrivateKey 获取私钥
func (km *KeyManager) GetPrivateKey(keyID string) (*ecdsa.PrivateKey, error) {
	privKey, exists := km.keys[keyID]
	if !exists {
		return nil, fmt.Errorf("private key not found for keyID: %s", keyID)
	}
	return privKey, nil
}

// PEM编码
func (km *KeyManager) EncodePrivateKeyPEM(keyID string) (string, error) {
	privKey, err := km.GetPrivateKey(keyID)
	if err != nil {
		return "", err
	}

	privKeyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return "", err
	}

	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privKeyBytes,
	}

	return string(pem.EncodeToMemory(block)), nil
}

func (km *KeyManager) EncodePublicKeyPEM(keyID string) (string, error) {
	privKey, err := km.GetPrivateKey(keyID)
	if err != nil {
		return "", err
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return "", err
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	return string(pem.EncodeToMemory(block)), nil
}

// ParsePublicKey 从字节数组解析公钥
func (km *KeyManager) ParsePublicKey(pubKeyBytes []byte) (*ecdsa.PublicKey, error) {
	pubKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not of type *ecdsa.PublicKey")
	}

	return ecdsaPubKey, nil
}
