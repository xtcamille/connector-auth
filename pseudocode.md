我将为您实现一个完整的连接器双向认证系统。由于代码量较大，我将分模块实现。

## 项目结构

```
connector-auth/
├── go.mod
├── main.go
├── pkg/
│   ├── auth/
│   │   ├── protocol.go
│   │   ├── verifier.go
│   │   └── signer.go
│   ├── crypto/
│   │   ├── keys.go
│   │   ├── signatures.go
│   │   └── kdf.go
│   ├── tls/
│   │   ├── manager.go
│   │   └── certificate.go
│   └── models/
│       ├── credentials.go
│       ├── messages.go
│       └── types.go
└── cmd/
    ├── connector-a/
    │   └── main.go
    └── connector-b/
        └── main.go
```

## 1. 核心数据结构定义

**pkg/models/types.go**

```go
package models

import (
	"time"
)

// DID 分布式身份标识
type DID string

// 可验证凭证
type VerifiableCredential struct {
	ID           string                 `json:"id"`
	Issuer       DID                    `json:"issuer"`
	Subject      DID                    `json:"subject"`
	IssuanceDate time.Time              `json:"issuanceDate"`
	Expiration   time.Time              `json:"expiration,omitempty"`
	Context      []string               `json:"@context"`
	Type         []string               `json:"type"`
	CredentialSubject map[string]interface{} `json:"credentialSubject"`
	Proof        Proof                  `json:"proof"`
}

// 身份授权凭证
type AuthorizationCredential struct {
	ID              string    `json:"id"`
	Issuer          DID       `json:"issuer"` // 用户DID
	Subject         DID       `json:"subject"` // 连接器DID
	IssuanceDate    time.Time `json:"issuanceDate"`
	ExpirationDate  time.Time `json:"expirationDate"`
	Permissions     []string  `json:"permissions"`
	ResourceScope   string    `json:"resourceScope"`
	MaxDataVolume   string    `json:"maxDataVolume,omitempty"`
	TLSBinding      TLSBinding `json:"tlsBinding,omitempty"`
	Proof           Proof     `json:"proof"`
}

// TLS证书绑定信息
type TLSBinding struct {
	CertificateThumbprint string    `json:"certificateThumbprint"`
	SubjectDN            string    `json:"subjectDN"`
	ValidityPeriod       TimeRange `json:"validityPeriod"`
}

// 时间范围
type TimeRange struct {
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
}

// 数字签名证明
type Proof struct {
	Type               string `json:"type"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	SignatureValue     string `json:"signatureValue"`
}

// 密钥对
type KeyPair struct {
	PrivateKey []byte `json:"privateKey"`
	PublicKey  []byte `json:"publicKey"`
	KeyID      string `json:"keyId"`
}
```

**pkg/models/messages.go**

```go
package models

import (
	"time"
)

// 身份验证请求
type AuthRequest struct {
	// 身份标识
	DIDConnector DID `json:"did_connector"`
	DIDUser      DID `json:"did_user"`
	DIDTarget    DID `json:"did_target"`

	// 凭证信息
	VCConnector VerifiableCredential    `json:"vc_connector"`
	AACUser     AuthorizationCredential `json:"aac_user"`

	// 挑战参数
	Nonce               string    `json:"nonce"`
	Timestamp           time.Time `json:"timestamp"`
	CertThumbprint      string    `json:"cert_thumbprint"`

	// 签名
	SignatureUser       string `json:"sig_user"`
	SignatureConnector  string `json:"sig_connector"`
}

// 认证响应
type AuthResponse struct {
	// 身份标识
	DIDConnector DID `json:"did_connector"`
	DIDUser      DID `json:"did_user"`
	DIDTarget    DID `json:"did_target"`

	// 凭证信息
	VCConnector VerifiableCredential    `json:"vc_connector"`
	AACUser     AuthorizationCredential `json:"aac_user"`

	// 挑战响应参数
	NonceB          string    `json:"nonce_b"`
	Timestamp       time.Time `json:"timestamp"`
	NonceA          string    `json:"nonce_a"` // 回显A的nonce
	CertThumbprint  string    `json:"cert_thumbprint"`

	// 签名
	SignatureUser      string `json:"sig_user"`
	SignatureConnector string `json:"sig_connector"`
}

// 最终确认
type FinalConfirmation struct {
	NonceA     string    `json:"nonce_a"`
	NonceB     string    `json:"nonce_b"`
	SessionKeyID string  `json:"session_key_id"`
	Timestamp  time.Time `json:"timestamp"`
	Signature  string    `json:"signature"`
}

// 会话密钥
type SessionKey struct {
	KeyID      string `json:"key_id"`
	Key        []byte `json:"key"`
	Algorithm  string `json:"algorithm"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}
```

## 2. 加密和签名模块

**pkg/crypto/keys.go**

```go
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
```

**pkg/crypto/signatures.go**

```go
package crypto

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
		"did_connector":    string(didConnector),
		"did_target":       string(didTarget),
		"timestamp":        timestamp.Format(time.RFC3339),
		"nonce":            nonce,
		"aac_digest":       aacHash,
		"cert_thumbprint":  certThumbprint,
	}

	return sm.signData(signatureData, userKeyID)
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

	return sm.signData(signatureData, connectorKeyID)
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
		"did_connector":    string(didConnector),
		"did_target":       string(didTarget),
		"timestamp":        timestamp.Format(time.RFC3339),
		"nonce":            nonce,
		"aac_digest":       aacHash,
		"cert_thumbprint":  certThumbprint,
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

// 签名数据
func (sm *SignatureManager) signData(data map[string]interface{}, keyID string) (string, error) {
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
```

**pkg/crypto/kdf.go**

```go
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
```

## 3. TLS管理模块

**pkg/tls/certificate.go**

```go
package tls

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"time"
)

// CertificateManager 证书管理器
type CertificateManager struct {
	certPool *x509.CertPool
}

func NewCertificateManager() *CertificateManager {
	pool := x509.NewCertPool()
	return &CertificateManager{
		certPool: pool,
	}
}

// AddRootCA 添加根证书
func (cm *CertificateManager) AddRootCA(certPEM []byte) error {
	if ok := cm.certPool.AppendCertsFromPEM(certPEM); !ok {
		return fmt.Errorf("failed to append root CA certificate")
	}
	return nil
}

// CalculateThumbprint 计算证书指纹
func (cm *CertificateManager) CalculateThumbprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}

// VerifyCertificate 验证证书
func (cm *CertificateManager) VerifyCertificate(cert *x509.Certificate) error {
	opts := x509.VerifyOptions{
		Roots: cm.certPool,
		CurrentTime: time.Now(),
	}

	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}

	// 检查证书是否在有效期内
	if time.Now().Before(cert.NotBefore) {
		return fmt.Errorf("certificate is not yet valid")
	}
	if time.Now().After(cert.NotAfter) {
		return fmt.Errorf("certificate has expired")
	}

	return nil
}

// ExtractPeerCertificate 从TLS连接提取对等方证书
func (cm *CertificateManager) ExtractPeerCertificate(conn *tls.Conn) (*x509.Certificate, error) {
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificates found")
	}

	// 返回叶证书（第一个证书）
	return state.PeerCertificates[0], nil
}

// GetTLSConfig 获取TLS配置
func (cm *CertificateManager) GetTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load key pair: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      cm.certPool,
		ClientCAs:    cm.certPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}, nil
}
```

## 4. 认证协议核心逻辑

**pkg/auth/protocol.go**

```go
package auth

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"time"

	"connector-auth/pkg/crypto"
	"connector-auth/pkg/models"
	"connector-auth/pkg/tls"
)

// AuthProtocol 认证协议
type AuthProtocol struct {
	signatureManager *crypto.SignatureManager
	kdfManager       *crypto.KDFManager
	certManager      *tls.CertificateManager
	nonceCache       *NonceCache
}

func NewAuthProtocol(sm *crypto.SignatureManager, km *crypto.KDFManager, cm *tls.CertificateManager) *AuthProtocol {
	return &AuthProtocol{
		signatureManager: sm,
		kdfManager:       km,
		certManager:      cm,
		nonceCache:       NewNonceCache(),
	}
}

// CreateAuthRequest 创建身份验证请求
func (ap *AuthProtocol) CreateAuthRequest(
	didConnector, didUser, didTarget models.DID,
	vcConnector models.VerifiableCredential,
	aacUser models.AuthorizationCredential,
	tlsConn *tls.Conn,
	userKeyID, connectorKeyID string,
) (*models.AuthRequest, error) {

	// 从TLS连接获取证书指纹
	peerCert, err := ap.certManager.ExtractPeerCertificate(tlsConn)
	if err != nil {
		return nil, fmt.Errorf("failed to extract peer certificate: %w", err)
	}

	certThumbprint := ap.certManager.CalculateThumbprint(peerCert)

	// 生成挑战参数
	nonce := generateNonce()
	timestamp := time.Now()

	// 创建用户签名
	userSig, err := ap.signatureManager.CreateUserSignature(
		didConnector, didTarget, timestamp, nonce, aacUser, certThumbprint, userKeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to create user signature: %w", err)
	}

	// 创建连接器签名
	connectorSig, err := ap.signatureManager.CreateConnectorSignature(
		didConnector, didTarget, timestamp, nonce, userSig, certThumbprint, connectorKeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to create connector signature: %w", err)
	}

	// 构造认证请求
	authRequest := &models.AuthRequest{
		DIDConnector:        didConnector,
		DIDUser:             didUser,
		DIDTarget:           didTarget,
		VCConnector:         vcConnector,
		AACUser:             aacUser,
		Nonce:               nonce,
		Timestamp:           timestamp,
		CertThumbprint:      certThumbprint,
		SignatureUser:       userSig,
		SignatureConnector:  connectorSig,
	}

	return authRequest, nil
}

// VerifyAuthRequest 验证身份验证请求
func (ap *AuthProtocol) VerifyAuthRequest(
	request *models.AuthRequest,
	tlsConn *tls.Conn,
	userPublicKey, connectorPublicKey interface{},
) error {

	// 1. TLS证书验证
	if err := ap.verifyTLSCertificate(tlsConn, request.CertThumbprint); err != nil {
		return fmt.Errorf("TLS certificate verification failed: %w", err)
	}

	// 2. 凭证验证
	if err := ap.verifyCredentials(request); err != nil {
		return fmt.Errorf("credentials verification failed: %w", err)
	}

	// 3. 身份绑定验证
	if err := ap.verifyIdentityBinding(request); err != nil {
		return fmt.Errorf("identity binding verification failed: %w", err)
	}

	// 4. 签名验证
	if err := ap.verifyRequestSignatures(request, userPublicKey, connectorPublicKey); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	// 5. 安全检查
	if err := ap.performSecurityChecks(request); err != nil {
		return fmt.Errorf("security checks failed: %w", err)
	}

	// 缓存nonce防止重放
	ap.nonceCache.Add(request.Nonce, request.Timestamp)

	return nil
}

// CreateAuthResponse 创建认证响应
func (ap *AuthProtocol) CreateAuthResponse(
	request *models.AuthRequest,
	didConnector, didUser models.DID,
	vcConnector models.VerifiableCredential,
	aacUser models.AuthorizationCredential,
	tlsConn *tls.Conn,
	userKeyID, connectorKeyID string,
) (*models.AuthResponse, error) {

	// 从TLS连接获取证书指纹
	peerCert, err := ap.certManager.ExtractPeerCertificate(tlsConn)
	if err != nil {
		return nil, fmt.Errorf("failed to extract peer certificate: %w", err)
	}

	certThumbprint := ap.certManager.CalculateThumbprint(peerCert)

	// 生成挑战参数
	nonceB := generateNonce()
	timestamp := time.Now()

	// 创建用户签名
	userSig, err := ap.signatureManager.CreateUserSignature(
		didConnector, request.DIDConnector, timestamp, request.Nonce, aacUser, certThumbprint, userKeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to create user signature: %w", err)
	}

	// 创建连接器签名
	connectorSig, err := ap.signatureManager.CreateConnectorSignature(
		didConnector, request.DIDConnector, timestamp, request.Nonce, userSig, certThumbprint, connectorKeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to create connector signature: %w", err)
	}

	// 构造认证响应
	authResponse := &models.AuthResponse{
		DIDConnector:        didConnector,
		DIDUser:             didUser,
		DIDTarget:           request.DIDConnector,
		VCConnector:         vcConnector,
		AACUser:             aacUser,
		NonceB:              nonceB,
		Timestamp:           timestamp,
		NonceA:              request.Nonce,
		CertThumbprint:      certThumbprint,
		SignatureUser:       userSig,
		SignatureConnector:  connectorSig,
	}

	return authResponse, nil
}

// VerifyAuthResponse 验证认证响应
func (ap *AuthProtocol) VerifyAuthResponse(
	response *models.AuthResponse,
	originalNonce string,
	tlsConn *tls.Conn,
	userPublicKey, connectorPublicKey interface{},
) error {

	// 1. TLS证书验证
	if err := ap.verifyTLSCertificate(tlsConn, response.CertThumbprint); err != nil {
		return fmt.Errorf("TLS certificate verification failed: %w", err)
	}

	// 2. 验证nonce回显
	if response.NonceA != originalNonce {
		return fmt.Errorf("nonce echo mismatch: expected %s, got %s", originalNonce, response.NonceA)
	}

	// 3. 凭证验证
	if err := ap.verifyResponseCredentials(response); err != nil {
		return fmt.Errorf("credentials verification failed: %w", err)
	}

	// 4. 签名验证
	if err := ap.verifyResponseSignatures(response, userPublicKey, connectorPublicKey); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	// 5. 安全检查
	if err := ap.performResponseSecurityChecks(response); err != nil {
		return fmt.Errorf("security checks failed: %w", err)
	}

	return nil
}

// CreateFinalConfirmation 创建最终确认
func (ap *AuthProtocol) CreateFinalConfirmation(
	nonceA, nonceB string,
	tlsMasterSecret []byte,
	connectorKeyID string,
) (*models.FinalConfirmation, *models.SessionKey, error) {

	// 派生会话密钥
	sessionKey, keyID, err := ap.kdfManager.DeriveSessionKey(nonceA, nonceB, tlsMasterSecret, "connector-session-key")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive session key: %w", err)
	}

	timestamp := time.Now()

	// 创建确认签名
	confirmationData := map[string]interface{}{
		"nonce_a":        nonceA,
		"nonce_b":        nonceB,
		"session_key_id": keyID,
		"timestamp":      timestamp.Format(time.RFC3339),
	}

	signature, err := ap.signatureManager.signData(confirmationData, connectorKeyID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign final confirmation: %w", err)
	}

	// 构造最终确认
	confirmation := &models.FinalConfirmation{
		NonceA:       nonceA,
		NonceB:       nonceB,
		SessionKeyID: keyID,
		Timestamp:    timestamp,
		Signature:    signature,
	}

	// 构造会话密钥
	sessionKeyObj := &models.SessionKey{
		KeyID:     keyID,
		Key:       sessionKey,
		Algorithm: "AES-256-GCM",
		CreatedAt: timestamp,
		ExpiresAt: timestamp.Add(24 * time.Hour), // 24小时有效期
	}

	return confirmation, sessionKeyObj, nil
}

// 辅助方法
func (ap *AuthProtocol) verifyTLSCertificate(tlsConn *tls.Conn, expectedThumbprint string) error {
	peerCert, err := ap.certManager.ExtractPeerCertificate(tlsConn)
	if err != nil {
		return err
	}

	// 验证证书
	if err := ap.certManager.VerifyCertificate(peerCert); err != nil {
		return err
	}

	// 验证指纹匹配
	actualThumbprint := ap.certManager.CalculateThumbprint(peerCert)
	if actualThumbprint != expectedThumbprint {
		return fmt.Errorf("certificate thumbprint mismatch: expected %s, got %s", expectedThumbprint, actualThumbprint)
	}

	return nil
}

func (ap *AuthProtocol) verifyCredentials(request *models.AuthRequest) error {
	// 验证VC有效性
	if request.VCConnector.Expiration.Before(time.Now()) {
		return fmt.Errorf("connector VC has expired")
	}

	// 验证AAC有效性
	if request.AACUser.ExpirationDate.Before(time.Now()) {
		return fmt.Errorf("user AAC has expired")
	}

	// 验证权限范围
	if len(request.AACUser.Permissions) == 0 {
		return fmt.Errorf("user AAC has no permissions")
	}

	return nil
}

func (ap *AuthProtocol) verifyIdentityBinding(request *models.AuthRequest) error {
	// 验证AAC授权对象与连接器DID一致
	if string(request.AACUser.Subject) != string(request.DIDConnector) {
		return fmt.Errorf("AAC subject does not match connector DID")
	}

	// 这里可以添加VC中TLS证书指纹的验证
	// 假设VC的credentialSubject中包含tlsBinding信息

	return nil
}

func (ap *AuthProtocol) verifyRequestSignatures(request *models.AuthRequest, userPubKey, connectorPubKey interface{}) error {
	// 验证用户签名
	userSigValid, err := ap.signatureManager.VerifyUserSignature(
		request.SignatureUser,
		request.DIDConnector, request.DIDTarget,
		request.Timestamp, request.Nonce,
		request.AACUser, request.CertThumbprint,
		userPubKey.(*ecdsa.PublicKey),
	)
	if err != nil {
		return err
	}
	if !userSigValid {
		return fmt.Errorf("user signature verification failed")
	}

	// 验证连接器签名
	connectorSigValid, err := ap.signatureManager.VerifyConnectorSignature(
		request.SignatureConnector,
		request.DIDConnector, request.DIDTarget,
		request.Timestamp, request.Nonce,
		request.SignatureUser, request.CertThumbprint,
		connectorPubKey.(*ecdsa.PublicKey),
	)
	if err != nil {
		return err
	}
	if !connectorSigValid {
		return fmt.Errorf("connector signature verification failed")
	}

	return nil
}

func (ap *AuthProtocol) performSecurityChecks(request *models.AuthRequest) error {
	// 检查时间戳新鲜度（5分钟窗口）
	if time.Since(request.Timestamp) > 5*time.Minute {
		return fmt.Errorf("timestamp is too old")
	}

	// 检查nonce是否重复使用
	if ap.nonceCache.Exists(request.Nonce) {
		return fmt.Errorf("nonce has been reused")
	}

	return nil
}

// 生成随机nonce
func generateNonce() string {
	return fmt.Sprintf("%x", make([]byte, 16)) // 简化实现
}

// NonceCache nonce缓存
type NonceCache struct {
	cache map[string]time.Time
}

func NewNonceCache() *NonceCache {
	return &NonceCache{
		cache: make(map[string]time.Time),
	}
}

func (nc *NonceCache) Add(nonce string, timestamp time.Time) {
	nc.cache[nonce] = timestamp
}

func (nc *NonceCache) Exists(nonce string) bool {
	_, exists := nc.cache[nonce]
	return exists
}

// 响应验证的类似方法...
func (ap *AuthProtocol) verifyResponseCredentials(response *models.AuthResponse) error {
	// 实现类似的凭证验证逻辑
	return nil
}

func (ap *AuthProtocol) verifyResponseSignatures(response *models.AuthResponse, userPubKey, connectorPubKey interface{}) error {
	// 实现类似的签名验证逻辑
	return nil
}

func (ap *AuthProtocol) performResponseSecurityChecks(response *models.AuthResponse) error {
	// 实现类似的安全检查逻辑
	return nil
}
```

## 5. 主程序示例

**cmd/connector-a/main.go**

```go
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"

	"connector-auth/pkg/auth"
	"connector-auth/pkg/crypto"
	"connector-auth/pkg/models"
	"connector-auth/pkg/tls"
)

func main() {
	// 初始化各个管理器
	keyManager := crypto.NewKeyManager()
	signatureManager := crypto.NewSignatureManager(keyManager)
	kdfManager := crypto.NewKDFManager()
	certManager := tls.NewCertificateManager()

	// 创建认证协议实例
	authProtocol := auth.NewAuthProtocol(signatureManager, kdfManager, certManager)

	// 生成密钥对
	userKeyPair, err := keyManager.GenerateKeyPair("user-alice")
	if err != nil {
		log.Fatal("Failed to generate user key pair:", err)
	}

	connectorKeyPair, err := keyManager.GenerateKeyPair("connector-a")
	if err != nil {
		log.Fatal("Failed to generate connector key pair:", err)
	}

	// 建立TLS连接
	conn, err := connectToConnectorB()
	if err != nil {
		log.Fatal("Failed to connect to connector B:", err)
	}
	defer conn.Close()

	// 创建认证请求
	authRequest, err := authProtocol.CreateAuthRequest(
		models.DID("did:example:connector:a"),
		models.DID("did:example:alice"),
		models.DID("did:example:connector:b"),
		createSampleVC(),
		createSampleAAC(),
		conn.(*tls.Conn),
		"user-alice",
		"connector-a",
	)
	if err != nil {
		log.Fatal("Failed to create auth request:", err)
	}

	// 发送认证请求
	if err := sendAuthRequest(conn, authRequest); err != nil {
		log.Fatal("Failed to send auth request:", err)
	}

	// 接收并验证认证响应
	authResponse, err := receiveAuthResponse(conn)
	if err != nil {
		log.Fatal("Failed to receive auth response:", err)
	}

	// 验证响应
	if err := authProtocol.VerifyAuthResponse(authResponse, authRequest.Nonce, conn
```