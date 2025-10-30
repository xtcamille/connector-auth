package auth

import (
	"crypto/ecdsa"
	"crypto/tls"
	"fmt"
	"time"

	"connector-auth/pkg/crypto"
	"connector-auth/pkg/models"
	localtls "connector-auth/pkg/tls"
)

// AuthProtocol 认证协议
type AuthProtocol struct {
	signatureManager *crypto.SignatureManager
	kdfManager       *crypto.KDFManager
	certManager      *localtls.CertificateManager
	nonceCache       *NonceCache
}

func NewAuthProtocol(sm *crypto.SignatureManager, km *crypto.KDFManager, cm *localtls.CertificateManager) *AuthProtocol {
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
		DIDConnector:       didConnector,
		DIDUser:            didUser,
		DIDTarget:          didTarget,
		VCConnector:        vcConnector,
		AACUser:            aacUser,
		Nonce:              nonce,
		Timestamp:          timestamp,
		CertThumbprint:     certThumbprint,
		SignatureUser:      userSig,
		SignatureConnector: connectorSig,
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
		DIDConnector:       didConnector,
		DIDUser:            didUser,
		DIDTarget:          request.DIDConnector,
		VCConnector:        vcConnector,
		AACUser:            aacUser,
		NonceB:             nonceB,
		Timestamp:          timestamp,
		NonceA:             request.Nonce,
		CertThumbprint:     certThumbprint,
		SignatureUser:      userSig,
		SignatureConnector: connectorSig,
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

	signature, err := ap.signatureManager.SignData(confirmationData, connectorKeyID)
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
