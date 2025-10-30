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
