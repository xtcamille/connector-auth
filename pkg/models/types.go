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
