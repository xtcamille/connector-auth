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
