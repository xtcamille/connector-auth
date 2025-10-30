package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
)

// TLSManager 负责管理TLS配置和加载证书
type TLSManager struct {
	certManager *CertificateManager
}

func NewTLSManager(cm *CertificateManager) *TLSManager {
	return &TLSManager{
		certManager: cm,
	}
}

// LoadTLSCertificates 从文件加载TLS证书和密钥
func (tm *TLSManager) LoadTLSCertificates(certFile, keyFile string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load TLS key pair: %w", err)
	}
	return cert, nil
}

// CreateTLSConfig 创建TLS配置
func (tm *TLSManager) CreateTLSConfig(cert tls.Certificate, rootCAs *x509.CertPool, clientAuth tls.ClientAuthType) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      rootCAs,
		ClientCAs:    rootCAs,
		ClientAuth:   clientAuth,
		MinVersion:   tls.VersionTLS12,
		// Custom VerifyPeerCertificate for more advanced validation if needed
	}
}

// LoadRootCA 从文件加载根CA证书
func (tm *TLSManager) LoadRootCA(caFile string) error {
	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("failed to read root CA file: %w", err)
	}

	if ok := tm.certManager.certPool.AppendCertsFromPEM(caCert); !ok {
		return fmt.Errorf("failed to append root CA certificate")
	}
	return nil
}

// StartTLSServer 启动一个简单的TLS服务器进行测试
func (tm *TLSManager) StartTLSServer(listenAddr, certFile, keyFile, caFile string) { 
	// 1. 加载根CA证书
	if err := tm.LoadRootCA(caFile); err != nil {
		log.Fatalf("Failed to load root CA: %v", err)
	}

	// 2. 加载服务器证书
	serverCert, err := tm.LoadTLSCertificates(certFile, keyFile)
	if err != nil {
		log.Fatalf("Failed to load server certificates: %v", err)
	}

	// 3. 创建TLS配置
	tlsConfig := tm.CreateTLSConfig(serverCert, tm.certManager.certPool, tls.RequireAndVerifyClientCert)

	listener, err := tls.Listen("tcp", listenAddr, tlsConfig)
	if err != nil {
		log.Fatalf("Server: listen failed: %v", err)
	}
	defer listener.Close()

	log.Printf("TLS Server listening on %s\n", listenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Server: accept failed: %v", err)
			continue
		}
		go tm.handleClientConnection(conn.(*tls.Conn))
	}
}

func (tm *TLSManager) handleClientConnection(conn *tls.Conn) {
	defer conn.Close()
	log.Printf("Server: accepted connection from %s\n", conn.RemoteAddr())

	// 提取并验证客户端证书
	peerCert, err := tm.certManager.ExtractPeerCertificate(conn)
	if err != nil {
		log.Printf("Server: failed to extract client certificate: %v", err)
		return
	}

	if err := tm.certManager.VerifyCertificate(peerCert); err != nil {
		log.Printf("Server: client certificate verification failed: %v", err)
		return
	}

	log.Printf("Server: Client certificate verified. Subject: %s\n", peerCert.Subject.CommonName)

	// 在这里可以读取数据或执行认证协议的后续步骤
	// For now, just a placeholder
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Printf("Server: failed to read from client: %v", err)
		return
	}

	log.Printf("Server: Received %d bytes from client: %s\n", n, string(buffer[:n]))

	// Example: send a response
	response := []byte("Hello from TLS server!")
	_, err = conn.Write(response)
	if err != nil {
		log.Printf("Server: failed to write to client: %v", err)
		return
	}
}
