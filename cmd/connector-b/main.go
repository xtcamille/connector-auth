package main

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"time"

	"connector-auth/pkg/auth"
	"connector-auth/pkg/crypto"
	"connector-auth/pkg/models"
	localtls "connector-auth/pkg/tls"
)

func main() {
	// 初始化各个管理器
	keyManager := crypto.NewKeyManager()
	signatureManager := crypto.NewSignatureManager(keyManager)
	kdfManager := crypto.NewKDFManager()
	certManager := localtls.NewCertificateManager()

	// 创建认证协议实例
	authProtocol := auth.NewAuthProtocol(signatureManager, kdfManager, certManager)

	// 生成连接器密钥对
	connectorBKeyPair, err := keyManager.GenerateKeyPair("connector-b")
	if err != nil {
		log.Fatal("Failed to generate connector B key pair:", err)
	}

	// 模拟用户公钥（实际应该从DID文档或其他可信来源获取）
	userPublicKey, err := keyManager.GenerateKeyPair("user-alice-pub")
	if err != nil {
		log.Fatal("Failed to generate user alice public key:", err)
	}

	parsedUserPublicKey, err := keyManager.ParsePublicKey(userPublicKey.PublicKey)
	if err != nil {
		log.Fatal("Failed to parse user public key:", err)
	}

	parsedConnectorBPublicKey, err := keyManager.ParsePublicKey(connectorBKeyPair.PublicKey)
	if err != nil {
		log.Fatal("Failed to parse connector B public key:", err)
	}

	// 启动TLS服务器
	tlsManager := localtls.NewTLSManager(certManager)

	// 加载服务器证书
	serverCert, err := tlsManager.LoadTLSCertificates("server.crt", "server.key")
	if err != nil {
		log.Fatalf("Failed to load server certificates: %v", err)
	}

	// 加载根CA证书
	caCert, err := ioutil.ReadFile("ca.crt")
	if err != nil {
		log.Fatalf("Failed to read root CA file: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := tlsManager.CreateTLSConfig(serverCert, caCertPool, tls.RequireAndVerifyClientCert)

	listener, err := tls.Listen("tcp", ":8081", tlsConfig)
	if err != nil {
		log.Fatal("Server: listen failed:", err)
	}
	defer listener.Close()

	log.Println("Connector B started and listening on :8081")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Server: accept failed: %v", err)
			continue
		}
		go handleAuthRequest(conn.(*tls.Conn), authProtocol, parsedUserPublicKey, parsedConnectorBPublicKey, signatureManager)
	}
}

func handleAuthRequest(conn net.Conn, ap *auth.AuthProtocol, userPublicKey, connectorPublicKey *ecdsa.PublicKey, signatureManager *crypto.SignatureManager) {
	defer conn.Close()

	log.Println("Handling incoming authentication request...")

	// 接收认证请求
	authRequest, err := receiveAuthRequest(conn)
	if err != nil {
		log.Println("Failed to receive auth request:", err)
		return
	}

	// 验证认证请求
	if err := ap.VerifyAuthRequest(authRequest, conn.(*tls.Conn), userPublicKey, connectorPublicKey); err != nil {
		log.Println("Auth request verification failed:", err)
		return
	}
	log.Println("Auth request verified successfully.")

	// 模拟创建Verifiable Credential for Connector B (如果需要)
	connectorBVC := createSampleVCForConnectorB()

	// 创建凭证签名器
	signer := auth.NewSimpleSigner(signatureManager)
	if err := signer.SignVC(&connectorBVC, "connector-b"); err != nil {
		log.Fatal("Failed to sign connector B VC:", err)
	}

	// 创建认证响应
	authResponse, err := ap.CreateAuthResponse(
		authRequest,
		models.DID("did:example:connector:b"),
		authRequest.DIDUser,
		connectorBVC,
		authRequest.AACUser, // 回显用户的AAC
		conn.(*tls.Conn),
		string(authRequest.DIDUser), // 用户的keyID
		"connector-b",
	)
	if err != nil {
		log.Println("Failed to create auth response:", err)
		return
	}

	// 发送认证响应
	if err := sendAuthResponse(conn, authResponse); err != nil {
		log.Println("Failed to send auth response:", err)
		return
	}
	log.Println("Auth response sent.")

	// 这里可以处理最终确认，但为了简化，我们暂时跳过
}

// 接收认证请求
func receiveAuthRequest(conn net.Conn) (*models.AuthRequest, error) {
	decoder := json.NewDecoder(conn)

	var request models.AuthRequest
	if err := decoder.Decode(&request); err != nil {
		return nil, fmt.Errorf("failed to decode auth request: %w", err)
	}
	return &request, nil
}

// 发送认证响应
func sendAuthResponse(conn net.Conn, response *models.AuthResponse) error {
	log.Println("Sending Auth Response...")
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(response); err != nil {
		return fmt.Errorf("failed to encode auth response: %w", err)
	}
	return nil
}

// 模拟创建Verifiable Credential for Connector B
func createSampleVCForConnectorB() models.VerifiableCredential {
	return models.VerifiableCredential{
		ID:           "vc:example:connectorB:789",
		Issuer:       models.DID("did:example:issuer"),
		Subject:      models.DID("did:example:connector:b"),
		IssuanceDate: time.Now(),
		Expiration:   time.Now().Add(24 * time.Hour),
		Context:      []string{"https://www.w3.org/2018/credentials/v1"},
		Type:         []string{"VerifiableCredential", "ConnectorCredential"},
		CredentialSubject: map[string]interface{}{
			"name": "Connector B",
		},
		Proof: models.Proof{
			Type:               "Ed25519Signature2018",
			Created:            time.Now().Format(time.RFC3339),
			VerificationMethod: "did:example:issuer#key-3",
			SignatureValue:     "", // Placeholder
		},
	}
}
