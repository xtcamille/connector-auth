package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"time"

	"crypto/x509"

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

	// 创建凭证签名器
	signer := auth.NewSimpleSigner(signatureManager)

	// 生成密钥对
	userKeyPair, err := keyManager.GenerateKeyPair("user-alice")
	if err != nil {
		log.Fatal("Failed to generate user key pair:", err)
	}

	connectorKeyPair, err := keyManager.GenerateKeyPair("connector-a")
	if err != nil {
		log.Fatal("Failed to generate connector key pair:", err)
	}

	// 创建样本VC和AAC
	sampleVC := createSampleVC()
	if err := signer.SignVC(&sampleVC, "connector-a"); err != nil {
		log.Fatal("Failed to sign sample VC:", err)
	}

	sampleAAC := createSampleAAC()
	if err := signer.SignAAC(&sampleAAC, "user-alice"); err != nil {
		log.Fatal("Failed to sign sample AAC:", err)
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
		sampleVC,
		sampleAAC,
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

	parsedUserPublicKey, err := keyManager.ParsePublicKey(userKeyPair.PublicKey)
	if err != nil {
		log.Fatal("Failed to parse user public key for verification:", err)
	}

	parsedConnectorPublicKey, err := keyManager.ParsePublicKey(connectorKeyPair.PublicKey)
	if err != nil {
		log.Fatal("Failed to parse connector public key for verification:", err)
	}

	// 验证响应
	if err := authProtocol.VerifyAuthResponse(authResponse, authRequest.Nonce, conn.(*tls.Conn), parsedUserPublicKey, parsedConnectorPublicKey); err != nil {
		log.Fatal("Failed to verify auth response:", err)
	}

	log.Println("Authentication successful!")

	// 示例：创建最终确认
	// 这里需要实际的TLS Master Secret，但在模拟环境中，我们暂时跳过这部分或使用占位符。
	// 实际Master Secret需要从TLS连接中获取，Go标准库未直接暴露，需要自定义TLS握手或使用hook。
	// 为简化，我们暂时使用一个模拟的tlsMasterSecret。

	simulatedTLSMasterSecret := []byte("simulated-tls-master-secret-for-demo")
	finalConfirmation, sessionKey, err := authProtocol.CreateFinalConfirmation(
		authRequest.Nonce,
		authResponse.NonceB,
		simulatedTLSMasterSecret,
		"connector-a",
	)
	if err != nil {
		log.Fatal("Failed to create final confirmation:", err)
	}

	log.Printf("Final Confirmation: %+v\n", finalConfirmation)
	log.Printf("Derived Session Key: %+v\n", sessionKey)
}

// 模拟连接到Connector B
func connectToConnectorB() (net.Conn, error) {
	log.Println("Connecting to Connector B...")

	// 加载客户端证书
	clientCert, err := tls.LoadX509KeyPair("client.crt", "client.key")
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificates: %w", err)
	}

	// 加载根CA证书
	caCert, err := ioutil.ReadFile("ca.crt")
	if err != nil {
		return nil, fmt.Errorf("failed to read root CA file: %w", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	config := &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		RootCAs:            caCertPool,
		InsecureSkipVerify: false,       // 生产环境应为false，这里仅作演示
		ServerName:         "localhost", // 必须匹配服务器证书的Common Name
	}

	conn, err := tls.Dial("tcp", "localhost:8081", config)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to connector B via TLS: %w", err)
	}
	return conn, nil
}

// 模拟创建Verifiable Credential
func createSampleVC() models.VerifiableCredential {
	return models.VerifiableCredential{
		ID:           "vc:example:123",
		Issuer:       models.DID("did:example:issuer"),
		Subject:      models.DID("did:example:connector:a"),
		IssuanceDate: time.Now(),
		Expiration:   time.Now().Add(24 * time.Hour),
		Context:      []string{"https://www.w3.org/2018/credentials/v1"},
		Type:         []string{"VerifiableCredential", "ConnectorCredential"},
		CredentialSubject: map[string]interface{}{
			"name": "Connector A",
		},
		Proof: models.Proof{
			Type:               "Ed25519Signature2018",
			Created:            time.Now().Format(time.RFC3339),
			VerificationMethod: "did:example:issuer#key-1",
			SignatureValue:     "", // Placeholder
		},
	}
}

// 模拟创建Authorization Credential
func createSampleAAC() models.AuthorizationCredential {
	return models.AuthorizationCredential{
		ID:             "aac:example:456",
		Issuer:         models.DID("did:example:alice"),
		Subject:        models.DID("did:example:connector:a"),
		IssuanceDate:   time.Now(),
		ExpirationDate: time.Now().Add(12 * time.Hour),
		Permissions:    []string{"read", "write"},
		ResourceScope:  "/data/sensors",
		Proof: models.Proof{
			Type:               "Ed25519Signature2018",
			Created:            time.Now().Format(time.RFC3339),
			VerificationMethod: "did:example:alice#key-2",
			SignatureValue:     "", // Placeholder
		},
	}
}

// 发送认证请求
func sendAuthRequest(conn net.Conn, request *models.AuthRequest) error {
	log.Println("Sending Auth Request...")
	jsonData, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal auth request: %w", err)
	}

	_, err = conn.Write(jsonData)
	if err != nil {
		return fmt.Errorf("failed to send auth request: %w", err)
	}
	return nil
}

// 接收认证响应
func receiveAuthResponse(conn net.Conn) (*models.AuthResponse, error) {
	log.Println("Receiving Auth Response...")
	decoder := json.NewDecoder(conn)
	var response models.AuthResponse
	if err := decoder.Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode auth response: %w", err)
	}
	return &response, nil
}
