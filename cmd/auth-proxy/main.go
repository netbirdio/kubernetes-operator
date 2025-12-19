package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/netbirdio/netbird/client/embed"
)

func main() {
	var (
		mgmtURL    string
		setupKey   string
		target     string
		listenAddr string
		statePath  string
		logLevel   string
		configPath string
		deviceName string
		dnsDomain  string
	)

	flag.StringVar(&mgmtURL, "management-url", os.Getenv("NB_MANAGEMENT_URL"), "NetBird Management URL")
	flag.StringVar(&setupKey, "setup-key", os.Getenv("NB_SETUP_KEY"), "NetBird Setup Key")
	flag.StringVar(&target, "target", os.Getenv("KUBERNETES_API_SERVER"), "Target Kubernetes API Server URL")
	flag.StringVar(&listenAddr, "listen-addr", ":443", "Address to listen on (within NetBird network)")
	flag.StringVar(&statePath, "state-path", "/var/lib/netbird/state.json", "Path to NetBird state file")
	flag.StringVar(&logLevel, "log-level", "info", "Log level")
	flag.StringVar(&configPath, "config-path", "/etc/netbird/config.json", "Path to NetBird config file")
	flag.StringVar(&deviceName, "hostname", os.Getenv("NB_HOSTNAME"), "Device name (hostname)")
	flag.StringVar(&dnsDomain, "dns-domain", os.Getenv("NB_DNS_DOMAIN"), "NetBird DNS domain (e.g., netbird.cloud)")

	flag.Parse()

	if setupKey == "" && os.Getenv("NB_SETUP_KEY") == "" {
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			log.Fatal("Setup key is required for initial setup")
		}
	}

	if target == "" {
		target = "https://kubernetes.default.svc"
	}

	// 1. Initialize NetBird Client
	opts := embed.Options{
		SetupKey:      setupKey,
		ManagementURL: mgmtURL,
		StatePath:     statePath,
		ConfigPath:    configPath,
		LogLevel:      logLevel,
		DeviceName:    deviceName,
	}

	client, err := embed.New(opts)
	if err != nil {
		log.Fatalf("Failed to create NetBird client: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Received signal, shutting down...")
		cancel()
		client.Stop(context.Background())
		os.Exit(0)
	}()

	log.Println("Starting NetBird client...")
	if err := client.Start(ctx); err != nil {
		log.Fatalf("Failed to start NetBird client: %v", err)
	}

	// 2. Setup Reverse Proxy
	targetURL, err := url.Parse(target)
	if err != nil {
		log.Fatalf("Invalid target URL: %v", err)
	}

	log.Printf("Proxying to %s", targetURL)

	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	k8sCA, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
	if err == nil {
		rootCAs.AppendCertsFromPEM(k8sCA)
	}

	saToken, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		log.Printf("Warning: Could not load ServiceAccount token: %v", err)
	}
	bearerToken := string(saToken)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: rootCAs,
		},
	}
	proxy.Transport = transport

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)

		if bearerToken != "" {
			req.Header.Set("Authorization", "Bearer "+bearerToken)
		}

		remoteIP, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			remoteIP = req.RemoteAddr
		}

		identity, err := client.WhoIs(remoteIP)
		if err != nil {
			log.Printf("Authentication failed: could not look up peer for IP %s: %v", remoteIP, err)
			req.Header.Del("Impersonate-User")
			req.Header.Del("Impersonate-Group")
			return
		}

		// Use UserId if available, otherwise fall back to FQDN as username
		username := identity.UserId
		if username == "" {
			username = identity.FQDN
		}

		log.Printf("Authenticated peer: %s (User: %s, Groups: %v)", identity.FQDN, username, identity.Groups)

		req.Header.Set("Impersonate-User", username)
		req.Header.Del("Impersonate-Group")
		for _, group := range identity.Groups {
			req.Header.Add("Impersonate-Group", group)
		}
	}

	authHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			remoteIP = r.RemoteAddr
		}

		_, err = client.WhoIs(remoteIP)
		if err != nil {
			log.Printf("Access denied for %s: %v", remoteIP, err)
			http.Error(w, "Unauthorized: Unknown NetBird Peer", http.StatusUnauthorized)
			return
		}

		proxy.ServeHTTP(w, r)
	})

	// 3. Generate self-signed TLS certificate
	tlsCert, err := generateSelfSignedCert(deviceName, dnsDomain)
	if err != nil {
		log.Fatalf("Failed to generate TLS certificate: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	// 4. Listen on NetBird Network with TLS
	listener, err := client.ListenTCP(listenAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", listenAddr, err)
	}

	tlsListener := tls.NewListener(listener, tlsConfig)

	log.Printf("Listening on %s (NetBird Network) with TLS", listenAddr)
	if err := http.Serve(tlsListener, authHandler); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

// generateSelfSignedCert creates a self-signed certificate for the proxy
func generateSelfSignedCert(hostname, dnsDomain string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	// Build DNS names for the certificate
	dnsNames := []string{hostname, "localhost"}
	if dnsDomain != "" {
		dnsNames = append(dnsNames, hostname+"."+dnsDomain)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"NetBird K8s Auth Proxy"},
			CommonName:   hostname,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}, nil
}
