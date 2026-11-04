package protocol

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func certificate(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "reap test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, hex.EncodeToString(digest[:])
}

func TestAuthenticationDirections(t *testing.T) {
	for _, wrong := range []bool{false, true} {
		client, server := net.Pipe()
		token := strings.Repeat("a", 40)
		supplied := token
		if wrong {
			supplied = strings.Repeat("b", 40)
		}
		done := make(chan error, 1)
		go func() { defer server.Close(); done <- AuthenticateServer(server, token) }()
		err := AuthenticateClient(client, supplied)
		client.Close()
		serverErr := <-done
		if wrong && (err == nil || serverErr == nil) {
			t.Fatal("wrong token accepted")
		}
		if !wrong && (err != nil || serverErr != nil) {
			t.Fatalf("auth failed %v %v", err, serverErr)
		}
	}
}

func TestFailedPinDoesNotTransmitToken(t *testing.T) {
	cert, pin := certificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	data := make(chan int, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			data <- -1
			return
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(2 * time.Second))
		server := tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}})
		var buffer [4096]byte
		n, _ := server.Read(buffer[:])
		data <- n
	}()
	if pin[0] == '0' {
		pin = "1" + pin[1:]
	} else {
		pin = "0" + pin[1:]
	}
	if _, err := Connect(context.Background(), listener.Addr().String(), pin, strings.Repeat("secret", 8)); err == nil {
		t.Fatal("wrong pin accepted")
	}
	if n := <-data; n != 0 {
		t.Fatalf("received %d token bytes before pin validation", n)
	}
}

func TestPinnedTLSInteroperation(t *testing.T) {
	cert, pin := certificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("x", 40)
	done := make(chan error, 1)
	go func() {
		server, err := AcceptAuthenticated(context.Background(), listener, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}, token, time.Second*3)
		if err == nil {
			defer server.Close()
			message, readErr := Read(server)
			err = readErr
			if err == nil && message["id"] != json.Number("3") {
				t.Error("request id changed")
			}
		}
		done <- err
	}()
	colonPin := strings.Join(splitPairs(strings.ToUpper(pin)), ":")
	client, err := Connect(context.Background(), listener.Addr().String(), " \n"+colonPin+"\n", token)
	if err != nil {
		t.Fatal(err)
	}
	if err := Write(client, Message{"id": 3, "op": "ping"}); err != nil {
		t.Fatal(err)
	}
	client.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
func splitPairs(s string) []string {
	var parts []string
	for len(s) > 0 {
		parts = append(parts, s[:2])
		s = s[2:]
	}
	return parts
}

func TestListenerDeadlineIncludesStalledHandshake(t *testing.T) {
	cert, _ := certificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := AcceptAuthenticated(context.Background(), listener, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}, strings.Repeat("x", 40), 150*time.Millisecond)
		done <- err
	}()
	raw, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err := <-done; err == nil {
		t.Fatal("stalled peer authenticated")
	}
	if time.Since(start) > time.Second {
		t.Fatal("handshake exceeded absolute listener window")
	}
}
