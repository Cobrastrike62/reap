package probe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func listenerRow(t *testing.T, address string) map[string]any {
	t.Helper()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	family := "ipv4"
	if strings.Contains(host, ":") {
		family = "ipv6"
	}
	return map[string]any{"proto": "tcp", "ip": host, "port": port,
		"addr": address, "family": family, "kind": "loopback", "process": nil, "pid": nil}
}

func requestRows(t *testing.T, rows ...map[string]any) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func linuxOnly(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("native probing is Linux only")
	}
}

// Finish the TLS handshake before serving HTTP. This fixture closes plaintext
// attempts like an ordinary TLS-only service, rather than Go's HTTP-server
// compatibility response to HTTP accidentally sent to a TLS listener.
func tlsFixture(t *testing.T, handler http.Handler) (string, []byte) {
	t.Helper()
	certificateSource := httptest.NewTLSServer(handler)
	config := certificateSource.TLS.Clone()
	certificate := certificateSource.Certificate().Raw
	certificateSource.Close()
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				if err := conn.(*tls.Conn).Handshake(); err != nil {
					return
				}
				request, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					return
				}
				defer request.Body.Close()
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, request)
				_ = recorder.Result().Write(conn)
			}()
		}
	}()
	return listener.Addr().String(), certificate
}

func TestHTTPAndTLSObservedEvidence(t *testing.T) {
	linuxOnly(t)
	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprintf("tls=%v", secure), func(t *testing.T) {
			var followed atomic.Int32
			redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				followed.Add(1)
			}))
			defer redirect.Close()
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/" || r.UserAgent() != "Reap-survey" {
					t.Errorf("unexpected probe request: %s %s %s", r.Method, r.URL.Path, r.UserAgent())
				}
				w.Header().Set("Location", redirect.URL+"/must-not-follow")
				w.Header().Set("Server", "Lab server")
				w.WriteHeader(http.StatusFound)
				_, _ = io.WriteString(w, "<html><TiTlE>  Lab &amp;\n test ♥ </title></html>")
			})
			var address string
			var certificate []byte
			if secure {
				address, certificate = tlsFixture(t, handler)
			} else {
				server := httptest.NewServer(handler)
				defer server.Close()
				address = server.Listener.Addr().String()
			}
			input := listenerRow(t, address)
			rows, err := Run(context.Background(), requestRows(t, input))
			if err != nil || len(rows) != 1 {
				t.Fatalf("Run: rows=%v err=%v", rows, err)
			}
			row := rows[0]
			protocol := "http"
			if secure {
				protocol = "https"
			}
			if row["status"] != "completed" || row["protocol"] != protocol || row["title"] != "Lab & test ♥" ||
				row["server"] != "Lab server" || row["redirect"] != redirect.URL+"/must-not-follow" ||
				!strings.Contains(row["http_status"].(string), "302") {
				t.Fatalf("unexpected evidence: %#v", row)
			}
			if followed.Load() != 0 {
				t.Fatal("probe followed an HTTP redirect")
			}
			if row["addr"] != input["addr"] || row["family"] != input["family"] {
				t.Fatalf("endpoint identity changed: %#v", row)
			}
			if secure {
				metadata := row["tls"].(map[string]any)
				digest := sha256.Sum256(certificate)
				if metadata["identity_verified"] != false || metadata["certificate_sha256"] != hex.EncodeToString(digest[:]) ||
					!strings.HasPrefix(metadata["version"].(string), "TLS 1.") {
					t.Fatalf("unexpected TLS evidence: %#v", metadata)
				}
			}
		})
	}
}

func TestWildcardBindMapsToTargetLoopback(t *testing.T) {
	linuxOnly(t)
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			host, wildcard, family := "127.0.0.1", "0.0.0.0", "ipv4"
			if network == "tcp6" {
				host, wildcard, family = "::1", "::", "ipv6"
			}
			listener, err := net.Listen(network, net.JoinHostPort(host, "0"))
			if err != nil {
				if network == "tcp6" {
					t.Skipf("IPv6 unavailable: %v", err)
				}
				t.Fatal(err)
			}
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, "<title>Loopback</title>")
			})}
			go server.Serve(listener)
			defer server.Close()
			row := listenerRow(t, listener.Addr().String())
			port := row["port"].(int)
			row["ip"], row["family"], row["kind"] = wildcard, family, "any"
			row["addr"] = net.JoinHostPort(wildcard, strconv.Itoa(port))
			rows, err := Run(context.Background(), requestRows(t, row))
			if err != nil || len(rows) != 1 || rows[0]["title"] != "Loopback" || rows[0]["ip"] != wildcard {
				t.Fatalf("wildcard probe: rows=%#v err=%v", rows, err)
			}
		})
	}
}

func TestBannerInvalidUTF8AndBounds(t *testing.T) {
	row := map[string]any{}
	parseEvidence(row, append([]byte("SSH-2.0-Lab "), 0xff, '\r', '\n'), false)
	if row["protocol"] != "banner" || row["banner"] != "SSH-2.0-Lab \uFFFD" || row["status"] != "completed" {
		t.Fatalf("banner: %#v", row)
	}
	response := "HTTP/1.0 200 OK\r\nServer: " + strings.Repeat("a", 300) + "\r\nLocation: " + strings.Repeat("b", 1200) +
		"\r\n\r\n<title>" + strings.Repeat("♥", 600) + "</title>"
	parseEvidence(row, []byte(response), true)
	if len(row["server"].(string)) != 256 || len(row["redirect"].(string)) != 1024 || len([]rune(row["title"].(string))) != 512 {
		t.Fatalf("HTTP evidence bounds: %#v", row)
	}
}

func TestEndpointReadCapAndPartialResponse(t *testing.T) {
	linuxOnly(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "<title>Bounded</title>"+strings.Repeat("x", MaxReadBytes*3))
	}))
	defer server.Close()
	rows, err := Run(context.Background(), requestRows(t, listenerRow(t, server.Listener.Addr().String())))
	if err != nil || len(rows) != 1 || rows[0]["read_partial"] != true || rows[0]["title"] != "Bounded" {
		t.Fatalf("capped response: %#v %v", rows, err)
	}
}

func TestSharedRawReadBudget(t *testing.T) {
	remaining := 10
	first, firstServer := net.Pipe()
	second, secondServer := net.Pipe()
	defer first.Close()
	defer second.Close()
	defer firstServer.Close()
	defer secondServer.Close()
	go func() { _, _ = firstServer.Write([]byte("123456")) }()
	go func() { _, _ = secondServer.Write([]byte("abcdef")) }()
	buffer := make([]byte, 100)
	if n, err := (&budgetConn{Conn: first, remaining: &remaining}).Read(buffer); n != 6 || err != nil {
		t.Fatalf("first read: %d %v", n, err)
	}
	wrapped := &budgetConn{Conn: second, remaining: &remaining}
	if n, err := wrapped.Read(buffer); n != 4 || err != nil {
		t.Fatalf("second read reset budget: %d %v", n, err)
	}
	if n, err := wrapped.Read(buffer); n != 0 || !errors.Is(err, errReadCap) || remaining != 0 {
		t.Fatalf("cap not enforced: %d %v budget=%d", n, err, remaining)
	}
}

func TestCanceledProbePreservesEveryEndpoint(t *testing.T) {
	linuxOnly(t)
	row := listenerRow(t, "127.0.0.1:3000")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rows, err := Run(ctx, requestRows(t, row, row))
	if err != nil || len(rows) != 2 {
		t.Fatalf("canceled results: %#v %v", rows, err)
	}
	for _, result := range rows {
		if result["status"] != "partial" || !strings.Contains(result["detail"].(string), "canceled") {
			t.Fatalf("canceled coverage: %#v", result)
		}
	}
}

func TestDeadlineStopsBlockedReadsAndPreservesRows(t *testing.T) {
	linuxOnly(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			<-done
		}
	}()
	row := listenerRow(t, listener.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	started := time.Now()
	rows, err := Run(ctx, requestRows(t, row, row))
	if err != nil || len(rows) != 2 || time.Since(started) > time.Second {
		t.Fatalf("unbounded probe: rows=%#v err=%v duration=%s", rows, err, time.Since(started))
	}
	for _, result := range rows {
		if result["status"] != "partial" || result["detail"] == "" {
			t.Fatalf("deadline coverage: %#v", result)
		}
	}
}

func TestInvalidEndpoints(t *testing.T) {
	base := listenerRow(t, "127.0.0.1:3000")
	cases := map[string]any{
		"null":            nil,
		"object":          map[string]any{},
		"null endpoint":   []any{nil},
		"scalar endpoint": []any{3},
	}
	mutations := map[string]any{
		"proto": "udp", "ip": "localhost", "port": 3000.5, "addr": "127.0.0.1:3001",
		"family": "ipv6", "kind": true, "process": 5, "pid": -1, "status": "completed",
	}
	for key, value := range mutations {
		row := make(map[string]any)
		for field, original := range base {
			row[field] = original
		}
		row[key] = value
		cases[key] = []any{row}
	}
	for _, port := range []any{nil, false, "3000", 0, 65536} {
		row := listenerRow(t, "127.0.0.1:3000")
		row["port"] = port
		cases[fmt.Sprintf("port-%v", port)] = []any{row}
	}
	for _, host := range []string{"10.0.0.0/24", "127.0.0.1-5", "::1%bad\r\nInjected", "[::1]", "example.invalid"} {
		row := listenerRow(t, "127.0.0.1:3000")
		row["ip"] = host
		row["addr"] = net.JoinHostPort(host, "3000")
		cases["invalid-ip-"+host] = []any{row}
	}
	for _, field := range []string{"ip", "proto", "family", "addr", "kind"} {
		row := listenerRow(t, "127.0.0.1:3000")
		row[field] = nil
		cases["null-"+field] = []any{row}
	}
	for _, key := range []string{"proto", "ip", "port", "addr"} {
		row := listenerRow(t, "127.0.0.1:3000")
		delete(row, key)
		cases["missing-"+key] = []any{row}
	}
	many := make([]any, MaxEndpoints+1)
	for i := range many {
		many[i] = base
	}
	cases["endpoint cap"] = many
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := validate(raw); err == nil {
				t.Fatalf("accepted malformed endpoints: %s", raw)
			}
		})
	}
	if _, err := validate(json.RawMessage(`[] trailing`)); err == nil {
		t.Fatal("accepted trailing JSON data")
	}
	if _, err := validate(bytes.Repeat([]byte(" "), 128*1024+1)); err == nil {
		t.Fatal("accepted excessive endpoints payload")
	}
}

func TestMalformedLaterEndpointPreventsAllNetworkActivity(t *testing.T) {
	linuxOnly(t)
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	good := listenerRow(t, listener.Addr().String())
	bad := listenerRow(t, "127.0.0.1:3000")
	bad["ip"] = "example.invalid"
	if _, err := Run(context.Background(), requestRows(t, good, bad)); err == nil {
		t.Fatal("accepted a malformed later endpoint")
	}
	_ = listener.SetDeadline(time.Now().Add(30 * time.Millisecond))
	conn, err := listener.Accept()
	if err == nil {
		conn.Close()
		t.Fatal("began probing before validating the entire request")
	}
	var netError net.Error
	if !errors.As(err, &netError) || !netError.Timeout() {
		t.Fatalf("unexpected accept result: %v", err)
	}
}

func TestValidOptionalMetadataAndLiteralFamilies(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "0.0.0.0", "::", "::1", "fe80::1%eth0", "::ffff:127.0.0.1"} {
		row := listenerRow(t, net.JoinHostPort(host, "3000"))
		delete(row, "kind")
		row["pid"], row["process"] = "123", "fixture"
		if _, err := validate(requestRows(t, row)); err != nil {
			t.Fatalf("rejected %s: %v", host, err)
		}
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		addr := "*:3000"
		if family == "ipv6" {
			addr = "[*]:3000"
		}
		row := map[string]any{"proto": "tcp", "ip": "*", "port": 3000, "addr": addr, "family": family}
		result, err := validate(requestRows(t, row))
		if err != nil || len(result) != 1 || (result[0].host != "127.0.0.1" && result[0].host != "::1") {
			t.Fatalf("wildcard validation: %#v %v", result, err)
		}
	}
	if rows, err := validate(json.RawMessage(`[]`)); err != nil || len(rows) != 0 {
		t.Fatalf("empty explicit list: %#v %v", rows, err)
	}
	rows := make([]map[string]any, MaxEndpoints)
	for i := range rows {
		rows[i] = listenerRow(t, "127.0.0.1:3000")
	}
	if result, err := validate(requestRows(t, rows...)); err != nil || len(result) != MaxEndpoints {
		t.Fatalf("valid maximum endpoint count: %#v %v", result, err)
	}
}
