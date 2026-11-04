// Package probe identifies only the explicitly supplied TCP listener endpoints.
// It does not resolve names, scan ranges, or follow HTTP redirects.
package probe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/netip"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	MaxEndpoints     = 24
	MaxReadBytes     = 64 * 1024
	OverallBudget    = 55 * time.Second
	operationTimeout = 2 * time.Second
)

var (
	errReadCap    = errors.New("64 KiB endpoint read cap reached")
	titlePattern  = regexp.MustCompile(`(?is)<title\b[^>]*>(.*?)</title\s*>`)
	statusPattern = regexp.MustCompile(`^HTTP/[0-9]+\.[0-9]+ [1-5][0-9]{2}(?:[ \t].*)?$`)
)

type endpoint struct {
	row  map[string]any
	host string
	port int
}

// Run validates the entire request before probing. Results retain input order
// and endpoint metadata, including a partial row for every unattempted endpoint.
// Application TLS identity is intentionally not verified during observation;
// these connections never carry an agent token or other session credentials.
func Run(parent context.Context, raw json.RawMessage) ([]map[string]any, error) {
	endpoints, err := validate(raw)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "linux" {
		return nil, errors.New("native TCP probing is supported only on Linux")
	}
	ctx, cancel := context.WithTimeout(parent, OverallBudget)
	defer cancel()
	rows := make([]map[string]any, 0, len(endpoints))
	for _, ep := range endpoints {
		if ctx.Err() != nil {
			ep.row["status"] = "partial"
			ep.row["detail"] = budgetDetail(ctx)
		} else {
			identify(ctx, ep)
		}
		rows = append(rows, ep.row)
	}
	return rows, nil
}

func validate(raw json.RawMessage) ([]endpoint, error) {
	if len(raw) > 128*1024 {
		return nil, errors.New("probe endpoints exceed request size limit")
	}
	var input []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &input); err != nil || input == nil {
		return nil, errors.New("probe endpoints must be a JSON array of objects")
	}
	if len(input) > MaxEndpoints {
		return nil, fmt.Errorf("probe accepts at most %d endpoints", MaxEndpoints)
	}
	rows := make([]endpoint, 0, len(input))
	for i, fields := range input {
		fail := func(detail string) ([]endpoint, error) {
			return nil, fmt.Errorf("invalid probe endpoint %d: %s", i, detail)
		}
		for name := range fields {
			switch name {
			case "proto", "ip", "port", "addr", "family", "kind", "process", "pid":
			default:
				return fail("unknown field " + name)
			}
		}
		readString := func(name string, maximum int, required bool) (string, error) {
			value, exists := fields[name]
			if !exists && !required {
				return "", nil
			}
			var result string
			if !exists || bytes.Equal(value, []byte("null")) || json.Unmarshal(value, &result) != nil ||
				!utf8.ValidString(result) || len(result) == 0 || len(result) > maximum {
				return "", fmt.Errorf("%s must be a nonempty string of at most %d bytes", name, maximum)
			}
			return result, nil
		}
		proto, err := readString("proto", 3, true)
		if err != nil || proto != "tcp" {
			return fail("proto must be tcp")
		}
		ip, err := readString("ip", 128, true)
		if err != nil {
			return fail(err.Error())
		}
		family, err := readString("family", 4, false)
		if err != nil {
			return fail(err.Error())
		}
		if family != "" && family != "ipv4" && family != "ipv6" {
			return fail("family must be ipv4 or ipv6")
		}
		host := ip
		expectedKind := "other"
		parsed, parseErr := netip.ParseAddr(ip)
		if ip == "*" {
			expectedKind = "any"
			if family == "ipv6" {
				host = "::1"
			} else {
				host = "127.0.0.1"
			}
		} else if parseErr != nil {
			return fail("ip must be a literal IPv4 or IPv6 address")
		} else {
			expectedFamily := "ipv6"
			if parsed.Is4() {
				expectedFamily = "ipv4"
			}
			if family != "" && family != expectedFamily {
				return fail("family disagrees with ip")
			}
			if zone := parsed.Zone(); zone != "" {
				if len(zone) > 64 {
					return fail("invalid IPv6 scope zone")
				}
				for _, char := range zone {
					if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '_' || char == '-' || char == '.') {
						return fail("invalid IPv6 scope zone")
					}
				}
			}
			if parsed.IsUnspecified() {
				expectedKind = "any"
				if parsed.Is4() {
					host = "127.0.0.1"
				} else {
					host = "::1"
				}
			} else if parsed.IsLoopback() {
				expectedKind = "loopback"
			}
		}
		var port int
		value, exists := fields["port"]
		if !exists || json.Unmarshal(value, &port) != nil || port < 1 || port > 65535 {
			return fail("port must be an integer from 1 through 65535")
		}
		addr, err := readString("addr", 160, true)
		if err != nil {
			return fail(err.Error())
		}
		expectedAddr := net.JoinHostPort(ip, strconv.Itoa(port))
		if ip == "*" && family == "ipv6" {
			expectedAddr = "[*]:" + strconv.Itoa(port)
		}
		if addr != expectedAddr {
			return fail("addr disagrees with ip and port")
		}
		if kind, err := readString("kind", 8, false); err != nil || kind != "" && kind != expectedKind {
			return fail("kind disagrees with ip")
		}
		if value, exists := fields["process"]; exists && !bytes.Equal(value, []byte("null")) {
			var process string
			if json.Unmarshal(value, &process) != nil || len(process) > 512 {
				return fail("process must be null or a string of at most 512 bytes")
			}
		}
		if value, exists := fields["pid"]; exists && !bytes.Equal(value, []byte("null")) {
			pid := strings.Trim(string(value), "\"")
			if len(pid) == 0 || len(pid) > 10 {
				return fail("pid must be null, a positive integer, or a decimal string")
			}
			for _, char := range pid {
				if char < '0' || char > '9' {
					return fail("pid must be null, a positive integer, or a decimal string")
				}
			}
			if pidValue, err := strconv.ParseUint(pid, 10, 32); err != nil || pidValue == 0 {
				return fail("pid is outside its valid range")
			}
		}
		row := make(map[string]any, len(fields)+8)
		for name, value := range fields {
			var decoded any
			if err := json.Unmarshal(value, &decoded); err != nil {
				return fail("invalid field " + name)
			}
			row[name] = decoded
		}
		row["port"] = port
		rows = append(rows, endpoint{row: row, host: host, port: port})
	}
	return rows, nil
}

// A shared budgetConn counts raw socket reads, including TLS handshake bytes,
// across both attempts. A failed first attempt cannot grant a fresh read cap.
type budgetConn struct {
	net.Conn
	remaining *int
}

func (conn *budgetConn) Read(buffer []byte) (int, error) {
	if *conn.remaining <= 0 {
		return 0, errReadCap
	}
	if len(buffer) > *conn.remaining {
		buffer = buffer[:*conn.remaining]
	}
	n, err := conn.Conn.Read(buffer)
	*conn.remaining -= n
	return n, err
}

func identify(ctx context.Context, ep endpoint) {
	remaining := MaxReadBytes
	errorsSeen := make([]string, 0, 2)
	secureFirst := ep.port == 443 || ep.port == 8443 || ep.port == 9443
	for _, secure := range []bool{secureFirst, !secureFirst} {
		if ctx.Err() != nil {
			errorsSeen = append(errorsSeen, budgetDetail(ctx))
			break
		}
		if remaining <= 0 {
			errorsSeen = append(errorsSeen, errReadCap.Error())
			ep.row["read_partial"] = true
			break
		}
		data, partial, err := attempt(ctx, ep, secure, &remaining)
		if partial {
			ep.row["read_partial"] = true
		}
		if len(data) > 0 && strings.TrimSpace(string(data)) != "" {
			parseEvidence(ep.row, data, secure)
			return
		}
		prefix := "TCP: "
		if secure {
			prefix = "TLS: "
		}
		if err != nil {
			errorsSeen = append(errorsSeen, prefix+truncate(err.Error(), 512))
		} else {
			errorsSeen = append(errorsSeen, prefix+"no response")
		}
	}
	ep.row["status"] = "partial"
	ep.row["detail"] = strings.Join(errorsSeen, "; ")
}

func attempt(ctx context.Context, ep endpoint, secure bool, remaining *int) ([]byte, bool, error) {
	dialer := net.Dialer{Timeout: operationTimeout}
	raw, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ep.host, strconv.Itoa(ep.port)))
	if err != nil {
		return nil, false, err
	}
	defer raw.Close()
	stopCancel := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stopCancel()
	conn := net.Conn(&budgetConn{Conn: raw, remaining: remaining})
	if err := conn.SetDeadline(operationDeadline(ctx)); err != nil {
		return nil, false, err
	}
	if secure {
		// This is an unauthenticated application-service observation. Agent
		// session TLS uses a separate mandatory certificate-pin check.
		tlsConn := tls.Client(conn, &tls.Config{MinVersion: tls.VersionTLS12,
			InsecureSkipVerify: true, ServerName: ep.host})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, *remaining <= 0, err
		}
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			return nil, false, errors.New("TLS peer supplied no certificate")
		}
		digest := sha256.Sum256(state.PeerCertificates[0].Raw)
		ep.row["tls"] = map[string]any{"version": tls.VersionName(state.Version),
			"certificate_sha256": hex.EncodeToString(digest[:]), "identity_verified": false}
		conn = tlsConn
	}
	if !secure && (ep.port == 21 || ep.port == 22 || ep.port == 25 || ep.port == 110 || ep.port == 143) {
		buffer := make([]byte, 4096)
		_ = conn.SetReadDeadline(operationDeadline(ctx))
		n, err := conn.Read(buffer)
		return buffer[:n], *remaining <= 0, err
	}
	request := "GET / HTTP/1.0\r\nHost: " + net.JoinHostPort(ep.host, strconv.Itoa(ep.port)) +
		"\r\nUser-Agent: Reap-survey\r\nConnection: close\r\n\r\n"
	if err := conn.SetWriteDeadline(operationDeadline(ctx)); err != nil {
		return nil, false, err
	}
	if _, err := io.Copy(conn, strings.NewReader(request)); err != nil {
		return nil, *remaining <= 0, err
	}
	var data bytes.Buffer
	buffer := make([]byte, 4096)
	for *remaining > 0 {
		if err := conn.SetReadDeadline(operationDeadline(ctx)); err != nil {
			return data.Bytes(), true, err
		}
		n, err := conn.Read(buffer)
		_, _ = data.Write(buffer[:n])
		if err != nil {
			if errors.Is(err, io.EOF) {
				return data.Bytes(), false, nil
			}
			return data.Bytes(), true, err
		}
		if ctx.Err() != nil {
			return data.Bytes(), true, ctx.Err()
		}
	}
	return data.Bytes(), true, errReadCap
}

func operationDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(operationTimeout)
	if overall, exists := ctx.Deadline(); exists && overall.Before(deadline) {
		return overall
	}
	return deadline
}

func budgetDetail(ctx context.Context) string {
	if errors.Is(ctx.Err(), context.Canceled) {
		return "probe canceled"
	}
	return "overall probe time budget reached (maximum 55 seconds)"
}

func parseEvidence(row map[string]any, data []byte, secure bool) {
	text := strings.ToValidUTF8(string(data), "\uFFFD")
	headers, body, _ := strings.Cut(text, "\r\n\r\n")
	lines := strings.Split(headers, "\r\n")
	row["status"] = "completed"
	if len(lines) == 0 || !statusPattern.MatchString(lines[0]) {
		row["protocol"] = "banner"
		first, _, _ := strings.Cut(text, "\n")
		row["banner"] = truncate(strings.TrimSuffix(first, "\r"), 512)
		return
	}
	protocol := "http"
	if secure {
		protocol = "https"
	}
	row["protocol"] = protocol
	row["http_status"] = truncate(lines[0], 256)
	row["server"], row["redirect"], row["title"] = "", "", ""
	for _, line := range lines[1:] {
		name, value, exists := strings.Cut(line, ":")
		if !exists {
			continue
		}
		switch strings.ToLower(name) {
		case "server":
			row["server"] = truncate(strings.TrimSpace(value), 256)
		case "location":
			row["redirect"] = truncate(strings.TrimSpace(value), 1024)
		}
	}
	if title := titlePattern.FindStringSubmatch(body); title != nil {
		row["title"] = truncate(strings.TrimSpace(html.UnescapeString(strings.Join(strings.Fields(title[1]), " "))), 512)
	}
}

func truncate(text string, maximum int) string {
	runes := []rune(text)
	if len(runes) > maximum {
		return string(runes[:maximum])
	}
	return text
}
