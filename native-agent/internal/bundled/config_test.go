package bundled

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func packed(data []byte) []byte {
	result := append([]byte("executable bytes"), data...)
	result = append(result, Magic...)
	return binary.BigEndian.AppendUint32(result, uint32(len(data)))
}

func validJSON(t *testing.T) []byte {
	t.Helper()
	data, err := json.Marshal(Config{1, "127.0.0.1", 7443, strings.Repeat("t", 43), strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestReadConnectionSetup(t *testing.T) {
	data := packed(validJSON(t))
	config, err := Read(bytes.NewReader(data), int64(len(data)))
	if err != nil || config.Connect != "127.0.0.1" || config.Port != 7443 {
		t.Fatalf("connection setup rejected: %v", err)
	}
	for _, host := range []string{"reap-pc", "reap.example.test", "::1", "2001:db8::1"} {
		config.Connect = host
		if err := config.Validate(); err != nil {
			t.Fatalf("valid host %s rejected: %v", host, err)
		}
	}
}

func TestRejectDamagedAndUnexpectedConnectionSetup(t *testing.T) {
	valid := string(validJSON(t))
	cases := []string{
		`[]`, `null`, `{`, "\xff",
		strings.Replace(valid, `"version":1`, `"version":2`, 1),
		strings.Replace(valid, `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(valid, `"version":1,`, ``, 1),
		strings.Replace(valid, `"version":1`, `"version":1,"key":"secret"`, 1),
		strings.Replace(valid, `"port":7443`, `"port":0`, 1),
		strings.Replace(valid, `"port":7443`, `"port":65536`, 1),
		strings.Replace(valid, `"port":7443`, `"port":"7443"`, 1),
		strings.Replace(valid, `"port":7443`, `"port":true`, 1),
		strings.Replace(valid, `127.0.0.1`, `https://127.0.0.1`, 1),
		strings.Replace(valid, `127.0.0.1`, `host/path`, 1),
		strings.Replace(valid, `127.0.0.1`, ` host`, 1),
		strings.Replace(valid, `127.0.0.1`, `host:7443`, 1),
		strings.Replace(valid, strings.Repeat("t", 43), "short", 1),
		strings.Replace(valid, strings.Repeat("a", 64), strings.Repeat("A", 64), 1),
		valid + `{}`, valid + ` unexpected`, strings.Repeat(" ", MaxSize+1),
	}
	for i, data := range cases {
		contents := packed([]byte(data))
		if _, err := Read(bytes.NewReader(contents), int64(len(contents))); err == nil {
			t.Errorf("accepted malformed setup case %d", i)
		}
	}
}

func TestFooterBoundsAndMissingConfiguration(t *testing.T) {
	for _, data := range [][]byte{nil, []byte("plain executable"), packed(validJSON(t))[:10]} {
		if _, err := Read(bytes.NewReader(data), int64(len(data))); !errors.Is(err, ErrMissing) {
			t.Fatalf("missing setup gave %v", err)
		}
	}
	for _, size := range []uint32{0, 1, MaxSize + 1, 0xffffffff} {
		data := packed(validJSON(t))
		binary.BigEndian.PutUint32(data[len(data)-4:], size)
		if _, err := Read(bytes.NewReader(data), int64(len(data))); err == nil || errors.Is(err, ErrMissing) {
			t.Fatalf("invalid footer length %d gave %v", size, err)
		}
	}
}
