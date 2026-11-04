package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"testing"
)

type fragments struct{ io.Reader }

func (r fragments) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.Reader.Read(p)
}

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return w.Buffer.Write(p)
}

func TestFragmentedFrameAndLargeIntegerID(t *testing.T) {
	w := &shortWriter{}
	id := json.Number("9223372036854775808123")
	if err := Write(w, Message{"id": id, "op": "ping", "text": "雪"}); err != nil {
		t.Fatal(err)
	}
	m, err := Read(fragments{bytes.NewReader(w.Bytes())})
	if err != nil {
		t.Fatal(err)
	}
	got, err := ID(m)
	if err != nil || got != id || m["text"] != "雪" {
		t.Fatalf("lost ID or Unicode: %#v %v", m, err)
	}
}

func TestRejectFrames(t *testing.T) {
	for _, payload := range [][]byte{[]byte("[]"), []byte("null"), []byte("1"), []byte(`{} {}`), []byte{0xff}, []byte(`{"id":`)} {
		var b bytes.Buffer
		binary.Write(&b, binary.BigEndian, uint32(len(payload)))
		b.Write(payload)
		if _, err := Read(&b); err == nil {
			t.Fatalf("accepted %q", payload)
		}
	}
	for _, length := range []uint32{0, MaxFrame + 1, 0xffffffff} {
		var b bytes.Buffer
		binary.Write(&b, binary.BigEndian, length)
		if _, err := Read(&b); err == nil {
			t.Fatalf("accepted size %d", length)
		}
	}
	for _, data := range [][]byte{{0, 0}, {0, 0, 0, 5, '{', '}'}} {
		if _, err := Read(bytes.NewReader(data)); err == nil {
			t.Fatal("accepted premature EOF")
		}
	}
}

func TestRejectNonIntegerIDs(t *testing.T) {
	for _, id := range []any{nil, "1", true, json.Number("1.0"), json.Number("1e2")} {
		if _, err := ID(Message{"id": id}); err == nil {
			t.Fatalf("accepted id %#v", id)
		}
	}
}
