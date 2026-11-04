// Package protocol implements version 1 of Reap's authenticated agent channel.
package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

const MaxFrame = 8 * 1024 * 1024

type Message map[string]any

// Read validates the length before allocating and never accepts a partial frame.
func Read(r io.Reader) (Message, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > MaxFrame {
		return nil, errors.New("invalid agent frame length")
	}
	data := make([]byte, int(n))
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	if !utf8.Valid(data) {
		return nil, errors.New("agent frame is not UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var message Message
	if err := decoder.Decode(&message); err != nil {
		return nil, fmt.Errorf("invalid agent JSON: %w", err)
	}
	if message == nil {
		return nil, errors.New("agent frame must be an object")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("trailing agent JSON")
	}
	return message, nil
}

func Write(w io.Writer, message Message) error {
	if message == nil {
		return errors.New("agent frame must be an object")
	}
	data, err := json.Marshal(message)
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > MaxFrame {
		return errors.New("agent frame too large")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	for _, part := range [][]byte{header[:], data} {
		for len(part) > 0 {
			n, err := w.Write(part)
			if err != nil {
				return err
			}
			if n <= 0 || n > len(part) {
				return io.ErrShortWrite
			}
			part = part[n:]
		}
	}
	return nil
}

// ID preserves integers without a float64 conversion or a platform word limit.
func ID(message Message) (json.Number, error) {
	id, ok := message["id"].(json.Number)
	if !ok {
		return "", errors.New("request id must be an integer")
	}
	s := id.String()
	if len(s) > 0 && s[0] == '-' {
		s = s[1:]
	}
	if len(s) == 0 {
		return "", errors.New("request id must be an integer")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return "", errors.New("request id must be an integer")
		}
	}
	return id, nil
}
