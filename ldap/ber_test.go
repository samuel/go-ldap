package ldap

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func TestIntSize(t *testing.T) {
	t.Parallel()
	// Sizes are for minimal two's-complement signed encoding: a positive value
	// whose top byte has the high bit set needs an extra leading 0x00 byte.
	tests := []struct {
		Int  int64
		Size int
	}{
		{0, 1},
		{1, 1},
		{127, 1},
		{128, 2},
		{0xff, 2},
		{256, 2},
		{0x7fff, 2},
		{0x8000, 3},
		{0xffff, 3},
		{-1, 1},
		{-128, 1},
		{-129, 2},
		{-32768, 2},
	}

	for _, is := range tests {
		if n := intSize(is.Int); n != is.Size {
			t.Errorf("intSize(%d) = %d. Want %d", is.Int, n, is.Size)
		}
	}
}

func TestIntEncodeDecode(t *testing.T) {
	t.Parallel()
	for _, v := range []int{0, 1, 127, 128, 255, 256, -1, -128, -129, 0x7fff, 0x8000, -32768, 0x123456} {
		pkt := NewPacket(ClassUniversal, true, TagInteger, v)
		b, err := pkt.Encode()
		if err != nil {
			t.Fatalf("encode %d: %s", v, err)
		}
		got, _, err := ParsePacket(b)
		if err != nil {
			t.Fatalf("decode %d (% x): %s", v, b, err)
		}
		gv, ok := got.Int()
		if !ok {
			t.Fatalf("decode %d (% x): not an int", v, b)
		}
		if gv != v {
			t.Errorf("int round-trip: encoded %d, decoded %d (% x)", v, gv, b)
		}
	}
}

func TestParsePacketBadLength(t *testing.T) {
	t.Parallel()
	// An 8-byte length with the high bit set decodes to a negative int and must
	// be rejected rather than panicking on the subsequent slice.
	buf := []byte{0x30, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	_, _, err := ParsePacket(buf)
	if err == nil {
		t.Fatal("expected error for negative-wrapping length, got nil")
	}
	var berr InvalidBEREncodingError
	if !errors.As(err, &berr) {
		t.Errorf("expected InvalidBEREncodingError, got %T: %v", err, err)
	}
}

func TestEncodeDecode(t *testing.T) {
	t.Parallel()
	tests := make([]*Packet, 0, 2)

	pkt := NewPacket(ClassUniversal, false, TagSequence, nil)
	pkt.AddItem(NewPacket(ClassUniversal, true, TagInteger, 0x1234))
	tests = append(tests, pkt)

	b := make([]byte, 1024)
	for i := range b {
		b[i] = byte(i)
	}
	pkt = NewPacket(ClassUniversal, false, TagSequence, nil)
	pkt.AddItem(NewPacket(ClassUniversal, true, TagOctetString, b))
	pkt.AddItem(NewPacket(ClassUniversal, true, TagUTF8String, "Testing"))
	tests = append(tests, pkt)

	for _, pkt := range tests {
		b := &bytes.Buffer{}
		if err := pkt.Write(b); err != nil {
			t.Fatal(err)
		}
		pkt2, _, err := ReadPacket(b)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(pkt, pkt2) {
			t.Errorf("Decode(Encode(%+v)) != %+v", pkt, pkt2)
		}
	}
}
