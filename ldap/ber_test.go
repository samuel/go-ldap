package ldap

import (
	"bytes"
	"reflect"
	"testing"
)

func TestIntSize(t *testing.T) {
	tests := []struct {
		Int  int64
		Size int
	}{
		{0, 1},
		{1, 1},
		{0xff, 1},
		{0xffff, 2},
		{-1, 8},
	}

	for _, is := range tests {
		if n := intSize(is.Int); n != is.Size {
			t.Errorf("intSize(%d) = %d. Want %d", is.Int, n, is.Size)
		}
	}
}

func TestEncodeDecode(t *testing.T) {
	var tests []*Packet

	pkt := NewPacket(ClassUniversal, false, TagSequence, nil)
	pkt.AddItem(NewPacket(ClassUniversal, true, TagInteger, 0x1234))
	tests = append(tests, pkt)

	b := make([]byte, 1024)
	for i := 0; i < len(b); i++ {
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
