package ldap

// TODO: handle negative integers properly

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const maxPacketSize = 32 << 20 // 32 MB

type InvalidBEREncodingError string

func (e InvalidBEREncodingError) Error() string {
	return string(e)
}

type Class byte

const (
	ClassUniversal   Class = 0
	ClassApplication Class = 1
	ClassContext     Class = 2
	ClassPrivate     Class = 3
)

var ClassNames = map[Class]string{
	ClassUniversal:   "Universal",
	ClassApplication: "Application",
	ClassContext:     "Context",
	ClassPrivate:     "Private",
}

func (c Class) String() string {
	return ClassNames[c]
}

const (
	TagEOC              = 0x00
	TagBoolean          = 0x01
	TagInteger          = 0x02
	TagBitString        = 0x03
	TagOctetString      = 0x04
	TagNULL             = 0x05
	TagObjectIdentifier = 0x06
	TagObjectDescriptor = 0x07
	TagExternal         = 0x08
	TagRealFloat        = 0x09
	TagEnumerated       = 0x0a
	TagEmbeddedPDV      = 0x0b
	TagUTF8String       = 0x0c
	TagRelativeOID      = 0x0d
	TagSequence         = 0x10
	TagSet              = 0x11
	TagNumericString    = 0x12
	TagPrintableString  = 0x13
	TagT61String        = 0x14
	TagVideotexString   = 0x15
	TagIA5String        = 0x16
	TagUTCTime          = 0x17
	TagGeneralizedTime  = 0x18
	TagGraphicString    = 0x19
	TagVisibleString    = 0x1a
	TagGeneralString    = 0x1b
	TagUniversalString  = 0x1c
	TagCharacterString  = 0x1d
	TagBMPString        = 0x1e
)

var TagNames = map[int]string{
	TagEOC:              "EOC (End-of-Content)",
	TagBoolean:          "Boolean",
	TagInteger:          "Integer",
	TagBitString:        "Bit String",
	TagOctetString:      "Octet String",
	TagNULL:             "NULL",
	TagObjectIdentifier: "Object Identifier",
	TagObjectDescriptor: "Object Descriptor",
	TagExternal:         "External",
	TagRealFloat:        "Real (float)",
	TagEnumerated:       "Enumerated",
	TagEmbeddedPDV:      "Embedded PDV",
	TagUTF8String:       "UTF8 String",
	TagRelativeOID:      "Relative-OID",
	TagSequence:         "Sequence and Sequence of",
	TagSet:              "Set and Set OF",
	TagNumericString:    "Numeric String",
	TagPrintableString:  "Printable String",
	TagT61String:        "T61 String",
	TagVideotexString:   "Videotex String",
	TagIA5String:        "IA5 String",
	TagUTCTime:          "UTC Time",
	TagGeneralizedTime:  "Generalized Time",
	TagGraphicString:    "Graphic String",
	TagVisibleString:    "Visible String",
	TagGeneralString:    "General String",
	TagUniversalString:  "Universal String",
	TagCharacterString:  "Character String",
	TagBMPString:        "BMP String",
}

type Packet struct {
	Class     Class
	Primitive bool // true=primitive, false=constructed
	Tag       int
	Value     interface{}
	Items     []*Packet
}

func NewPacket(class Class, primitive bool, tag int, value interface{}) *Packet {
	return &Packet{
		Class:     class,
		Primitive: primitive,
		Tag:       tag,
		Value:     value,
	}
}

func ReadPacket(rd io.Reader) (*Packet, int, error) {
	buf := make([]byte, 16)
	if n, err := io.ReadFull(rd, buf[:2]); err != nil {
		return nil, n, err
	}
	hdr := 2
	dataLen := int(buf[1])
	if dataLen&0x80 != 0 {
		nl := int(dataLen & 0x7f)
		if nl == 0 {
			return nil, 2, InvalidBEREncodingError("ldap: indefinite form for length not supported")
		} else if nl > 8 {
			return nil, 2, InvalidBEREncodingError("ldap: number of size bytes failed sanity check")
		}
		if n, err := io.ReadFull(rd, buf[2:2+nl]); err != nil {
			return nil, hdr + n, err
		}
		hdr += nl
		dataLen = 0
		for i := 2; i < 2+nl; i++ {
			dataLen = (dataLen << 8) | int(buf[i])
		}
		if dataLen > maxPacketSize {
			return nil, 2 + nl, InvalidBEREncodingError("ldap: packet larger than max allowed size")
		}
	}

	total := dataLen + hdr
	if total > len(buf) {
		buf2 := make([]byte, total)
		copy(buf2, buf[:hdr])
		buf = buf2
	} else {
		buf = buf[:total]
	}
	if n, err := io.ReadFull(rd, buf[hdr:total]); err != nil {
		return nil, hdr + n, err
	}
	return ParsePacket(buf)
}

func ParsePacket(buf []byte) (*Packet, int, error) {
	if len(buf) < 2 {
		return nil, 0, InvalidBEREncodingError("ldap: short packet")
	}

	hdr := 2
	dataLen := int(buf[1])
	if dataLen&0x80 != 0 {
		n := int(dataLen & 0x7f)
		if n == 0 {
			return nil, hdr, InvalidBEREncodingError("ldap: indefinite form for length not supported")
		} else if n > 8 {
			return nil, hdr, InvalidBEREncodingError("ldap: number of size bytes failed sanity check")
		}
		if len(buf) < 2+n {
			return nil, hdr, InvalidBEREncodingError("ldap: short packet")
		}
		hdr += n
		dataLen = 0
		for i := 2; i < 2+n; i++ {
			dataLen = (dataLen << 8) | int(buf[i])
		}
		if dataLen > maxPacketSize {
			return nil, hdr, InvalidBEREncodingError("ldap: packet larger than max allowed size")
		}
	}

	if dataLen > len(buf)-hdr {
		return nil, hdr, InvalidBEREncodingError("ldap: short packet")
	}
	data := buf[hdr : hdr+dataLen]

	pkt := &Packet{
		Class:     Class(buf[0] >> 6),
		Primitive: buf[0]&0x20 == 0,
		Tag:       int(buf[0] & 0x1f),
	}

	if pkt.Primitive {
		if pkt.Class == ClassUniversal {
			var err error
			pkt.Value, err = parseValue(pkt.Tag, data)
			if err != nil {
				return nil, hdr + dataLen, err
			}
		} else {
			pkt.Value = data
		}
	} else {
		for len(data) > 0 {
			item, n, err := ParsePacket(data)
			if err != nil {
				return nil, hdr + dataLen - len(data) + n, err
			}
			pkt.Items = append(pkt.Items, item)
			data = data[n:]
		}
	}

	return pkt, hdr + dataLen, nil
}

func (p *Packet) AddItem(it *Packet) *Packet {
	p.Items = append(p.Items, it)
	return it
}

func (p *Packet) Bool() (bool, bool) {
	v, ok := p.Value.(bool)
	return v, ok
}

func (p *Packet) Bytes() ([]byte, bool) {
	v, ok := p.Value.([]byte)
	return v, ok
}

func (p *Packet) Int() (int, bool) {
	v, ok := p.Value.(int)
	return v, ok
}

func (p *Packet) Uint() (uint, bool) {
	v, ok := p.Value.(int)
	return uint(v), ok
}

func (p *Packet) Str() (string, bool) {
	if s, ok := p.Value.(string); ok {
		return s, true
	}
	if s, ok := p.Value.([]byte); ok {
		return string(s), true
	}
	return "", false
}

// TODO: handle negatives properly
func intSize(v int64) int {
	n := 0
	for x := uint64(v); x != 0; x >>= 8 {
		n++
	}
	if n == 0 {
		return 1
	}
	return n
}

// Size returns data size, total size with headers, and an error for unknown types
func (p *Packet) Size() (int, int, error) {
	var size int
	if p.Primitive {
		if p.Value == nil {
			return 0, 0, errors.New("ldap: nil value in Packet.Size")
		}
		switch v := p.Value.(type) {
		case []byte:
			size = len(v)
		case string:
			size = len(v)
		case int:
			size = intSize(int64(v))
		case bool:
			size = 1
		default:
			return 0, 0, fmt.Errorf("ldap: unknown type in Packet.Size: %T", p.Value)
		}
	} else {
		for _, it := range p.Items {
			_, n, err := it.Size()
			if err != nil {
				return 0, 0, err
			}
			size += n
		}
	}
	if size < 128 {
		return size, size + 2, nil
	}
	n := 0
	for x := size; x != 0; x >>= 8 {
		n++
	}
	return size, size + 2 + n, nil
}

func (p *Packet) Encode() ([]byte, error) {
	b := &bytes.Buffer{}
	if err := p.Write(b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (p *Packet) Write(w io.Writer) error {
	return p.write(w, make([]byte, 16))
}

func (p *Packet) write(w io.Writer, b []byte) error {
	sz, total, err := p.Size()
	if err != nil {
		return err
	}
	if total > maxPacketSize {
		return fmt.Errorf("ldap: packet larger than max size (%d > %d)", total, maxPacketSize)
	}
	pri := byte(0x20)
	if p.Primitive {
		pri = 0
	}
	hdr := 2
	b[0] = byte(byte(p.Class)<<6 | pri | byte(p.Tag)&0x1f)
	if sz < 128 {
		b[1] = byte(sz)
	} else {
		n := 0
		for x := sz; x > 0; x >>= 8 {
			n++
		}
		hdr += n
		b[1] = 0x80 | byte(n)
		s := uint((n - 1) * 8)
		for i := 0; i < n; i++ {
			b[i+2] = byte(sz >> s & 0xff)
			s -= 8
		}
	}
	if _, err := w.Write(b[:hdr]); err != nil {
		return err
	}

	if p.Primitive {
		if p.Value == nil {
			return errors.New("ldap: nil value in Packet.write")
		}
		switch v := p.Value.(type) {
		case []byte:
			if _, err := w.Write(v); err != nil {
				return err
			}
		case string:
			if _, err := io.WriteString(w, v); err != nil {
				return err
			}
		case int:
			n := 0
			if v == 0 {
				n = 1
				b[0] = 0
			} else {
				for x := v; x > 0; x >>= 8 {
					n++
				}
				s := uint((n - 1) * 8)
				for i := 0; i < n; i++ {
					b[i] = byte(v >> s & 0xff)
					s -= 8
				}
			}
			if _, err := w.Write(b[:n]); err != nil {
				return err
			}
		case bool:
			b[0] = 0
			if v {
				b[0] = 0xff
			}
			if _, err := w.Write(b[:1]); err != nil {
				return err
			}
		default:
			return errors.New("ldap: unknown type in Packet.write")
		}
	} else {
		if p.Value != nil {
			return errors.New("ldap: non-primitive type has a value")
		}
		for _, it := range p.Items {
			if err := it.write(w, b); err != nil {
				return err
			}
		}
	}

	return nil
}

func (p *Packet) Format(w io.Writer) error {
	return p.format(w, "")
}

func (p *Packet) format(w io.Writer, indent string) error {
	pri := "Primitive"
	if !p.Primitive {
		pri = "Constructed"
	}
	if _, err := fmt.Fprintf(w, "%sClass:%s %s", indent, p.Class.String(), pri); err != nil {
		return err
	}
	var tag string
	if p.Class == ClassUniversal {
		tag = TagNames[p.Tag]
	}
	if tag == "" {
		tag = strconv.Itoa(p.Tag)
	}
	if _, err := fmt.Fprintf(w, " Tag:%s", tag); err != nil {
		return err
	}

	if p.Primitive {
		if b, ok := p.Value.([]byte); ok {
			if _, err := fmt.Fprintf(w, " Len:%d\n", len(b)); err != nil {
				return err
			}
			for _, s := range strings.Split(hex.Dump(b), "\n") {
				if s != "" {
					if _, err := fmt.Fprintf(w, "%s %s\n", indent, s); err != nil {
						return err
					}
				}
			}
		} else if _, err := fmt.Fprintf(w, " Value:%+v\n", p.Value); err != nil {
			return err
		}
	} else {
		if _, err := w.Write([]byte("\n")); err != nil {
			return err
		}
		for _, it := range p.Items {
			if err := it.format(w, indent+"  "); err != nil {
				return err
			}
		}
	}

	return nil
}

func parseValue(tag int, data []byte) (interface{}, error) {
	switch tag {
	default:
		return data, nil
	case TagBoolean:
		if len(data) != 1 {
			return nil, InvalidBEREncodingError("ldap: bool other than 1")
		}
		return data[0] != 0, nil
	case TagInteger, TagEnumerated:
		// TODO: handle negatives properly
		i := 0
		for _, b := range data {
			i = (i << 8) | int(b)
		}
		return i, nil
	case TagPrintableString:
		// Treat this as ASCII rather than UTF-8
		runes := make([]rune, len(data))
		for i, c := range data {
			runes[i] = rune(c)
		}
		return string(runes), nil
	case TagUTF8String: //, TagOctetString:
		return string(data), nil
	}
}
