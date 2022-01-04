package ldap

import (
	"fmt"

	"io"
)

type ModType int

const (
	Add       ModType = 0
	Delete    ModType = 1
	Replace   ModType = 2
	Increment ModType = 3
)

func (mt ModType) String() string {
	switch mt {
	case Add:
		return "Add"
	case Delete:
		return "Delete"
	case Replace:
		return "Replace"
	case Increment:
		return "Increment"
	}
	return fmt.Sprintf("ModType(%d)", int(mt))
}

type Mod struct {
	Type   ModType
	Name   string
	Values [][]byte
}

type ModifyRequest struct {
	DN   string
	Mods []*Mod
}

type ModifyResponse struct {
	BaseResponse
}

func parseModifyRequest(pkt *Packet) (*ModifyRequest, error) {
	if len(pkt.Items) != 2 {
		return nil, ProtocolError("modify request requires exactly 2 items")
	}
	dn, ok := pkt.Items[0].Str()
	if !ok {
		return nil, ProtocolError("invalid dn")
	}
	req := &ModifyRequest{DN: dn}
	for _, it := range pkt.Items[1].Items {
		if len(it.Items) != 2 || len(it.Items[1].Items) != 2 {
			return nil, ProtocolError("mod operation requires 2 items")
		}
		mod := &Mod{}
		typ, ok := it.Items[0].Int()
		if !ok {
			return nil, ProtocolError("invalid mod op")
		}
		mod.Type = ModType(typ)
		mod.Name, ok = it.Items[1].Items[0].Str()
		if !ok {
			return nil, ProtocolError("invalid attribute name")
		}
		mod.Values = make([][]byte, len(it.Items[1].Items[1].Items))
		for i, c := range it.Items[1].Items[1].Items {
			val, ok := c.Bytes()
			if !ok {
				return nil, ProtocolError("invalid attribute value")
			}
			mod.Values[i] = val
		}
		req.Mods = append(req.Mods, mod)
	}
	return req, nil
}

func (r *ModifyRequest) WritePackets(w io.Writer, msgID int) error {
	req := NewRequestPacket(msgID)
	pkt := req.AddItem(NewPacket(ClassApplication, false, ApplicationModifyRequest, nil))
	pkt.AddItem(NewPacket(ClassUniversal, true, TagOctetString, r.DN))
	pkt = pkt.AddItem(NewPacket(ClassUniversal, false, TagSequence, nil))
	for _, m := range r.Mods {
		p := pkt.AddItem(NewPacket(ClassUniversal, false, TagSequence, nil))
		p.AddItem(NewPacket(ClassUniversal, true, TagEnumerated, int(m.Type)))
		p = p.AddItem(NewPacket(ClassUniversal, false, TagSequence, nil))
		p.AddItem(NewPacket(ClassUniversal, true, TagOctetString, m.Name))
		p = p.AddItem(NewPacket(ClassUniversal, false, TagSet, nil))
		for _, v := range m.Values {
			p.AddItem(NewPacket(ClassUniversal, true, TagOctetString, v))
		}
	}
	return req.Write(w)
}

func (r *ModifyResponse) WritePackets(w io.Writer, msgID int) error {
	res := NewResponsePacket(msgID)
	pkt := res.AddItem(r.BaseResponse.NewPacket())
	pkt.Tag = ApplicationModifyResponse
	return res.Write(w)
}
