package ldap

import "io"

type ExtendedRequest struct {
	Name  string
	Value []byte
}

type ExtendedResponse struct {
	BaseResponse
	Name  string
	Value []byte
}

func (r *ExtendedResponse) WritePackets(w io.Writer, msgID int) error {
	res := NewResponsePacket(msgID)
	pkt := res.AddItem(r.BaseResponse.NewPacket())
	pkt.Tag = ApplicationExtendedResponse
	if r.Name != "" {
		pkt.AddItem(NewPacket(ClassContext, true, 10, r.Name))
	}
	if r.Value != nil {
		pkt.AddItem(NewPacket(ClassContext, true, 11, r.Value))
	}
	return res.Write(w)
}

func (r *ExtendedRequest) WritePackets(w io.Writer, msgID int) error {
	pkt := NewPacket(ClassApplication, false, ApplicationExtendedRequest, nil)
	if r.Name != "" {
		pkt.AddItem(NewPacket(ClassContext, true, 0, r.Name))
	}
	if r.Value != nil {
		pkt.AddItem(NewPacket(ClassContext, true, 1, r.Value))
	}
	req := NewRequestPacket(msgID)
	req.AddItem(pkt)
	return req.Write(w)
}

func parseExtendedResponse(pkt *Packet) (*ExtendedResponse, error) {
	res := &ExtendedResponse{}
	if err := parseBaseResponse(pkt, &res.BaseResponse); err != nil {
		return nil, err
	}
	var ok bool
	for _, it := range pkt.Items[3:] {
		switch it.Tag {
		case 10:
			res.Name, ok = it.Str()
			if !ok {
				return nil, ProtocolError("invalid extended response oid")
			}
		case 11:
			res.Value, ok = it.Bytes()
			if !ok {
				return nil, ProtocolError("invalid extended response value")
			}
		default:
			return nil, ProtocolError("unsupported extended response tag")
		}
	}
	return res, nil
}

func parseExtendedRequest(pkt *Packet) (*ExtendedRequest, error) {
	var ok bool
	req := &ExtendedRequest{}
	if len(pkt.Items) > 2 {
		return nil, ProtocolError("too many tags for extended request")
	}
	for _, it := range pkt.Items {
		switch it.Tag {
		case 0:
			req.Name, ok = it.Str()
			if !ok {
				return nil, ProtocolError("invalid extended request oid")
			}
		case 1:
			req.Value, ok = it.Bytes()
			if !ok {
				return nil, ProtocolError("invalid extended request value")
			}
		default:
			return nil, ProtocolError("unsupported extended request tag")
		}
	}
	return req, nil
}

type PasswordModifyRequest struct {
	UserIdentity string
	OldPassword  []byte
	NewPassword  []byte
}

type PasswordModifyResponse struct {
	GenPassword []byte // [0] OCTET STRING OPTIONAL
}

func parsePasswordModifyRequest(pkt *Packet) (*PasswordModifyRequest, error) {
	var ok bool
	req := &PasswordModifyRequest{}
	for _, it := range pkt.Items {
		switch it.Tag {
		case 0:
			req.UserIdentity, ok = it.Str()
			if !ok {
				return nil, ProtocolError("invalid user identity tag")
			}
		case 1:
			req.OldPassword, ok = it.Bytes()
			if !ok {
				return nil, ProtocolError("invalid old password tag")
			}
		case 2:
			req.NewPassword, ok = it.Bytes()
			if !ok {
				return nil, ProtocolError("invalid new password tag")
			}
		default:
			return nil, ProtocolError("unknown tag")
		}
	}
	return req, nil
}
