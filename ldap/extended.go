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

func parseExtendedRequest(pkt *Packet) (*ExtendedRequest, error) {
	var ok bool
	req := &ExtendedRequest{}
	if len(pkt.Items) > 2 {
		return nil, ErrProtocolError("too many tags for extended request")
	}
	for _, it := range pkt.Items {
		switch it.Tag {
		case 0:
			req.Name, ok = it.Str()
			if !ok {
				return nil, ErrProtocolError("invalid extended request oid")
			}
		case 1:
			req.Value, ok = it.Bytes()
			if !ok {
				return nil, ErrProtocolError("invalid extended request value")
			}
		default:
			return nil, ErrProtocolError("unsupported extended request tag")
		}
	}
	return req, nil
}

type PasswordModifyRequest struct {
	UserIdentity string
	OldPassword  []byte
	NewPassword  []byte
}

func parsePasswordModifyRequest(pkt *Packet) (*PasswordModifyRequest, error) {
	var ok bool
	req := &PasswordModifyRequest{}
	for _, it := range pkt.Items {
		switch it.Tag {
		case 0:
			req.UserIdentity, ok = it.Str()
			if !ok {
				return nil, ErrProtocolError("invalid user identity tag")
			}
		case 1:
			req.OldPassword, ok = it.Bytes()
			if !ok {
				return nil, ErrProtocolError("invalid old password tag")
			}
		case 2:
			req.NewPassword, ok = it.Bytes()
			if !ok {
				return nil, ErrProtocolError("invalid new password tag")
			}
		default:
			return nil, ErrProtocolError("unknown tag")
		}
	}
	return req, nil
}
