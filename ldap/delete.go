package ldap

import "io"

type DeleteRequest struct {
	DN string
}

type DeleteResponse struct {
	BaseResponse
}

func parseDeleteRequest(pkt *Packet) (*DeleteRequest, error) {
	dn, ok := pkt.Str()
	if !ok {
		return nil, ProtocolError("invalid dn")
	}
	return &DeleteRequest{DN: dn}, nil
}

func parseDeleteResponse(pkt *Packet) (*DeleteResponse, error) {
	res := &DeleteResponse{}
	if err := parseBaseResponse(pkt, &res.BaseResponse); err != nil {
		return nil, err
	}
	return res, nil
}

func (r *DeleteResponse) WritePackets(w io.Writer, msgID int) error {
	res := NewResponsePacket(msgID)
	pkt := res.AddItem(r.BaseResponse.NewPacket())
	pkt.Tag = ApplicationDelResponse
	return res.Write(w)
}

func (r *DeleteRequest) WritePackets(w io.Writer, msgID int) error {
	req := NewRequestPacket(msgID)
	req.AddItem(NewPacket(ClassApplication, true, ApplicationDelRequest, r.DN))
	return req.Write(w)
}
