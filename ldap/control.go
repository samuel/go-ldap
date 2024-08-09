package ldap

// Control is an LDAP control attached to a request or response message
// (RFC 4511 section 4.1.11):
//
//	Control ::= SEQUENCE {
//	     controlType             LDAPOID,
//	     criticality             BOOLEAN DEFAULT FALSE,
//	     controlValue            OCTET STRING OPTIONAL }
type Control struct {
	Type        string
	Criticality bool
	Value       []byte
}

// supportedControls is the set of control OIDs the server recognizes. The
// server currently implements none; add OIDs here (and advertise them in the
// RootDSE supportedControl attribute) as controls become supported.
var supportedControls = map[string]bool{}

// parseControls decodes the optional [0] Controls element of an LDAPMessage.
// It returns (nil, nil) when pkt is nil (no controls present).
func parseControls(pkt *Packet) ([]*Control, error) {
	if pkt == nil {
		return nil, nil
	}
	controls := make([]*Control, 0, len(pkt.Items))
	for _, c := range pkt.Items {
		if len(c.Items) == 0 {
			return nil, &ProtocolError{Reason: "control requires a controlType"}
		}
		ctrl := &Control{}
		var ok bool
		if ctrl.Type, ok = c.Items[0].Str(); !ok {
			return nil, &ProtocolError{Reason: "invalid control type"}
		}
		// criticality (BOOLEAN DEFAULT FALSE) and controlValue (OCTET STRING)
		// are both optional and are distinguished by their universal tag.
		for _, it := range c.Items[1:] {
			if it.Class != ClassUniversal {
				continue
			}
			switch it.Tag {
			case TagBoolean:
				ctrl.Criticality, _ = it.Bool()
			case TagOctetString:
				ctrl.Value, _ = it.Bytes()
			}
		}
		controls = append(controls, ctrl)
	}
	return controls, nil
}

// unsupportedCriticalControl returns the controlType of the first control that
// is marked critical but not supported, reporting ok=true when one is found.
// Per RFC 4511 section 4.1.11 such a control means the server MUST NOT perform
// the operation and must instead return unavailableCriticalExtension; a
// non-critical unsupported control is ignored.
func unsupportedCriticalControl(controls []*Control) (string, bool) {
	for _, c := range controls {
		if c.Criticality && !supportedControls[c.Type] {
			return c.Type, true
		}
	}
	return "", false
}
