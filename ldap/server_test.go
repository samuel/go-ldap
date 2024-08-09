package ldap

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

// TestSearchResponseEmptyIsSuccess verifies that a search matching zero entries
// is reported as success (with a SearchResultDone), not noSuchObject. Per
// RFC 4511 an empty result set is still a successful search.
func TestSearchResponseEmptyIsSuccess(t *testing.T) {
	t.Parallel()
	res := &SearchResponse{BaseResponse: BaseResponse{Code: ResultSuccess}}
	var buf bytes.Buffer
	if err := res.WritePackets(&buf, 1); err != nil {
		t.Fatal(err)
	}
	pkt, _, err := ParsePacket(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(pkt.Items) != 2 {
		t.Fatalf("message has %d items, want 2", len(pkt.Items))
	}
	op := pkt.Items[1]
	if op.Tag != ApplicationSearchResultDone {
		t.Fatalf("op tag = %d, want SearchResultDone (%d)", op.Tag, ApplicationSearchResultDone)
	}
	code, ok := op.Items[0].Int()
	if !ok {
		t.Fatal("result code is not an int")
	}
	if ResultCode(code) != ResultSuccess {
		t.Errorf("result code = %s, want Success", ResultCode(code))
	}
}

// TestClientServerRoundTrip exercises the full client/server request path over
// an in-memory pipe (Bind then Search) against the DebugBackend.
func TestClientServerRoundTrip(t *testing.T) {
	t.Parallel()
	srv, err := NewServer(DebugBackend, nil)
	if err != nil {
		t.Fatal(err)
	}
	cliCn, srvCn := net.Pipe()
	scli := &srvClient{
		cn:         srvCn,
		wr:         bufio.NewWriter(srvCn),
		srv:        srv,
		remoteAddr: srvCn.RemoteAddr(),
	}
	go scli.serve(t.Context())

	c := NewClient(cliCn, false)
	defer func() { _ = c.Close() }()

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	if err := c.Bind(ctx, "cn=test", []byte("pw")); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	res, err := c.Search(ctx, &SearchRequest{Scope: ScopeWholeSubtree, Filter: &Present{Attribute: "objectClass"}})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("got %d results, want 1", len(res))
	}
	if res[0].DN != "cn=admin,dc=example,dc=com" {
		t.Errorf("DN = %q, want cn=admin,dc=example,dc=com", res[0].DN)
	}
}

// TestServerMalformedSearchResponseTag verifies that a malformed search request
// is answered with a SearchResultDone (tag 5), not a SearchResultEntry (tag 4),
// so the client can parse the failure.
func TestServerMalformedSearchResponseTag(t *testing.T) {
	t.Parallel()
	cliCn := startPipeServer(t)

	// A search request with no items fails parsing (it must have 8).
	msg := NewPacket(ClassUniversal, false, TagSequence, nil)
	msg.AddItem(NewPacket(ClassUniversal, true, TagInteger, 7))
	msg.AddItem(NewPacket(ClassApplication, false, ApplicationSearchRequest, nil))

	op := requestResponse(t, cliCn, msg)
	if op.Tag != ApplicationSearchResultDone {
		t.Errorf("response op tag = %d, want SearchResultDone (%d)", op.Tag, ApplicationSearchResultDone)
	}
	code, _ := op.Items[0].Int()
	if ResultCode(code) != ResultProtocolError {
		t.Errorf("result code = %s, want Protocol Error", ResultCode(code))
	}
}

// TestServerRejectsCriticalControl verifies that an unrecognized control marked
// critical causes the operation to be rejected with unavailableCriticalExtension
// (RFC 4511 4.1.11), carried on the operation's own response type.
func TestServerRejectsCriticalControl(t *testing.T) {
	t.Parallel()
	cliCn := startPipeServer(t)

	msg := searchMessageWithControl(8, "1.2.3.4.5.6.7", true)
	op := requestResponse(t, cliCn, msg)
	if op.Tag != ApplicationSearchResultDone {
		t.Errorf("response op tag = %d, want SearchResultDone (%d)", op.Tag, ApplicationSearchResultDone)
	}
	code, _ := op.Items[0].Int()
	if ResultCode(code) != ResultUnavailableCriticalExtension {
		t.Errorf("result code = %s, want Unavailable Critical Extension", ResultCode(code))
	}
}

// TestServerIgnoresNonCriticalControl verifies that an unrecognized control that
// is NOT critical is ignored and the operation proceeds normally.
func TestServerIgnoresNonCriticalControl(t *testing.T) {
	t.Parallel()
	cliCn := startPipeServer(t)

	msg := searchMessageWithControl(8, "1.2.3.4.5.6.7", false)
	op := requestResponse(t, cliCn, msg)
	// DebugBackend returns one entry, so the first response is a result entry,
	// proving the operation ran rather than being rejected.
	if op.Tag != ApplicationSearchResultEntry {
		t.Errorf("response op tag = %d, want SearchResultEntry (%d)", op.Tag, ApplicationSearchResultEntry)
	}
}

// startPipeServer runs a srvClient (backed by DebugBackend) on one end of an
// in-memory pipe and returns the client end. The server stops when the returned
// connection is closed at the end of the test.
func startPipeServer(t *testing.T) net.Conn {
	t.Helper()
	srv, err := NewServer(DebugBackend, nil)
	if err != nil {
		t.Fatal(err)
	}
	cliCn, srvCn := net.Pipe()
	t.Cleanup(func() { _ = cliCn.Close() })
	cli := &srvClient{
		cn:         srvCn,
		wr:         bufio.NewWriter(srvCn),
		srv:        srv,
		remoteAddr: srvCn.RemoteAddr(),
	}
	go cli.serve(t.Context())
	return cliCn
}

// requestResponse writes msg to the connection and returns the protocolOp of the
// first response message.
func requestResponse(t *testing.T, cn net.Conn, msg *Packet) *Packet {
	t.Helper()
	b, err := msg.Encode()
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = cn.Write(b) }()
	_ = cn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, _, err := ReadPacket(cn)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Items) < 2 {
		t.Fatalf("response message has %d items, want >= 2", len(resp.Items))
	}
	return resp.Items[1]
}

// searchMessageWithControl builds a valid subtree search LDAPMessage carrying a
// single control with the given OID and criticality.
func searchMessageWithControl(msgID int, oid string, critical bool) *Packet {
	msg := NewPacket(ClassUniversal, false, TagSequence, nil)
	msg.AddItem(NewPacket(ClassUniversal, true, TagInteger, msgID))
	search := msg.AddItem(NewPacket(ClassApplication, false, ApplicationSearchRequest, nil))
	search.AddItem(NewPacket(ClassUniversal, true, TagOctetString, "dc=example,dc=com")) // baseObject
	search.AddItem(NewPacket(ClassUniversal, true, TagEnumerated, int(ScopeWholeSubtree)))
	search.AddItem(NewPacket(ClassUniversal, true, TagEnumerated, int(NeverDerefAliases)))
	search.AddItem(NewPacket(ClassUniversal, true, TagInteger, 0))     // sizeLimit
	search.AddItem(NewPacket(ClassUniversal, true, TagInteger, 0))     // timeLimit
	search.AddItem(NewPacket(ClassUniversal, true, TagBoolean, false)) // typesOnly
	search.AddItem(NewPacket(ClassContext, true, filterTagPresent, "objectClass"))
	search.AddItem(NewPacket(ClassUniversal, false, TagSequence, nil)) // attributes

	controls := msg.AddItem(NewPacket(ClassContext, false, 0, nil))
	ctrl := controls.AddItem(NewPacket(ClassUniversal, false, TagSequence, nil))
	ctrl.AddItem(NewPacket(ClassUniversal, true, TagOctetString, oid))
	ctrl.AddItem(NewPacket(ClassUniversal, true, TagBoolean, critical))
	return msg
}
