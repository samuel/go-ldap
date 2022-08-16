package ldap

import (
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"
)

type Scope int

const (
	ScopeBaseObject   Scope = 0
	ScopeSingleLevel  Scope = 1
	ScopeWholeSubtree Scope = 2
	ScopeChildren     Scope = 3 // used by ldapsearch/ldaptools (-s children) but not part of the standard
)

var ScopeMap = map[Scope]string{
	ScopeBaseObject:   "Base Object",
	ScopeSingleLevel:  "Single Level",
	ScopeWholeSubtree: "Whole Subtree",
	ScopeChildren:     "Children",
}

func (sc Scope) String() string {
	if s := ScopeMap[sc]; s != "" {
		return s
	}
	return strconv.Itoa(int(sc))
}

type DerefAliases int

const (
	NeverDerefAliases   DerefAliases = 0
	DerefInSearching    DerefAliases = 1
	DerefFindingBaseObj DerefAliases = 2
	DerefAlways         DerefAliases = 3
)

var DerefMap = map[DerefAliases]string{
	NeverDerefAliases:   "NeverDerefAliases",
	DerefInSearching:    "DerefInSearching",
	DerefFindingBaseObj: "DerefFindingBaseObj",
	DerefAlways:         "DerefAlways",
}

func (d DerefAliases) String() string {
	if s := DerefMap[d]; s != "" {
		return s
	}
	return strconv.Itoa(int(d))
}

type ExtensibleMatch struct {
	MatchingRule string // optional
	Attribute    string
	Value        string
	DNAttributes bool
}

type SearchRequest struct {
	BaseDN       string
	Scope        Scope
	DerefAliases DerefAliases
	SizeLimit    int
	TimeLimit    int
	TypesOnly    bool
	Filter       Filter
	Attributes   map[string]bool
}

type SearchResult struct {
	DN         string
	Attributes map[string][][]byte
}

func IsPrintable(v []byte) bool {
	for i := 0; i < len(v); {
		r, s := utf8.DecodeRune(v[i:])
		if r == utf8.RuneError || r < 32 {
			return false
		}
		i += s
	}
	return true
}

func (r *SearchResult) ToLDIF(w io.Writer) error {
	if _, err := fmt.Fprintf(w, "dn: %s\n", r.DN); err != nil {
		return err
	}
	for name, values := range r.Attributes {
		for _, v := range values {
			if IsPrintable(v) {
				if _, err := fmt.Fprintf(w, "%s: %s\n", name, string(v)); err != nil {
					return err
				}
			} else {
				if _, err := fmt.Fprintf(w, "%s:: %s\n", name, base64.StdEncoding.EncodeToString(v)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

type SearchResponse struct {
	BaseResponse
	Results []*SearchResult
}

func (r *SearchResponse) WritePackets(w io.Writer, msgID int) error {
	top := NewResponsePacket(msgID)
	for _, res := range r.Results {
		top.Items = top.Items[:1]
		pkt := top.AddItem(NewPacket(ClassApplication, false, ApplicationSearchResultEntry, nil))
		pkt.AddItem(NewPacket(ClassUniversal, true, TagOctetString, res.DN))
		attrPkt := pkt.AddItem(NewPacket(ClassUniversal, false, TagSequence, nil))
		for name, vals := range res.Attributes {
			p := attrPkt.AddItem(NewPacket(ClassUniversal, false, TagSequence, nil))
			p.AddItem(NewPacket(ClassUniversal, true, TagOctetString, name))
			valsPkt := p.AddItem(NewPacket(ClassUniversal, false, TagSet, nil))
			for _, v := range vals {
				valsPkt.AddItem(NewPacket(ClassUniversal, true, TagOctetString, v))
			}
		}
		if err := top.Write(w); err != nil {
			return err
		}
	}
	top.Items = top.Items[:1]
	pkt := top.AddItem(r.BaseResponse.NewPacket())
	pkt.Tag = ApplicationSearchResultDone
	if len(r.Results) == 0 && r.BaseResponse.Code == ResultSuccess {
		r.BaseResponse.Code = ResultNoSuchObject
	}
	return top.Write(w)
}

func (r *SearchRequest) WritePackets(w io.Writer, msgID int) error {
	pkt := NewPacket(ClassApplication, false, ApplicationSearchRequest, nil)
	pkt.AddItem(NewPacket(ClassUniversal, true, TagOctetString, r.BaseDN))
	pkt.AddItem(NewPacket(ClassUniversal, true, TagEnumerated, int(r.Scope)))
	pkt.AddItem(NewPacket(ClassUniversal, true, TagEnumerated, int(r.DerefAliases)))
	pkt.AddItem(NewPacket(ClassUniversal, true, TagInteger, r.SizeLimit))
	pkt.AddItem(NewPacket(ClassUniversal, true, TagInteger, r.TimeLimit))
	pkt.AddItem(NewPacket(ClassUniversal, true, TagBoolean, r.TypesOnly))
	if r.Filter == nil {
		r.Filter = &Present{Attribute: "objectClass"}
	}
	p, err := r.Filter.Encode()
	if err != nil {
		return err
	}
	pkt.AddItem(p)
	p = pkt.AddItem(NewPacket(ClassUniversal, false, TagSequence, nil))
	for a := range r.Attributes {
		p.AddItem(NewPacket(ClassUniversal, true, TagOctetString, a))
	}

	req := NewRequestPacket(msgID)
	req.AddItem(pkt)
	return req.Write(w)
}

func parseSearchRequest(pkt *Packet) (*SearchRequest, error) {
	if len(pkt.Items) != 8 {
		return nil, ProtocolError("search request should have 8 items")
	}
	var ok bool
	req := &SearchRequest{}
	if req.BaseDN, ok = pkt.Items[0].Str(); !ok {
		return nil, ProtocolError("can't parse baseObject for search request")
	}
	scope, ok := pkt.Items[1].Int()
	if !ok {
		return nil, ProtocolError("can't parse scope for search request")
	}
	req.Scope = Scope(scope)
	deref, ok := pkt.Items[2].Int()
	if !ok {
		return nil, ProtocolError("can't parse derefAliases for search request")
	}
	req.DerefAliases = DerefAliases(deref)
	if req.SizeLimit, ok = pkt.Items[3].Int(); !ok {
		return nil, ProtocolError("can't parse sizeLimit for search request")
	}
	if req.TimeLimit, ok = pkt.Items[4].Int(); !ok {
		return nil, ProtocolError("can't parse sizeLimit for search request")
	}
	if req.TypesOnly, ok = pkt.Items[5].Bool(); !ok {
		return nil, ProtocolError("can't parse typesOnly for search request")
	}
	var err error
	req.Filter, err = parseSearchFilter(pkt.Items[6])
	if err != nil {
		return nil, err
	}
	req.Attributes = make(map[string]bool)
	for _, it := range pkt.Items[7].Items {
		s, ok := it.Str()
		if !ok {
			return nil, ProtocolError("can't parse attribute from list for search request")
		}
		req.Attributes[s] = true // TODO: should we lower case these? [strings.ToLower(s)] = true
	}
	return req, nil
}

func parseSearchResultResponse(pkt *Packet) (*SearchResult, error) {
	if len(pkt.Items) != 2 {
		return nil, ProtocolError("search result response should have 2 items")
	}
	var ok bool
	res := &SearchResult{}
	res.DN, ok = pkt.Items[0].Str()
	if !ok {
		return nil, ProtocolError("failed to parse dn for search result response")
	}
	res.Attributes = make(map[string][][]byte)
	for _, p := range pkt.Items[1].Items {
		if len(p.Items) != 2 {
			return nil, ProtocolError("search result response attribute should have 2 items")
		}
		name, ok := p.Items[0].Str()
		if !ok {
			return nil, ProtocolError("failed to parse attribute name in search result response")
		}
		for _, p2 := range p.Items[1].Items {
			value, ok := p2.Bytes()
			if !ok {
				return nil, ProtocolError("failed to parse attribute value in search result response")
			}
			res.Attributes[name] = append(res.Attributes[name], value)
		}
	}
	return res, nil
}
