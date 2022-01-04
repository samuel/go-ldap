package ldap

import (
	"fmt"
	"net"
)

// Context is passed created by and passed back to a server backend to provide
// state for a client connection.
type Context interface{}

// Backend is implemented by an LDAP database to provide the backing store
type Backend interface {
	Add(Context, *AddRequest) (*AddResponse, error)
	Bind(Context, *BindRequest) (*BindResponse, error)
	Connect(remoteAddr net.Addr) (Context, error)
	Delete(Context, *DeleteRequest) (*DeleteResponse, error)
	Disconnect(Context)
	ExtendedRequest(Context, *ExtendedRequest) (*ExtendedResponse, error)
	Modify(Context, *ModifyRequest) (*ModifyResponse, error)
	ModifyDN(Context, *ModifyDNRequest) (*ModifyDNResponse, error)
	PasswordModify(Context, *PasswordModifyRequest) ([]byte, error)
	Search(Context, *SearchRequest) (*SearchResponse, error)
	Whoami(Context) (string, error)
}

type debugBackend struct{}

// DebugBackend is an implementation of a server backend that prints out requests
var DebugBackend Backend = debugBackend{}

func (debugBackend) Add(ctx Context, req *AddRequest) (*AddResponse, error) {
	fmt.Printf("ADD %+v\n", req)
	return &AddResponse{}, nil
}

func (debugBackend) Bind(ctx Context, req *BindRequest) (*BindResponse, error) {
	fmt.Printf("BIND %+v\n", req)
	return &BindResponse{
		BaseResponse: BaseResponse{
			Code:      ResultSuccess,
			MatchedDN: "",
			Message:   "",
		},
	}, nil
}

func (debugBackend) Connect(addr net.Addr) (Context, error) {
	return nil, nil
}

func (debugBackend) Disconnect(ctx Context) {
}

func (debugBackend) Delete(ctx Context, req *DeleteRequest) (*DeleteResponse, error) {
	fmt.Printf("DELETE %+v\n", req)
	return &DeleteResponse{}, nil
}

func (debugBackend) ExtendedRequest(ctx Context, req *ExtendedRequest) (*ExtendedResponse, error) {
	fmt.Printf("EXTENDED %+v\n", req)
	return nil, ProtocolError("unsupported extended request")
}

func (debugBackend) Modify(ctx Context, req *ModifyRequest) (*ModifyResponse, error) {
	fmt.Printf("MODIFY dn=%s\n", req.DN)
	for _, m := range req.Mods {
		fmt.Printf("\t%s %s\n", m.Type, m.Name)
		for _, v := range m.Values {
			fmt.Printf("\t\t%s\n", string(v))
		}
	}
	return &ModifyResponse{}, nil
}

func (debugBackend) ModifyDN(ctx Context, req *ModifyDNRequest) (*ModifyDNResponse, error) {
	fmt.Printf("MODIFYDN %+v\n", req)
	return &ModifyDNResponse{}, nil
}

func (debugBackend) PasswordModify(ctx Context, req *PasswordModifyRequest) ([]byte, error) {
	fmt.Printf("PASSWORD MODIFY %+v\n", req)
	return []byte("genpass"), nil
}

func (debugBackend) Search(ctx Context, req *SearchRequest) (*SearchResponse, error) {
	fmt.Printf("SEARCH %+v\n", req)
	return &SearchResponse{
		BaseResponse: BaseResponse{
			Code:      ResultSuccess, //LDAPResultNoSuchObject,
			MatchedDN: "",
			Message:   "",
		},
		Results: []*SearchResult{
			&SearchResult{
				DN: "cn=admin,dc=example,dc=com",
				Attributes: map[string][][]byte{
					"objectClass": [][]byte{[]byte("person")},
					"cn":          [][]byte{[]byte("admin")},
					"uid":         [][]byte{[]byte("123")},
				},
			},
		},
	}, nil
}

func (debugBackend) Whoami(ctx Context) (string, error) {
	fmt.Println("WHOAMI")
	return "cn=someone,o=somewhere", nil
}
