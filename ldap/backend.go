package ldap

import (
	"context"
	"fmt"
	"net"
)

// State is passed created by and passed back to a server backend to provide
// state for a client connection.
type State interface{}

// Backend is implemented by an LDAP database to provide the backing store.
type Backend interface {
	Add(ctx context.Context, state State, req *AddRequest) (*AddResponse, error)
	Bind(ctx context.Context, state State, req *BindRequest) (*BindResponse, error)
	Connect(remoteAddr net.Addr) (State, error)
	Delete(ctx context.Context, state State, req *DeleteRequest) (*DeleteResponse, error)
	Disconnect(state State)
	ExtendedRequest(ctx context.Context, state State, req *ExtendedRequest) (*ExtendedResponse, error)
	Modify(ctx context.Context, state State, req *ModifyRequest) (*ModifyResponse, error)
	ModifyDN(ctx context.Context, state State, req *ModifyDNRequest) (*ModifyDNResponse, error)
	PasswordModify(ctx context.Context, state State, req *PasswordModifyRequest) ([]byte, error)
	Search(ctx context.Context, state State, req *SearchRequest) (*SearchResponse, error)
	Whoami(ctx context.Context, state State) (string, error)
}

type debugBackend struct{}

// DebugBackend is an implementation of a server backend that prints out requests.
var DebugBackend Backend = debugBackend{}

func (debugBackend) Add(ctx context.Context, state State, req *AddRequest) (*AddResponse, error) {
	fmt.Printf("ADD %+v\n", req)
	return &AddResponse{}, nil
}

func (debugBackend) Bind(ctx context.Context, state State, req *BindRequest) (*BindResponse, error) {
	fmt.Printf("BIND %+v\n", req)
	return &BindResponse{
		BaseResponse: BaseResponse{
			Code:      ResultSuccess,
			MatchedDN: "",
			Message:   "",
		},
	}, nil
}

func (debugBackend) Connect(remoteAddr net.Addr) (State, error) {
	return nil, nil
}

func (debugBackend) Disconnect(state State) {
}

func (debugBackend) Delete(ctx context.Context, state State, req *DeleteRequest) (*DeleteResponse, error) {
	fmt.Printf("DELETE %+v\n", req)
	return &DeleteResponse{}, nil
}

func (debugBackend) ExtendedRequest(ctx context.Context, state State, req *ExtendedRequest) (*ExtendedResponse, error) {
	fmt.Printf("EXTENDED %+v\n", req)
	return nil, &ProtocolError{Reason: "unsupported extended request"}
}

func (debugBackend) Modify(ctx context.Context, state State, req *ModifyRequest) (*ModifyResponse, error) {
	fmt.Printf("MODIFY dn=%s\n", req.DN)
	for _, m := range req.Mods {
		fmt.Printf("\t%s %s\n", m.Type, m.Name)
		for _, v := range m.Values {
			fmt.Printf("\t\t%s\n", string(v))
		}
	}
	return &ModifyResponse{}, nil
}

func (debugBackend) ModifyDN(ctx context.Context, state State, req *ModifyDNRequest) (*ModifyDNResponse, error) {
	fmt.Printf("MODIFYDN %+v\n", req)
	return &ModifyDNResponse{}, nil
}

func (debugBackend) PasswordModify(ctx context.Context, state State, req *PasswordModifyRequest) ([]byte, error) {
	fmt.Printf("PASSWORD MODIFY %+v\n", req)
	return []byte("genpass"), nil
}

func (debugBackend) Search(ctx context.Context, state State, req *SearchRequest) (*SearchResponse, error) {
	fmt.Printf("SEARCH %+v\n", req)
	return &SearchResponse{
		BaseResponse: BaseResponse{
			Code:      ResultSuccess, //LDAPResultNoSuchObject,
			MatchedDN: "",
			Message:   "",
		},
		Results: []*SearchResult{
			{
				DN: "cn=admin,dc=example,dc=com",
				Attributes: map[string][][]byte{
					"objectClass": {[]byte("person")},
					"cn":          {[]byte("admin")},
					"uid":         {[]byte("123")},
				},
			},
		},
	}, nil
}

func (debugBackend) Whoami(ctx context.Context, state State) (string, error) {
	fmt.Println("WHOAMI")
	return "cn=someone,o=somewhere", nil
}
