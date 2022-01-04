package ldap

import (
	"fmt"
	"strconv"
)

// http://www.iana.org/assignments/ldap-parameters/ldap-parameters.xml

const protocolVersion = 3

// Controls
const (
	OIDContentSynchControl              = "1.3.6.1.4.1.4203.1.9.1.1" // https://tools.ietf.org/html/rfc4533
	OIDProxiedAuthControl               = "2.16.840.1.113730.3.4.18" // https://tools.ietf.org/html/rfc4370
	OIDNamedSubordinateReferenceControl = "2.16.840.1.113730.3.4.2"  // https://tools.ietf.org/html/rfc3296
)

// Extensions
const (
	OIDCancel         = "1.3.6.1.1.8"             // https://tools.ietf.org/html/rfc3909
	OIDStartTLS       = "1.3.6.1.4.1.1466.20037"  // http://www.iana.org/go/rfc4511 - http://www.iana.org/go/rfc4513
	OIDPasswordModify = "1.3.6.1.4.1.4203.1.11.1" // http://www.iana.org/go/rfc3062
	OIDWhoAmI         = "1.3.6.1.4.1.4203.1.11.3" // http://www.iana.org/go/rfc4532
)

// Features
const (
	OIDModifyIncrement          = "1.3.6.1.1.14"           // http://www.iana.org/go/rfc4525
	OIDAllOperationalAttributes = "1.3.6.1.4.1.4203.1.5.1" // https://www.rfc-editor.org/rfc/rfc3673.txt
	OIDAttributesByObjectClass  = "1.3.6.1.4.1.4203.1.5.2" // https://tools.ietf.org/html/rfc4529
	OIDTrueFalseFilters         = "1.3.6.1.4.1.4203.1.5.3" // https://tools.ietf.org/html/rfc4526
	OIDLanguageTagOptions       = "1.3.6.1.4.1.4203.1.5.4" // https://tools.ietf.org/html/rfc3866
	OIDLanguageRangeOptions     = "1.3.6.1.4.1.4203.1.5.5" // http://tools.ietf.org/html/rfc3866
)

var RootDSE = map[string][]string{
	"supportedLDAPVersion": []string{
		"3",
	},
	"supportedFeatures": []string{
		OIDModifyIncrement,
		OIDAllOperationalAttributes,
	},
	"supportedExtension": []string{
		OIDWhoAmI,
		OIDPasswordModify,
	},
	"supportedSASLMechanisms": []string{},
}

const (
	ApplicationBindRequest           = 0
	ApplicationBindResponse          = 1
	ApplicationUnbindRequest         = 2
	ApplicationSearchRequest         = 3
	ApplicationSearchResultEntry     = 4
	ApplicationSearchResultDone      = 5
	ApplicationModifyRequest         = 6
	ApplicationModifyResponse        = 7
	ApplicationAddRequest            = 8
	ApplicationAddResponse           = 9
	ApplicationDelRequest            = 10
	ApplicationDelResponse           = 11
	ApplicationModifyDNRequest       = 12
	ApplicationModifyDNResponse      = 13
	ApplicationCompareRequest        = 14
	ApplicationCompareResponse       = 15
	ApplicationAbandonRequest        = 16
	ApplicationSearchResultReference = 19
	ApplicationExtendedRequest       = 23
	ApplicationExtendedResponse      = 24
)

var ApplicationMap = map[uint8]string{
	ApplicationBindRequest:           "Bind Request",
	ApplicationBindResponse:          "Bind Response",
	ApplicationUnbindRequest:         "Unbind Request",
	ApplicationSearchRequest:         "Search Request",
	ApplicationSearchResultEntry:     "Search Result Entry",
	ApplicationSearchResultDone:      "Search Result Done",
	ApplicationModifyRequest:         "Modify Request",
	ApplicationModifyResponse:        "Modify Response",
	ApplicationAddRequest:            "Add Request",
	ApplicationAddResponse:           "Add Response",
	ApplicationDelRequest:            "Del Request",
	ApplicationDelResponse:           "Del Response",
	ApplicationModifyDNRequest:       "Modify DN Request",
	ApplicationModifyDNResponse:      "Modify DN Response",
	ApplicationCompareRequest:        "Compare Request",
	ApplicationCompareResponse:       "Compare Response",
	ApplicationAbandonRequest:        "Abandon Request",
	ApplicationSearchResultReference: "Search Result Reference",
	ApplicationExtendedRequest:       "Extended Request",
	ApplicationExtendedResponse:      "Extended Response",
}

type ResultCode byte

const (
	ResultSuccess                      ResultCode = 0
	ResultOperationsError              ResultCode = 1
	ResultProtocolError                ResultCode = 2
	ResultTimeLimitExceeded            ResultCode = 3
	ResultSizeLimitExceeded            ResultCode = 4
	ResultCompareFalse                 ResultCode = 5
	ResultCompareTrue                  ResultCode = 6
	ResultAuthMethodNotSupported       ResultCode = 7
	ResultStrongAuthRequired           ResultCode = 8
	ResultReferral                     ResultCode = 10
	ResultAdminLimitExceeded           ResultCode = 11
	ResultUnavailableCriticalExtension ResultCode = 12
	ResultConfidentialityRequired      ResultCode = 13
	ResultSaslBindInProgress           ResultCode = 14
	ResultNoSuchAttribute              ResultCode = 16
	ResultUndefinedAttributeType       ResultCode = 17
	ResultInappropriateMatching        ResultCode = 18
	ResultConstraintViolation          ResultCode = 19
	ResultAttributeOrValueExists       ResultCode = 20
	ResultInvalidAttributeSyntax       ResultCode = 21
	ResultNoSuchObject                 ResultCode = 32
	ResultAliasProblem                 ResultCode = 33
	ResultInvalidDNSyntax              ResultCode = 34
	ResultAliasDereferencingProblem    ResultCode = 36
	ResultInappropriateAuthentication  ResultCode = 48
	ResultInvalidCredentials           ResultCode = 49
	ResultInsufficientAccessRights     ResultCode = 50
	ResultBusy                         ResultCode = 51
	ResultUnavailable                  ResultCode = 52
	ResultUnwillingToPerform           ResultCode = 53
	ResultLoopDetect                   ResultCode = 54
	ResultNamingViolation              ResultCode = 64
	ResultObjectClassViolation         ResultCode = 65
	ResultNotAllowedOnNonLeaf          ResultCode = 66
	ResultNotAllowedOnRDN              ResultCode = 67
	ResultEntryAlreadyExists           ResultCode = 68
	ResultObjectClassModsProhibited    ResultCode = 69
	ResultAffectsMultipleDSAs          ResultCode = 71
	ResultOther                        ResultCode = 80
)

var ResultCodeMap = map[ResultCode]string{
	ResultSuccess:                      "Success",
	ResultOperationsError:              "Operations Error",
	ResultProtocolError:                "Protocol Error",
	ResultTimeLimitExceeded:            "Time Limit Exceeded",
	ResultSizeLimitExceeded:            "Size Limit Exceeded",
	ResultCompareFalse:                 "Compare False",
	ResultCompareTrue:                  "Compare True",
	ResultAuthMethodNotSupported:       "Auth Method Not Supported",
	ResultStrongAuthRequired:           "Strong Auth Required",
	ResultReferral:                     "Referral",
	ResultAdminLimitExceeded:           "Admin Limit Exceeded",
	ResultUnavailableCriticalExtension: "Unavailable Critical Extension",
	ResultConfidentialityRequired:      "Confidentiality Required",
	ResultSaslBindInProgress:           "Sasl Bind In Progress",
	ResultNoSuchAttribute:              "No Such Attribute",
	ResultUndefinedAttributeType:       "Undefined Attribute Type",
	ResultInappropriateMatching:        "Inappropriate Matching",
	ResultConstraintViolation:          "Constraint Violation",
	ResultAttributeOrValueExists:       "Attribute Or Value Exists",
	ResultInvalidAttributeSyntax:       "Invalid Attribute Syntax",
	ResultNoSuchObject:                 "No Such Object",
	ResultAliasProblem:                 "Alias Problem",
	ResultInvalidDNSyntax:              "Invalid DN Syntax",
	ResultAliasDereferencingProblem:    "Alias Dereferencing Problem",
	ResultInappropriateAuthentication:  "Inappropriate Authentication",
	ResultInvalidCredentials:           "Invalid Credentials",
	ResultInsufficientAccessRights:     "Insufficient Access Rights",
	ResultBusy:                         "Busy",
	ResultUnavailable:                  "Unavailable",
	ResultUnwillingToPerform:           "Unwilling To Perform",
	ResultLoopDetect:                   "Loop Detect",
	ResultNamingViolation:              "Naming Violation",
	ResultObjectClassViolation:         "Object Class Violation",
	ResultNotAllowedOnNonLeaf:          "Not Allowed On Non Leaf",
	ResultNotAllowedOnRDN:              "Not Allowed On RDN",
	ResultEntryAlreadyExists:           "Entry Already Exists",
	ResultObjectClassModsProhibited:    "Object Class Mods Prohibited",
	ResultAffectsMultipleDSAs:          "Affects Multiple DSAs",
	ResultOther:                        "Other",
}

func (c ResultCode) String() string {
	s := ResultCodeMap[c]
	if s == "" {
		s = strconv.Itoa(int(c))
	}
	return s
}

type UnsupportedRequestTagError int

func (e UnsupportedRequestTagError) Error() string {
	return fmt.Sprintf("ldap: unsupported request tag %d", int(e))
}

type ProtocolError string

func (e ProtocolError) Error() string {
	return fmt.Sprintf("ldap: protocol error: %s", string(e))
}
