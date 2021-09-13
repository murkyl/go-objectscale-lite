package objectscalelite

import (
	"fmt"
	"github.com/mitchellh/mapstructure"
	"log"
	"strings"
)

const (
	apiDefaultDuration       int64  = 3600
	apiHdrNamespace          string = "x-emc-namespace"
	apiOpAccessKeyID         string = "AccessKeyId"
	apiOpAction              string = "Action"
	apiOpDurationSeconds     string = "DurationSeconds"
	apiOpInlineSessionPolicy string = "InlineSessionPolicy"
	apiOpUserName            string = "UserName"
	apiOpGroupName           string = "GroupName"
	apiOpMarker              string = "Marker"
	apiOpMaxItems            string = "MaxItems"
	apiOpPath                string = "Path"
	apiOpPathPrefix          string = "PathPrefix"
	apiOpPermissionBoundary  string = "PermissionsBoundary"
	apiOpPolicyArn           string = "PolicyArn"
	apiOpPolicyArns          string = "PolicyArns"
	apiOpRoleArn             string = "RoleArn"
	apiOpRoleName            string = "RoleName"
	apiOpRoleSessionName     string = "RoleSessionName"
	apiPathIAM               string = "iam"
	apiPathSTS               string = "sts"
)

// ObjectScaleCfg contains the configuration to connect to an ObjectScale cluster endpoint
type ObjectScaleCfg struct {
	User       string
	Password   string
	Endpoint   string
	BypassCert bool
}

// ObjectScaleConn contains the state of a connection
type ObjectScaleConn struct {
	*ObjectScaleSession
}

// ObjectScaleQueryParams is a general structure holding possible query parameter values to pass
// into a function. Only values that are usable by a specific function will be used, other will
// be ignored
type ObjectScaleQueryParams struct {
	Boundary            string
	DurationSeconds     int64
	InlineSessionPolicy string
	Marker              string
	MaxItems            int
	OnlyAttached        bool
	Path                string
	PathPrefix          string
	PermissionsBoundary string
	PolicyArns          string
	PolicyScope         string
	PolicyUsageFilter   string
	PrincipalArn        string
	RoleArn             string
	RoleSessionName     string
	SAMLAssertion       string
	Tags                map[string]string
	UserName            string
}

// ObjectScaleGeneralResponse holds general response values for many function calls
type ObjectScaleGeneralResponse struct {
	ResponseMetadata struct {
		RequestID string
	}
}

// ObjectScaleAssumedRole holds the return values of an IAM Assume Role response
type ObjectScaleAssumedRole struct {
	AssumeRoleUser ObjectScaleAssumedRoleUser
	Credentials    ObjectScaleCredentials
}

// ObjectScaleAssumedRoleUser holds the return value for an assumed role in an IAM Assume Role response
type ObjectScaleAssumedRoleUser struct {
	AssumedRoleID string
	Arn           string
}

// ObjectScaleAssumedSAMLRole holds the return value for a SAML response in an IAM Assume Role SAML response
type ObjectScaleAssumedSAMLRole struct {
	ObjectScaleAssumedRole
	Issuer      string
	Subject     string
	SubjectType string
}

// ObjectScaleIAMAccessKey holds the access key and secret for a user
type ObjectScaleIAMAccessKey struct {
	AccessKeyID     string
	CreateDate      string
	SecretAccessKey string
	Status          string
	UserName        string
}

// ObjectScaleIAMUser represents the values for an IAM user
type ObjectScaleIAMUser struct {
	Arn        string
	CreateDate string
	Path       string
	UserID     string
	UserName   string
}

// ObjectScaleIAMGroup represents the values for an IAM group
type ObjectScaleIAMGroup struct {
	Arn        string
	CreateDate string `json:"omitempty"`
	GroupName  string
	GroupID    string
	Path       string
}

// ObjectScaleList is a base structure for most list responses
type ObjectScaleList struct {
	Marker      string `json:"omitempty"`
	IsTruncated bool
}

// ObjectScaleListIAMAccessKeys is a list of IAM groups
type ObjectScaleListIAMAccessKeys struct {
	ObjectScaleList
	AccessKeyMetadata []ObjectScaleIAMAccessKey
}

// ObjectScaleListIAMUser is a list of IAM users
type ObjectScaleListIAMUser struct {
	ObjectScaleList
	Users []ObjectScaleIAMUser
}

// ObjectScaleListIAMUserGroup is a list of IAM groups
type ObjectScaleListIAMUserGroup struct {
	ObjectScaleList
	Groups []ObjectScaleIAMGroup
}

// GetURNPolicyFromString takes strings in 2 formats and returns a URN policy string
// The URN format looks like: urn:ecs:service::namespace:resource-type/resource-id
// An example URL for ObjectScale: urn:ecs:iam:::policy/NameOfAPolicy
// The first format is a string that is already in the urn format and that string is returned
// The second supports a simple string that for policies in the Global/System context
// Policies in a specific namespace can be used with the format namespace:policyName
func GetURNPolicyFromString(data string) string {
	if strings.HasPrefix(data, "urn:") {
		return data
	}
	urnParts := strings.Split(data, ":")
	ns := ""
	if len(urnParts) > 1 {
		ns = urnParts[0]
		data = urnParts[1]
	}
	return fmt.Sprintf("urn:ecs:iam::%s:policy/%s", ns, data)
}

// NewObjectScaleConn returns a connection state object that is used by all other calls in this library
func NewObjectScaleConn() *ObjectScaleConn {
	state := ObjectScaleConn{}
	state.ObjectScaleSession = NewSession("")
	return &state
}

// Connect performs the actual connection to the ObjectScale cluster endpoint given the endpoint configuration in a ObjectScaleCfg struct
func (conn *ObjectScaleConn) Connect(cfg *ObjectScaleCfg) error {
	conn.Disconnect()
	conn.SetEndpoint(cfg.Endpoint)
	conn.SetUser(cfg.User)
	conn.SetPassword(cfg.Password)
	conn.SetIgnoreCert(cfg.BypassCert)
	err := conn.ObjectScaleSession.Connect()
	if err != nil {
		log.Print(fmt.Sprintf("[Connect] Unable to connect to API endpoint: %s\n", err))
		return err
	}
	//log.Print(fmt.Sprintf("[Connect] Connected with session ID: %s", conn.SessionToken))
	return nil
}

// Disconnect disconnects the connection to the endpoint. This is safe to call multiple times and even if a connect was never performed
func (conn *ObjectScaleConn) Disconnect() error {
	return conn.ObjectScaleSession.Disconnect()
}

// DoBasicIAMCall performs a simple POST and expects the response to be an ObjectScaleGeneralResponse
func (conn *ObjectScaleConn) DoBasicIAMCall(ns string, query map[string]string) (*ObjectScaleGeneralResponse, error) {
	jsonObj, err := conn.Send(
		"POST",
		apiPathIAM,
		query,                                  // query
		nil,                                    // body
		map[string]string{apiHdrNamespace: ns}, // extra headers
	)
	if err != nil {
		return nil, err
	}
	var result ObjectScaleGeneralResponse
	if err = mapstructure.Decode(jsonObj, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
