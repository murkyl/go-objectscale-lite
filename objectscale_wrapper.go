package objectscalelite

import (
	"fmt"
	"github.com/mitchellh/mapstructure"
	"log"
	"strings"
)

const (
	apiHdrNamespace         string = "x-emc-namespace"
	apiOpAccessKeyID        string = "AccessKeyId"
	apiOpAction             string = "Action"
	apiOpUserName           string = "UserName"
	apiOpGroupName          string = "GroupName"
	apiOpPermissionBoundary string = "PermissionsBoundary"
	apiOpPolicyArn          string = "PolicyArn"
	apiOpRoleName           string = "RoleName"
	apiPathIAM              string = "iam"
)

// ObjectScaleCfg contains the configuration to connect to a OneFS cluster endpoint
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
	Marker              string
	MaxItems            int
	OnlyAttached        bool
	Path                string
	PathPrefix          string
	PermissionsBoundary string
	PolicyScope         string
	PolicyUsageFilter   string
	Tags                map[string]string
	UserName            string
}

// ObjectScaleGeneralResponse holds general response values for many function calls
type ObjectScaleGeneralResponse struct {
	ResponseMetadata struct {
		RequestID string
	}
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

// Connect performs the actual connection to the OneFS cluster endpoint given the endpoint configuration in a ObjectScaleCfg struct
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
	log.Print(fmt.Sprintf("[Connect] Connected with session ID: %s", conn.SessionToken))
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

// AddIAMUserToGroup adds a user to an already defined group in a specified namespace
func (conn *ObjectScaleConn) AddIAMUserToGroup(ns string, userName string, groupName string) (*ObjectScaleGeneralResponse, error) {
	return conn.DoBasicIAMCall(
		ns,
		map[string]string{
			apiOpAction:    "AddUserToGroup",
			apiOpUserName:  userName,
			apiOpGroupName: groupName,
		},
	)
}

// CreateIAMAccessKey creates a new access key for a user
func (conn *ObjectScaleConn) CreateIAMAccessKey(ns string, userName string) (*ObjectScaleIAMAccessKey, error) {
	query := map[string]string{
		apiOpAction:   "CreateAccessKey",
		apiOpUserName: userName,
	}
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
	var result struct {
		CreateAccessKeyResult struct{ AccessKey ObjectScaleIAMAccessKey }
	}
	if err = mapstructure.Decode(jsonObj, &result); err != nil {
		return nil, err
	}
	return &result.CreateAccessKeyResult.AccessKey, nil
}

// CreateIAMUser creates a new user in the specified namespace ns
func (conn *ObjectScaleConn) CreateIAMUser(ns string, userName string, qParams *ObjectScaleQueryParams) (*ObjectScaleIAMUser, error) {
	query := map[string]string{
		apiOpAction:   "CreateUser",
		apiOpUserName: userName,
	}
	if qParams != nil {
		if qParams.Path != "" {
			query["Path"] = qParams.Path
		}
		if qParams.PermissionsBoundary != "" {
			query[apiOpPermissionBoundary] = GetURNPolicyFromString(qParams.PermissionsBoundary)
		}
		if len(qParams.Tags) > 0 {
			i := 1
			for k, v := range qParams.Tags {
				query[fmt.Sprintf("Tags.member.%d.Key", i)] = k
				query[fmt.Sprintf("Tags.member.%d.Value", i)] = v
				i++
			}
		}
	}
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
	var result struct {
		CreateUserResult struct{ User ObjectScaleIAMUser }
	}
	if err = mapstructure.Decode(jsonObj, &result); err != nil {
		return nil, err
	}
	return &result.CreateUserResult.User, nil
}

// CreateIAMGroup creates a new group in the specified namespace ns
func (conn *ObjectScaleConn) CreateIAMGroup(ns string, groupName string, qParams *ObjectScaleQueryParams) (*ObjectScaleIAMGroup, error) {
	query := map[string]string{
		apiOpAction:    "CreateGroup",
		apiOpGroupName: groupName,
	}
	if qParams != nil {
		if qParams.Path != "" {
			query["Path"] = qParams.Path
		}
	}
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
	var result struct {
		CreateGroupResult struct{ Group ObjectScaleIAMGroup }
	}
	if err = mapstructure.Decode(jsonObj, &result); err != nil {
		return nil, err
	}
	return &result.CreateGroupResult.Group, nil
}

// DeleteIAMAccessKey deletes an access key from a user
func (conn *ObjectScaleConn) DeleteIAMAccessKey(ns string, userName string, accessKeyID string) (*ObjectScaleGeneralResponse, error) {
	return conn.DoBasicIAMCall(
		ns,
		map[string]string{
			apiOpAction:      "DeleteAccessKey",
			apiOpUserName:    userName,
			apiOpAccessKeyID: accessKeyID,
		},
	)
}

// DeleteIAMGroup deletes a group in the specified namespace ns
func (conn *ObjectScaleConn) DeleteIAMGroup(ns string, groupName string) (*ObjectScaleGeneralResponse, error) {
	return conn.DoBasicIAMCall(
		ns,
		map[string]string{
			apiOpAction:    "DeleteGroup",
			apiOpGroupName: groupName,
		},
	)
}

// DeleteIAMRole deletes a role in the specified namespace ns
func (conn *ObjectScaleConn) DeleteIAMRole(ns string, roleName string) (*ObjectScaleGeneralResponse, error) {
	return conn.DoBasicIAMCall(
		ns,
		map[string]string{
			apiOpAction:   "DeleteRole",
			apiOpRoleName: roleName,
		},
	)
}

// DeleteIAMUser deletes a user in the specified namespace. This user must not have any attached policies or
// belong to any groups. If any exist they must be cleaned up first before the delete user call will succeed
func (conn *ObjectScaleConn) DeleteIAMUser(ns string, userName string) (*ObjectScaleGeneralResponse, error) {
	return conn.DoBasicIAMCall(
		ns,
		map[string]string{
			apiOpAction:   "DeleteUser",
			apiOpUserName: userName,
		},
	)
}

// DeleteIAMUserForce will delete a user in a given namespace without first performing normal cleanup
// The fuction does the cleanup on the caller's behalf by removing the user from any groups and detaching
// any policies before removing the user account
func (conn *ObjectScaleConn) DeleteIAMUserForce(ns string, userName string) (*ObjectScaleGeneralResponse, error) {
	// Remove the user from any groups they belong
	groups, err := conn.ListIAMGroupsForUser(ns, userName, nil)
	if err != nil {
		return nil, fmt.Errorf("Unable to list groups for user %s\n%v", userName, err)
	}
	for _, elem := range groups.Groups {
		_, err := conn.RemoveIAMUserFromGroup(ns, userName, elem.GroupName)
		if err != nil {
			return nil, fmt.Errorf("Unable to remove group %s from user %s\n%v", elem.GroupName, userName, err)
		}
	}
	// Detach any policies
	policies, err := conn.ListIAMAttachedUserPolicies(ns, userName, nil)
	if err != nil {
		return nil, fmt.Errorf("Unable to list attached policies for user %s\n%v", userName, err)
	}
	for _, elem := range policies.AttachedPolicies {
		_, err := conn.DetachIAMUserPolicy(ns, userName, elem.PolicyArn)
		if err != nil {
			return nil, fmt.Errorf("Unable to detach policy %s from user %s\n%v", elem.PolicyArn, userName, err)
		}
	}
	// Delete any existing access keys
	keys, err := conn.ListIAMAccessKeys(ns, userName, nil)
	if err != nil {
		return nil, fmt.Errorf("Unable to list access keys for user %s\n%v", userName, err)
	}
	for _, elem := range keys.AccessKeyMetadata {
		_, err := conn.DeleteIAMAccessKey(ns, userName, elem.AccessKeyID)
		if err != nil {
			return nil, fmt.Errorf("Unable to delete access key %s from user %s\n%v", elem.AccessKeyID, userName, err)
		}
	}

	return conn.DeleteIAMUser(ns, userName)
}

// DeleteIAMUserPermissionsBoundary deletes the permission boundary from a user in the specified namespace ns
func (conn *ObjectScaleConn) DeleteIAMUserPermissionsBoundary(ns string, userName string) (*ObjectScaleGeneralResponse, error) {
	return conn.DoBasicIAMCall(
		ns,
		map[string]string{
			apiOpAction:   "DeleteUserPermissionsBoundary",
			apiOpUserName: userName,
		},
	)
}

// ListIAMAccessKeys returns a list of access keys for a user
func (conn *ObjectScaleConn) ListIAMAccessKeys(ns string, userName string, qParams *ObjectScaleQueryParams) (*ObjectScaleListIAMAccessKeys, error) {
	query := map[string]string{
		apiOpAction:   "ListAccessKeys",
		apiOpUserName: userName,
	}
	if qParams != nil {
		if qParams.Marker != "" {
			query["Marker"] = qParams.Marker
		}
		if qParams.MaxItems != 0 {
			query["MaxItems"] = fmt.Sprintf("%d", qParams.MaxItems)
		}
		if qParams.PathPrefix != "" {
			query["PathPrefix"] = qParams.PathPrefix
		}
	}
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
	var result struct{ ListAccessKeysResult ObjectScaleListIAMAccessKeys }
	if err = mapstructure.Decode(jsonObj, &result); err != nil {
		return nil, err
	}
	return &result.ListAccessKeysResult, nil
}

// ListIAMGroupsForUser returns a list of groups that a user belongs in the specified namespace ns
func (conn *ObjectScaleConn) ListIAMGroupsForUser(ns string, userName string, qParams *ObjectScaleQueryParams) (*ObjectScaleListIAMUserGroup, error) {
	query := map[string]string{
		apiOpAction:   "ListGroupsForUser",
		apiOpUserName: userName,
	}
	if qParams != nil {
		if qParams.Marker != "" {
			query["Marker"] = qParams.Marker
		}
		if qParams.MaxItems != 0 {
			query["MaxItems"] = fmt.Sprintf("%d", qParams.MaxItems)
		}
	}
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
	var result struct{ ListGroupsForUserResult ObjectScaleListIAMUserGroup }
	if err = mapstructure.Decode(jsonObj, &result); err != nil {
		return nil, err
	}
	return &result.ListGroupsForUserResult, nil
}

// ListIAMUsers returns a list of users in the namespace ns
func (conn *ObjectScaleConn) ListIAMUsers(ns string, qParams *ObjectScaleQueryParams) (*ObjectScaleListIAMUser, error) {
	query := map[string]string{
		apiOpAction: "ListUsers",
	}
	if qParams != nil {
		if qParams.Marker != "" {
			query["Marker"] = qParams.Marker
		}
		if qParams.MaxItems != 0 {
			query["MaxItems"] = fmt.Sprintf("%d", qParams.MaxItems)
		}
		if qParams.PathPrefix != "" {
			query["PathPrefix"] = qParams.PathPrefix
		}
	}
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
	var result struct{ ListUsersResult ObjectScaleListIAMUser }
	if err = mapstructure.Decode(jsonObj, &result); err != nil {
		return nil, err
	}
	return &result.ListUsersResult, err
}

// PutIAMUserPermissionsBoundary adds a permission boundary URN to a user
func (conn *ObjectScaleConn) PutIAMUserPermissionsBoundary(ns string, userName string, boundary string) (*ObjectScaleGeneralResponse, error) {
	return conn.DoBasicIAMCall(
		ns,
		map[string]string{
			apiOpAction:             "PutUserPermissionsBoundary",
			apiOpUserName:           userName,
			apiOpPermissionBoundary: GetURNPolicyFromString(boundary),
		},
	)
}

// RemoveIAMUserFromGroup removes a user from a group in the specified namespace ns
func (conn *ObjectScaleConn) RemoveIAMUserFromGroup(ns string, userName string, groupName string) (*ObjectScaleGeneralResponse, error) {
	return conn.DoBasicIAMCall(
		ns,
		map[string]string{
			apiOpAction:    "RemoveUserFromGroup",
			apiOpUserName:  userName,
			apiOpGroupName: groupName,
		},
	)
}
