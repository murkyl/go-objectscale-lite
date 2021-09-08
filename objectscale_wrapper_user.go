package objectscalelite

import (
	"fmt"
	"github.com/mitchellh/mapstructure"
	"strings"
)

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
			query[apiOpPath] = qParams.Path
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

// DeleteIAMAccessKeyAll deletes all access keys from a user
func (conn *ObjectScaleConn) DeleteIAMAccessKeyAll(ns string, userName string) error {
	var errList []string
	keyList, err := conn.ListIAMAccessKeys(ns, userName, nil)
	if err != nil {
		return err
	}
	for _, keyMeta := range keyList.AccessKeyMetadata {
		_, err := conn.DeleteIAMAccessKey(ns, userName, keyMeta.AccessKeyID)
		if err != nil {
			errList = append(errList, fmt.Sprintf("Unable to delete access key %s for user %s in namespace %s: %v", keyMeta.AccessKeyID, userName, ns, err))
		}
	}
	if len(errList) > 0 {
		return fmt.Errorf(strings.Join(errList, "\n"))
	}
	return nil
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
// The function does the cleanup on the caller's behalf by removing the user from any groups and detaching
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
			query[apiOpMarker] = qParams.Marker
		}
		if qParams.MaxItems != 0 {
			query[apiOpMaxItems] = fmt.Sprintf("%d", qParams.MaxItems)
		}
		if qParams.PathPrefix != "" {
			query[apiOpPathPrefix] = qParams.PathPrefix
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
			query[apiOpMarker] = qParams.Marker
		}
		if qParams.MaxItems != 0 {
			query[apiOpMaxItems] = fmt.Sprintf("%d", qParams.MaxItems)
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
			query[apiOpMarker] = qParams.Marker
		}
		if qParams.MaxItems != 0 {
			query[apiOpMaxItems] = fmt.Sprintf("%d", qParams.MaxItems)
		}
		if qParams.PathPrefix != "" {
			query[apiOpPathPrefix] = qParams.PathPrefix
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
