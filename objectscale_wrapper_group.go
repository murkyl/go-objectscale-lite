package objectscalelite

import (
	"github.com/mitchellh/mapstructure"
)

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

// CreateIAMGroup creates a new group in the specified namespace ns
func (conn *ObjectScaleConn) CreateIAMGroup(ns string, groupName string, qParams *ObjectScaleQueryParams) (*ObjectScaleIAMGroup, error) {
	query := map[string]string{
		apiOpAction:    "CreateGroup",
		apiOpGroupName: groupName,
	}
	if qParams != nil {
		if qParams.Path != "" {
			query[apiOpPath] = qParams.Path
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
