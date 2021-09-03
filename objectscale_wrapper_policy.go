package objectscalelite

import (
	"fmt"
	"github.com/mitchellh/mapstructure"
)

// ObjectScaleIAMPolicy represents a single IAM policy
type ObjectScaleIAMPolicy struct {
	Arn                          string
	AttachmentCount              int
	CreateDate                   string
	DefaultVersionID             string
	Description                  string
	IsAttachable                 bool
	Path                         string
	PermissionBoundaryUsageCount int
	PolicyArn                    string `json:"omitempty"`
	PolicyID                     string
	PolicyName                   string
	UpdateDate                   string
}

// ObjectScaleListIAMUserPolicies represents a list of user policies
type ObjectScaleListIAMUserPolicies struct {
	ObjectScaleList
	PolicyNames []string
}

// ObjectScaleListIAMAttachedUserPolicies represents a list of policies that are attached to a user
type ObjectScaleListIAMAttachedUserPolicies struct {
	ObjectScaleList
	AttachedPolicies []ObjectScaleIAMPolicy
}

// ObjectScaleListIAMPolicy represents a list of policies
type ObjectScaleListIAMPolicy struct {
	ObjectScaleList
	Policies []ObjectScaleIAMPolicy
}

// AttachIAMGroupPolicy adds a policy to a group
func (conn *ObjectScaleConn) AttachIAMGroupPolicy(ns string, groupName string, policy string) (*ObjectScaleGeneralResponse, error) {
	return conn.DoBasicIAMCall(
		ns,
		map[string]string{
			apiOpAction:    "AttachGroupPolicy",
			apiOpGroupName: groupName,
			apiOpPolicyArn: GetURNPolicyFromString(policy),
		},
	)
}

// AttachIAMRolePolicy adds a policy to a role
func (conn *ObjectScaleConn) AttachIAMRolePolicy(ns string, roleName string, policy string) (*ObjectScaleGeneralResponse, error) {
	return conn.DoBasicIAMCall(
		ns,
		map[string]string{
			apiOpAction:    "AttachRolePolicy",
			apiOpGroupName: roleName,
			apiOpPolicyArn: GetURNPolicyFromString(policy),
		},
	)
}

// AttachIAMUserPolicy adds a policy to a user
func (conn *ObjectScaleConn) AttachIAMUserPolicy(ns string, userName string, policy string) (*ObjectScaleGeneralResponse, error) {
	return conn.DoBasicIAMCall(
		ns,
		map[string]string{
			apiOpAction:    "AttachUserPolicy",
			apiOpUserName:  userName,
			apiOpPolicyArn: GetURNPolicyFromString(policy),
		},
	)
}

// DeleteIAMGroupPolicy deletes a group policy
func (conn *ObjectScaleConn) DeleteIAMGroupPolicy(ns string, groupName string, policy string) (*ObjectScaleGeneralResponse, error) {
	return conn.DoBasicIAMCall(
		ns,
		map[string]string{
			apiOpAction:    "DeleteGroupPolicy",
			apiOpGroupName: groupName,
			apiOpPolicyArn: GetURNPolicyFromString(policy),
		},
	)
}

// DeleteIAMPolicy deletes a policy
func (conn *ObjectScaleConn) DeleteIAMPolicy(ns string, policy string) (*ObjectScaleGeneralResponse, error) {
	return conn.DoBasicIAMCall(
		ns,
		map[string]string{
			apiOpAction:    "DeletePolicy",
			apiOpPolicyArn: GetURNPolicyFromString(policy),
		},
	)
}

// DeleteIAMRolePolicy deletes a role policy
func (conn *ObjectScaleConn) DeleteIAMRolePolicy(ns string, roleName string, policy string) (*ObjectScaleGeneralResponse, error) {
	return conn.DoBasicIAMCall(
		ns,
		map[string]string{
			apiOpAction:    "DeleteRolePolicy",
			apiOpRoleName:  roleName,
			apiOpPolicyArn: GetURNPolicyFromString(policy),
		},
	)
}

// DeleteIAMUserPolicy deletes a user policy
func (conn *ObjectScaleConn) DeleteIAMUserPolicy(ns string, userName string, policy string) (*ObjectScaleGeneralResponse, error) {
	return conn.DoBasicIAMCall(
		ns,
		map[string]string{
			apiOpAction:    "DeleteUserPolicy",
			apiOpUserName:  userName,
			apiOpPolicyArn: GetURNPolicyFromString(policy),
		},
	)
}

// DetachIAMGroupPolicy removes a policy attched to a group
func (conn *ObjectScaleConn) DetachIAMGroupPolicy(ns string, groupName string, policy string) (*ObjectScaleGeneralResponse, error) {
	return conn.DoBasicIAMCall(
		ns,
		map[string]string{
			apiOpAction:    "DetachGroupPolicy",
			apiOpGroupName: groupName,
			apiOpPolicyArn: GetURNPolicyFromString(policy),
		},
	)
}

// DetachIAMRolePolicy removes a policy attached to a role
func (conn *ObjectScaleConn) DetachIAMRolePolicy(ns string, roleName string, policy string) (*ObjectScaleGeneralResponse, error) {
	return conn.DoBasicIAMCall(
		ns,
		map[string]string{
			apiOpAction:    "DetachRolePolicy",
			apiOpRoleName:  roleName,
			apiOpPolicyArn: GetURNPolicyFromString(policy),
		},
	)
}

// DetachIAMUserPolicy removes a policy attached to a user
func (conn *ObjectScaleConn) DetachIAMUserPolicy(ns string, userName string, policy string) (*ObjectScaleGeneralResponse, error) {
	return conn.DoBasicIAMCall(
		ns,
		map[string]string{
			apiOpAction:    "DetachUserPolicy",
			apiOpUserName:  userName,
			apiOpPolicyArn: GetURNPolicyFromString(policy),
		},
	)
}

// ListIAMPolicies returns a list of policies
func (conn *ObjectScaleConn) ListIAMPolicies(ns string, qParams *ObjectScaleQueryParams) (*ObjectScaleListIAMPolicy, error) {
	query := map[string]string{
		apiOpAction: "ListPolicies",
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
		query["OnlyAttached"] = fmt.Sprintf("%t", qParams.OnlyAttached)
		if qParams.PolicyUsageFilter != "" {
			query["PolicyUsageFilter"] = qParams.PolicyUsageFilter
		}
		if qParams.PolicyScope != "" {
			query["PolicyScope"] = qParams.PolicyScope
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
	var result struct{ ListPoliciesResult ObjectScaleListIAMPolicy }
	if err = mapstructure.Decode(jsonObj, &result); err != nil {
		return nil, err
	}
	return &result.ListPoliciesResult, nil
}

// ListIAMUserPolicies returns a list of user policies
func (conn *ObjectScaleConn) ListIAMUserPolicies(ns string, userName string, qParams *ObjectScaleQueryParams) (*ObjectScaleListIAMUserPolicies, error) {
	query := map[string]string{
		apiOpAction:   "ListUserPolicies",
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
	var result struct {
		ListUserPoliciesResult ObjectScaleListIAMUserPolicies
	}
	if err = mapstructure.Decode(jsonObj, &result); err != nil {
		return nil, err
	}
	return &result.ListUserPoliciesResult, nil
}

// ListIAMAttachedUserPolicies returns a list of policies that are attached to a user
func (conn *ObjectScaleConn) ListIAMAttachedUserPolicies(ns string, userName string, qParams *ObjectScaleQueryParams) (*ObjectScaleListIAMAttachedUserPolicies, error) {
	query := map[string]string{
		apiOpAction:   "ListAttachedUserPolicies",
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
	var result struct {
		ListAttachedUserPoliciesResult ObjectScaleListIAMAttachedUserPolicies
	}
	if err = mapstructure.Decode(jsonObj, &result); err != nil {
		return nil, err
	}
	return &result.ListAttachedUserPoliciesResult, nil
}
