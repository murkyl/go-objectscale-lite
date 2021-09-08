package objectscalelite

import ()

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
