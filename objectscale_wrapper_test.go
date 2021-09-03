package objectscalelite

import (
	"fmt"
  "strconv"
	"testing"
)

func TestSetupWrapper(t *testing.T) {
	TestUser = envOrFail(t, "USER")
	TestPassword = envOrFail(t, "PASSWORD")
	TestEndpoint = envOrFail(t, "ENDPOINT")
	TestBypassCert, _ = strconv.ParseBool(envOrDefault("CERT", "true"))
	TestNamespace = envOrFail(t, "NAMESPACE")
	TestIAMUser = envOrDefault("TESTUSER", "testuser")
	TestIAMGroupBase = envOrDefault("TESTGROUP", "testgroup")
	TestIAMGroupCount, _ = strconv.Atoi(envOrDefault("GROUPCOUNT", "3"))
}

func testConnect(t *testing.T) *ObjectScaleConn {
	conn := NewObjectScaleConn()
	err := conn.Connect(&ObjectScaleCfg{
		User:       TestUser,
		Password:   TestPassword,
		Endpoint:   TestEndpoint,
		BypassCert: TestBypassCert,
	})
	if err != nil {
		t.Logf(fmt.Sprintf("Unable to connect to API endpoint: %s\n", err))
		return nil
	}
	return conn
}

func testDisconnect(t *testing.T, conn *ObjectScaleConn) {
	err := conn.Disconnect()
	if err != nil {
		t.Logf("Error disconnecting: %v", err)
	}
}

func TestWrapperSessionConnectAndDisconnect(t *testing.T) {
	var conn *ObjectScaleConn
	if conn = testConnect(t); conn == nil {
		t.Fail()
		return
	}
	testDisconnect(t, conn)
}

func TestWrapperListIAMUsers(t *testing.T) {
	var conn *ObjectScaleConn
	if conn = testConnect(t); conn == nil {
		t.Fail()
		return
	}
	data, err := conn.ListIAMUsers(TestNamespace, nil)
	if err != nil {
		t.Logf("Error getting IAM user list: %v", err)
		t.Fail()
		return
	}
	t.Logf("IAM user list: %v\n", data)
	testDisconnect(t, conn)
}

func TestWrapperListIAMPolicies(t *testing.T) {
	var conn *ObjectScaleConn
	if conn = testConnect(t); conn == nil {
		t.Fail()
		return
	}
	data, err := conn.ListIAMPolicies(TestNamespace, nil)
	if err != nil {
		t.Logf("Error getting IAM policy list: %v", err)
		t.Fail()
		return
	}
	t.Logf("IAM policy list: %v\n", data)
	testDisconnect(t, conn)
}

func TestWrapperCreateIAMGroups(t *testing.T) {
	var conn *ObjectScaleConn
	if conn = testConnect(t); conn == nil {
		t.Fail()
		return
	}
	for i := 0; i < TestIAMGroupCount; i++ {
		_, err := conn.CreateIAMGroup(TestNamespace, fmt.Sprintf("%s%d", TestIAMGroupBase, i), nil)
		if err != nil {
			t.Logf("Error creating IAM group: %v", err)
			t.Fail()
			return
		}
	}
	testDisconnect(t, conn)
}

func TestWrapperCreateIAMUser(t *testing.T) {
	var conn *ObjectScaleConn
	if conn = testConnect(t); conn == nil {
		t.Fail()
		return
	}
	data, err := conn.CreateIAMUser(TestNamespace, TestIAMUser, &ObjectScaleQueryParams{
		Tags: map[string]string{
			"Foo":  "bar",
			"Test": "Data",
		},
	})
	if err != nil {
		t.Logf("Error getting IAM user list: %v", err)
		t.Fail()
		return
	}
	t.Logf("Create User Result: %v\n", data)
	testDisconnect(t, conn)
}

func TestWrapperAttachIAMUserPolicy(t *testing.T) {
	var conn *ObjectScaleConn
	if conn = testConnect(t); conn == nil {
		t.Fail()
		return
	}
	data, err := conn.AttachIAMUserPolicy(TestNamespace, TestIAMUser, "apj:andy")
	if err != nil {
		t.Logf("Error attaching IAM user policy: %v", err)
		t.Fail()
		return
	}
	t.Logf("Attach Policy Result: %v\n", data)
	testDisconnect(t, conn)
}

func TestWrapperAddIAMUserToGroup(t *testing.T) {
	var conn *ObjectScaleConn
	if conn = testConnect(t); conn == nil {
		t.Fail()
		return
	}
	for i := 0; i < TestIAMGroupCount; i++ {
		_, err := conn.AddIAMUserToGroup(TestNamespace, TestIAMUser, fmt.Sprintf("%s%d", TestIAMGroupBase, i))
		if err != nil {
			t.Logf("Error adding IAM user to group: %v", err)
			t.Fail()
			return
		}
	}
	testDisconnect(t, conn)
}

func TestWrapperDeleteIAMUser(t *testing.T) {
	var conn *ObjectScaleConn
	if conn = testConnect(t); conn == nil {
		t.Fail()
		return
	}
	delResponse, err := conn.DeleteIAMUserForce(TestNamespace, TestIAMUser)
	if err != nil {
		t.Logf("Error deleting IAM user: %v", err)
		t.Fail()
		return
	}
	t.Logf("Delete User Result: %v\n", delResponse)
	testDisconnect(t, conn)
}
