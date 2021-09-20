package objectscalelite

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"testing"
)

func envOrDefault(name string, defValue string) string {
	value, exist := os.LookupEnv(name)
	if exist == false {
		return defValue
	}
	return value
}

func envOrFail(t *testing.T, name string) string {
	value, exist := os.LookupEnv(name)
	if exist == false {
		t.Fatal("To run tests you must provide environment variables USER, PASSWORD, ENDPOINT, and NAMESPACE. CERT variable is optional.")
	}
	return value
}

var (
	TestUser          string
	TestPassword      string
	TestEndpoint      string
	TestBypassCert    bool
	TestNamespace     string
	TestIAMUser       string
	TestIAMGroupBase  string
	TestIAMGroupCount int
)

func TestSetup(t *testing.T) {
	TestUser = envOrFail(t, "USER")
	TestPassword = envOrFail(t, "PASSWORD")
	TestEndpoint = envOrFail(t, "ENDPOINT")
	TestBypassCert, _ = strconv.ParseBool(envOrDefault("CERT", "true"))
	TestNamespace = envOrFail(t, "NAMESPACE")
	TestIAMUser = envOrDefault("TESTUSER", "testuser")
	TestIAMGroupBase = envOrDefault("TESTGROUP", "testgroup")
	TestIAMGroupCount, _ = strconv.Atoi(envOrDefault("GROUPCOUNT", "3"))
}

func TestSessionConnectAndDisconnect(t *testing.T) {
	TestSetup(t)
	conn := NewSession(TestEndpoint)
	conn.SetAuthType("basic")
	conn.SetIgnoreCert(true)
	conn.SetPassword(TestPassword)
	conn.SetUser(TestUser)
	if err := conn.Connect(); err != nil {
		log.Print(fmt.Sprintf("Unable to connect to API endpoint: %s\n", err))
		return
	}
	log.Print(fmt.Sprintf("Connected with session ID: %s", conn.SessionToken))
	conn.Disconnect()
}

func TestIAMUserList(t *testing.T) {
	TestSetup(t)
	conn := NewSession(TestEndpoint)
	conn.SetAuthType("iam")
	conn.SetIgnoreCert(true)
	conn.SetPassword(TestPassword)
	conn.SetUser(TestUser)
	conn.SetSigningCtx(NewV4SignerContext(TestUser, TestPassword, "", ""))
	if err := conn.Connect(); err != nil {
		log.Print(fmt.Sprintf("Unable to connect to API endpoint: %s\n", err))
		return
	}
	query := map[string]string{
		apiOpAction: "ListUsers",
	}
	jsonObj, err := conn.Send(
		"POST",
		apiPathIAM,
		query,                                  // query
		nil,                                    // body
		map[string]string{apiHdrNamespace: TestNamespace}, // extra headers
	)
	if err != nil {
		t.Fatal(fmt.Sprintf("Error in request: %v", err))
	}
	t.Logf("JSON response: %v", jsonObj)
	conn.Disconnect()
}
