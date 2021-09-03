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
		t.Fatal("To run tests you must provide environment variables USER, PASSWORD, ENDPOINT, and NAMESPACE")
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
	conn := NewSession("")
	conn.SetEndpoint(TestEndpoint)
	conn.SetUser(TestUser)
	conn.SetPassword(TestPassword)
	conn.SetIgnoreCert(true)
	err := conn.Connect()
	if err != nil {
		log.Print(fmt.Sprintf("Unable to connect to API endpoint: %s\n", err))
		return
	}
	log.Print(fmt.Sprintf("Connected with session ID: %s", conn.SessionToken))
	conn.Disconnect()
}
