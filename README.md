# go-objectscale-lite

go-objectscale-lite is a lightweight wrapper around native Go HTTP calls to interact with a DellEMC ECS/ObjectScale
object store. The wrapper handles session creation and tear down if required and can also use AWS v4 signatures to
sign requests. If a session expires the module will attempt to automatically re-authenticate.
The library is split into 2 sections. The most basic part of the library handles the session and provides basic send commands. The second part of the library wraps the session and send command and provides functions that encapsulate parsing of the responses returned from the API.

## Basic code

This library is designed to access the management and configuration APIs rather than perform data access. The basic library handles connections for both DellEMC ECS namespace access as well as IAM access for ObjectScale. When accessing a namespace a connection is required with a user name and password. For access to an ObjectScale endpoint an IAM access ID and secret are required instead and passed in as a signing context.
The library can handle automatic reconnects for sessions and signing requests for IAM.

## Examples for basic usage

Using a namespace user to list available users in a namespace. Returned result is a raw JSON object which is a map[string]interface{}.

```go
conn := NewSession("[https://endpoint.com:4443](https://endpoint.com:4443)")
conn.SetAuthType("basic")
conn.SetIgnoreCert(true)
conn.SetPassword("user_password")
conn.SetUser("api_user")
if err := conn.Connect(); err != nil {
	fmt.Printf("Unable to connect to API endpoint: %s\n", err)
}
query := map[string]string{
	apiOpAction: "ListUsers",
}
jsonObj, err := conn.Send(
	"POST",
	"iam", // path
	query, // query
	nil,   // body
	map[string]string{"x-emc-namespace": "some_namespace"}, // extra headers
)
conn.Disconnect()
```

Using an IAM user to list available users in a namespace.  Returned result is a raw JSON object which is a map[string]interface{}.

```go
conn := NewSession("[https://endpoint.com:4443](https://endpoint.com:4443)")
conn.SetAuthType("iam")
conn.SetIgnoreCert(true)
conn.SetSigningCtx(NewV4SignerContext("iam_access_id", "iam_secret", "", ""))
if err := conn.Connect(); err != nil {
	fmt.Printf("Unable to connect to API endpoint: %s\n", err)
}
query := map[string]string{
	apiOpAction: "ListUsers",
}
jsonObj, err := conn.Send(
	"POST",
	"iam", // path
	query, // query
	nil,   // body
	map[string]string{"x-emc-namespace": "some_namespace"}, // extra headers
)
conn.Disconnect()
```

## Wrapper code

Wrapper functions return results in a structure for easy access.

Using an IAM user to list available users in a namespace.

```go
conn := NewObjectScaleConn()
err := conn.Connect(&ObjectScaleCfg{
	AuthType:   "iam",
	Endpoint:   "[https://endpoint.com:4443](https://endpoint.com:4443)",
	BypassCert: true,
	SigningCtx: NewV4SignerContext("iam_access_id", "iam_secret", "", ""),
})
data, err := conn.ListIAMUsers("some_namespace", nil)
if err != nil {
	fmt.Printf("Error getting IAM user list: %s\n", err)
}
for _, user := range data.Users {
	fmt.Printf("User: %s", user.UserName)
}
conn.Disconnect()
```
