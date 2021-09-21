// Package objectscalelite provides a thin wrapper around native Go HTTP calls to handle
// ObjectScale session state.
// If a session expires the module will attempt to automatically re-authenticate
// Additional higher level wrappers are also availble as convenience functions
package objectscalelite

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	defaultAuthType       string = "iam"
	defaultConnTimeout    int    = 120
	defaultMaxReauthCount int    = 5
	headerSessionToken    string = "X-Sds-Auth-Token"
	headerAccept          string = "Accept"
	acceptApplicationJSON string = "application/json"
	sessionLoginPath      string = "login"
	sessionLogoutPath     string = "logout"
)

// ObjectScaleSession represents the state object for a connection
type ObjectScaleSession struct {
	User         string
	Password     string
	Endpoint     string
	AuthType     string
	IgnoreCert   bool
	SessionToken string
	SigningCtx   *V4SignerContext
	Client       *http.Client
	ConnTimeout  int
	reauthCount  int
}

// ObjectScaleCredentials holds the access ID, secret key, session token, and expiration
type ObjectScaleCredentials struct {
	AccessKeyID     string
	Expiration      string
	SecretAccessKey string
	SessionToken    string
}

// NewSession is a factory function returning a context object. This must be used in order to
// use any  of the other functions. This context can be modified by helper functions before
// connecting to the endpoint
func NewSession(endpoint string) *ObjectScaleSession {
	return &ObjectScaleSession{
		Endpoint:    endpoint,
		ConnTimeout: defaultConnTimeout,
		IgnoreCert:  false,
		AuthType:    defaultAuthType,
	}
}

// SetAuthType is a setter used to set the type of authentication used in the connect call. Valid values are "iam" and "basic"
func (ctx *ObjectScaleSession) SetAuthType(s string) string {
	old := ctx.AuthType
	ctx.AuthType = s
	return old
}

// SetConnTimeout is a setter used to set the timeout for the HTTP connection (http.Client)
func (ctx *ObjectScaleSession) SetConnTimeout(t int) int {
	old := ctx.ConnTimeout
	ctx.ConnTimeout = t
	return old
}

// SetEndpoint updates the endpoint that will be used for the connection
// The string passed in must include the protocol (http or https), end point, and port
// e.g. https://cluster.fqdn:8080
// If SetEndpoint is used after a connection has already been made you must disconnect
// and reconnect to use the new endpoint
func (ctx *ObjectScaleSession) SetEndpoint(s string) string {
	old := ctx.Endpoint
	ctx.Endpoint = s
	return old
}

// SetIgnoreCert is a setter used to set the flag to ignore or not ignore certificate checking
func (ctx *ObjectScaleSession) SetIgnoreCert(b bool) bool {
	old := ctx.IgnoreCert
	ctx.IgnoreCert = b
	return old
}

// SetPassword is a setter used to set the password in the session context
func (ctx *ObjectScaleSession) SetPassword(s string) string {
	old := ctx.Password
	ctx.Password = s
	return old
}

// SetSigningCtx is a setter used to set the AWS v4 signing context in the session context
func (ctx *ObjectScaleSession) SetSigningCtx(s V4SignerContext) *V4SignerContext {
	old := ctx.SigningCtx
	ctx.SigningCtx = &s
	return old
}

// SetUser is a setter used to set the user name in the session context
func (ctx *ObjectScaleSession) SetUser(s string) string {
	old := ctx.User
	ctx.User = s
	return old
}

// GetURL takes in a path and query argument to create a full URL based on the Endpoint
// in the ObjectScaleSession.
// path can be a string or a slice/array of strings
// query is map of strings in a basic key, value pair
func (ctx *ObjectScaleSession) GetURL(path interface{}, query map[string]string) string {
	x, _ := url.Parse(ctx.Endpoint)
	switch path.(type) {
	case []string:
		x.Path += strings.Join(path.([]string), "/")
	default:
		x.Path += path.(string)
	}
	// Manually create the query params as the standard Go query.Encode() wants to encode all reserved characters even if it is not necessary
	queryString := ""
	if query != nil {
		qArray := make([]string, 0, len(query))
		sortedKeys := make([]string, 0, len(query))
		for key := range query {
			sortedKeys = append(sortedKeys, key)
		}
		sort.Strings(sortedKeys)
		for _, key := range sortedKeys {
			qArray = append(qArray, queryEscape(key)+"="+queryEscape(query[key]))
		}
		queryString = "?" + strings.Join(qArray, "&")
	}
	return x.String() + queryString
}

// init is an internal helper function to create the http.Client object
func (ctx *ObjectScaleSession) init() error {
	if ctx.IgnoreCert {
		ctx.Client = &http.Client{
			Timeout: time.Duration(ctx.ConnTimeout) * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}
	} else {
		ctx.Client = &http.Client{
			Timeout: time.Duration(ctx.ConnTimeout) * time.Second,
		}
	}
	return nil
}

// Connect is called to initiate a connection to the endpoint. Connect can be called multiple times as
// the fucntion will automatically disconnect any existing connection. Changes to the endpoint can be
// made to the context and another Connect made to switch to the other endpoint.
func (ctx *ObjectScaleSession) Connect() error {
	// Cleanup any existing session before trying to connect
	ctx.Disconnect()
	// Automatically initialize the ObjectScaleSession
	ctx.init()
	if ctx.AuthType != "basic" {
		// No connection or session token is required if the authentication type is IAM as each request is signed
		return nil
	}
	req, err := http.NewRequest("GET", ctx.GetURL(sessionLoginPath, nil), nil)
	if err != nil {
		return fmt.Errorf("[Connect] Failed to create NewRequest: %v", err)
	}
	req.Header.Add(headerAccept, acceptApplicationJSON)
	req.SetBasicAuth(ctx.User, ctx.Password)
	resp, err := ctx.Client.Do(req)
	if err != nil {
		return fmt.Errorf("[Connect] Client.Do error: %v", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		defer resp.Body.Close()
		respBody, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("[Connect] Unable to create a session: %s", fmt.Sprintf("%+v", string(respBody)))
	}
	// The camel cased header is required due to HTTP library processing the headers
	if resp.Header[headerSessionToken] == nil {
		return fmt.Errorf("[Connect] No session token in response:\n%v", resp)
	}
	ctx.SessionToken = resp.Header[headerSessionToken][0]
	if ctx.SessionToken == "" {
		return fmt.Errorf("[Connect] Unable to get session token:\n%v", resp)
	}
	ctx.reauthCount = 0
	return nil
}

// Disconnect cleans up a connection to an endpoint. This should be called after calls to the API are completed
func (ctx *ObjectScaleSession) Disconnect() error {
	return ctx.DisconnectForce(false)
}

// DisconnectForce cleans up a connection to an endpoint. This call has a boolean that when set to true will
// disconnect any other sessions belonging to the user that created the session
func (ctx *ObjectScaleSession) DisconnectForce(force bool) error {
	if ctx.Client == nil || ctx.AuthType != "basic" {
		return nil
	}
	queryargs := map[string]string{}
	if force {
		queryargs = map[string]string{"force": "true"}
	}
	req, err := http.NewRequest("GET", ctx.GetURL(sessionLogoutPath, queryargs), nil)
	if err != nil {
		return fmt.Errorf("[Disconnect] Failed to crate NewRequest: %v", err)
	}
	setHeaders(req, ctx, nil)
	_, err = ctx.Client.Do(req)
	if err != nil {
		err = fmt.Errorf("[Disconnect] Session delete error: %v", err)
	}
	ctx.Client.CloseIdleConnections()
	ctx.Client = nil
	ctx.SessionToken = ""
	// This return takes the error code from the Client.Do above and returns it. Successful runs will return nil
	return err
}

// Reconnect is a simple helper function that calls Disconnect and then Connect in succession
func (ctx *ObjectScaleSession) Reconnect() error {
	ctx.Disconnect()
	return ctx.Connect()
}

// SendRaw makes a call to the API and returns the raw HTTP response and error codes. It is the responsibility
// of the caller to process the response.
func (ctx *ObjectScaleSession) SendRaw(method string, path interface{}, query map[string]string, body interface{}, headers map[string]string) (*http.Response, error) {
	return ctx.SendRawSigned(method, path, query, body, headers, nil)
}

// SendRawSigned makes a call to the API and returns the raw HTTP response and error codes. The function will also sign
// the request using the AWS v4 signature algorithm. It is the responsibility of the caller to process the response. The
// call will used the V4SignerContext in the context by default but a separate signing context can be used to override
// the default
func (ctx *ObjectScaleSession) SendRawSigned(method string, path interface{}, query map[string]string, body interface{}, headers map[string]string, signingCtx *V4SignerContext) (*http.Response, error) {
	var reqBody io.Reader
	switch body.(type) {
	case nil:
		reqBody = nil
	case []byte:
		reqBody = bytes.NewReader(body.([]byte))
	case string:
		reqBody = bytes.NewReader([]byte(body.(string)))
	default:
		reqBody = bytes.NewReader([]byte(body.(string)))
	}
	req, err := http.NewRequest(method, ctx.GetURL(path, query), reqBody)
	if err != nil {
		return nil, fmt.Errorf("[SendRawSgined] Request error: %v", err)
	}
	setHeaders(req, ctx, headers)
	if signingCtx != nil {
		signingCtx.V4SignRequest(req)
	} else if ctx.SigningCtx != nil {
		ctx.SigningCtx.V4SignRequest(req)
	}
	return ctx.Client.Do(req)
}

// Send performs an API call and does some automatic post-processing. This processing consists of converting the
// response into a JSON object in the form of a map[string]interface{}. This call will also attempt to automatically
// re-authenticate if a 401 response is returned.
func (ctx *ObjectScaleSession) Send(method string, path interface{}, query map[string]string, body interface{}, headers map[string]string) (map[string]interface{}, error) {
	return ctx.SendSigned(method, path, query, body, headers, nil)
}

// SendSigned performs an API call and does some automatic post-processing. The function will also sign the request
// using the AWS v4 signature algorithm. This processing consists of converting the response into a JSON object in the
// form of a map[string]interface{}. This call will also attempt to automatically re-authenticate if a 401 response is
// returned.
func (ctx *ObjectScaleSession) SendSigned(method string, path interface{}, query map[string]string, body interface{}, headers map[string]string, signingCtx *V4SignerContext) (map[string]interface{}, error) {
	jsonBody := make(map[string]interface{})
	resp, err := ctx.SendRawSigned(method, path, query, body, headers, signingCtx)
	if err != nil {
		return nil, fmt.Errorf("[SendSigned] Error returned by SendRawSigned: %v", err)
	}
	defer resp.Body.Close()
	rawBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("[SendSigned] Error reading response body: %v", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if resp.StatusCode == 401 {
			// If a 401 error with a message of "Authorization required" is received, we should automatically re-authenticate to get a new session token and retry the request
			if ctx.reauthCount >= defaultMaxReauthCount {
				log.Printf("[ERROR][SendSigned] Automatic re-authentication failed!")
			} else {
				time.Sleep(backoffTime(ctx.reauthCount, 0, nil))
				ctx.reauthCount++
				ctx.Reconnect()
				// Recursively call SendSigned with the same parameters and return the result. There is a limited number of re-auth attempts before failing the entire call
				return ctx.SendSigned(method, path, query, body, headers, signingCtx)
			}
		}
		return nil, fmt.Errorf("[SendSigned] Non 2xx response received (%d): %s", resp.StatusCode, fmt.Sprintf("%+v", string(rawBody)))
	}
	// If there is no body in the response, there is no need to try and process continuation requests
	// This can happen for some methods like DELETE
	if len(rawBody) == 0 || rawBody == nil {
		return nil, nil
	}
	if err := json.Unmarshal(rawBody, &jsonBody); err != nil {
		return nil, fmt.Errorf("[SendSigned] Error unmarshaling JSON: %v\nRaw body: %s", err, rawBody)
	}
	return jsonBody, nil
}

// setHeaders sets the headers for a request appropriately
// The function takes the request, ObjectScaleSession, and a map containing possible header key/value pairs
// The function first overwrites any existing headers in the request with those supplied in the headers parameter
// Only after this is done do we attempt to add in the session header. If these headers exist in the passed in
// headers array, they are not overridden. The values in the passed in headers map take precedence
func setHeaders(req *http.Request, ctx *ObjectScaleSession, headers map[string]string) {
	for k, v := range headers {
		// Manually set headers as we want to preserve the case sensitivity of each header
		req.Header[k] = []string{v}
	}
	defaultHeaders := map[string]string{
		headerAccept: acceptApplicationJSON,
	}
	if ctx.AuthType == "basic" {
		defaultHeaders[headerSessionToken] = ctx.SessionToken
	}
	for k, v := range defaultHeaders {
		if _, ok := req.Header[k]; !ok {
			req.Header.Add(k, v)
		}
	}
}

// backoffTime calculates the number of milliseconds to sleep given the number of retires already attempted
// backoffType determines the backoff algorithm. The available backoff types:
// 0: Exponential backoff, (2^retry)ms + (random[0-100))ms, max = 5 seconds
func backoffTime(retry int, backoffType int, backoffCfg *map[string]interface{}) time.Duration {
	backoff := 0
	maxBackoff := 5 * 1000
	switch backoffType {
	default:
		num, _ := rand.Int(rand.Reader, big.NewInt(100))
		backoff = 2 ^ retry + int(num.Int64())
	}
	if backoff > maxBackoff {
		backoff = maxBackoff
	}
	return time.Duration(backoff) * time.Millisecond
}

func queryEscape(q string) string {
	// There are a small subset of characters that must be escaped in the query portion of a URL
	// Those are "&" / "#" / "=" / "%"
	// These characters are delimiters for the key=value pairs, a delimiter for the fragment portion of the URL, a delimiter
	// for the key and value portions, and the escape character
	noPercent := strings.Replace(q, "%", "%25", -1)
	noEquals := strings.Replace(noPercent, "=", "%3D", -1)
	noHashes := strings.Replace(noEquals, "#", "%23", -1)
	noAmpersand := strings.Replace(noHashes, "&", "%26", -1)
	return noAmpersand
}
