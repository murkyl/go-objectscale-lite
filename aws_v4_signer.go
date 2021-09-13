package objectscalelite

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	// V4SignerEmptySHA256 is the SHA256 hash of an empty string. Use this to avoid hashing an empty string
	V4SignerEmptySHA256 string = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	// V4SignerTimeFormat is the format for a long format timestamp
	V4SignerTimeFormat string = "20060102T150405Z"
	// V4SignerTimeFormatShort is the format for a short format timestamp
	V4SignerTimeFormatShort     string = "20060102"
	v4SignerSignaturePrefix     string = "AWS4"
	v4SignerAlgorithm           string = "AWS4-HMAC-SHA256"
	v4SignerRequest             string = "aws4_request"
	v4SignerHdrAmzDate          string = "X-Amz-Date"
	v4SignerHdrAmzContentSha256 string = "X-Amz-Content-Sha256"
	v4SignerHdrAuthorization    string = "Authorization"
	v4SignerHdrHost             string = "Host"
)

var (
	v4SignerTrimspace *regexp.Regexp = regexp.MustCompile(" {2,}")
)

// V4SignerContext stores the context user to sign HTTP requests
type V4SignerContext struct {
	AccessKey     string
	Secret        string
	Region        string
	Service       string
	FixedDate     time.Time
	SignedHeaders []*regexp.Regexp
}

// NewV4SignerContext returns a context struct that can be used to sign HTTP requests
func NewV4SignerContext(access string, secret string, region string, service string) V4SignerContext {
	return V4SignerContext{
		AccessKey:     access,
		Secret:        secret,
		Region:        region,
		Service:       service,
		SignedHeaders: GetV4DefaultSignedHeaders(),
	}
}

// V4SignRequest will sign an HTTP request based on https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
// The request will be modified with additional headers as required for the signing.
// If the request has a body, the Content-Length and X-Amz-Content-Sha256 will be properly
// populated. If you do not want the signer to calculate the Sha256 of the body you must include
// the X-Amz-Content-Sha256 header manually before calling V4SignRequest
// The signer defaults to using the current time when signing the request. If a specific time is required
// for the signing set the V4SignerContext member FixedDate to a time.Time object.
func (ctx *V4SignerContext) V4SignRequest(req *http.Request) string {
	datestamp := ctx.FixedDate
	payloadHash := V4SignerEmptySHA256
	if !datestamp.IsZero() {
		// If a fixed date for the request is requested, set the X-Amz-Date header so CreateV4CanonicalHeader does not generate an automatic date
		req.Header.Set(v4SignerHdrAmzDate, datestamp.Format(V4SignerTimeFormat))
	}
	// Check if a SHA256 of the body is required
	if req.Body != nil {
		if _, ok := req.Header[v4SignerHdrAmzContentSha256]; !ok {
			// TODO: Need to do body SHA256
			//req.Header.Add(v4SignerHdrAmzContentSha256, "HashValueHere")
		} else {
			payloadHash = req.Header.Get(v4SignerHdrAmzContentSha256)
		}
	}
	// Generate the main components needed to be signed
	canonicalURI := CreateV4CanonicalURIString(req)
	canonicalQuery := CreateV4CanonicalQueryString(req)
	headerList, canonicalHeaders := CreateV4CanonicalHeader(req, GetV4DefaultSignedHeaders())
	datestamp, _ = time.Parse(V4SignerTimeFormat, req.Header.Get(v4SignerHdrAmzDate))
	signingTime := datestamp.Format(V4SignerTimeFormatShort)
	// Start building more composite strings to be signed
	canonicalRequest := req.Method + "\n" + canonicalURI + "\n" + canonicalQuery + "\n" + canonicalHeaders + "\n" + headerList + "\n" + payloadHash
	credentialScope := signingTime + "/" + ctx.Region + "/" + ctx.Service + "/" + v4SignerRequest
	stringToSign := v4SignerAlgorithm + "\n" + req.Header.Get(v4SignerHdrAmzDate) + "\n" + credentialScope + "\n" + GetSha256Hex([]byte(canonicalRequest))
	// Create the signing key and sign the request
	signingKey := GetV4SignatureKey(ctx.Secret, signingTime, ctx.Region, ctx.Service)
	signature := GetHmacSha256Hex(signingKey, []byte(stringToSign))
	// Add the header with the signature to the request
	req.Header.Add(
		v4SignerHdrAuthorization,
		v4SignerAlgorithm+" Credential="+ctx.AccessKey+"/"+credentialScope+", SignedHeaders="+headerList+", Signature="+signature,
	)
	return signature
}

// CreateV4CanonicalHeader returns a 2-tuple of strings that consist of a list of signed headers
// separated by a ; (semicolon) and a string with all the headers and their values concatenated together
// separated by a \n (line feed) character.
// The list of regular expressions is used to determine which fields in the HTTP header need to be
// signed. A default list can be generated with the GetV4DefaultSignedHeaders function.
// This function will modify the incoming request and add a Host and X-Amz-Date header to the request
// if they do not exist.
func CreateV4CanonicalHeader(req *http.Request, headerRegex []*regexp.Regexp) (string, string) {
	var listHeaderNames []string
	var signedHeaderStrings []string
	signedHeaders := make(http.Header)
	// Iterate over all the request headers and save headers that match regexp array
	for k, v := range req.Header {
		if !isSignedHeader(k, headerRegex) {
			continue
		}
		lkey := strings.ToLower(k)
		if _, ok := signedHeaders[lkey]; ok {
			// Multiple headers of the same name occurred. Save the values in an array to concatenate later
			// This is a duplicate header there is no need to save the header name again so we continue
			signedHeaders[lkey] = append(signedHeaders[lkey], v...)
			continue
		}
		listHeaderNames = append(listHeaderNames, lkey)
		signedHeaders[lkey] = v
	}
	if _, ok := signedHeaders[strings.ToLower(v4SignerHdrHost)]; !ok {
		listHeaderNames = append(listHeaderNames, strings.ToLower(v4SignerHdrHost))
	}
	if _, ok := signedHeaders[strings.ToLower(v4SignerHdrAmzDate)]; !ok {
		listHeaderNames = append(listHeaderNames, strings.ToLower(v4SignerHdrAmzDate))
	}
	// Sort the headers according to AWS requirements
	sort.Strings(listHeaderNames)
	// Using the header names, get all the values and create the canonical header string
	for _, headerName := range listHeaderNames {
		if headerName == "host" {
			// If there is already a host header, do not auto generate
			if len(signedHeaders[headerName]) < 1 {
				if req.Host != "" {
					req.Header.Set(v4SignerHdrHost, req.Host)
				} else {
					req.Header.Set(v4SignerHdrHost, req.URL.Host)
				}
				// Fix up the signedHeaders array to include the host
				signedHeaders[headerName] = append(signedHeaders[headerName], req.Header.Get(v4SignerHdrHost))
			}
		} else if headerName == "x-amz-date" {
			// If there is already an x-amz-date header, do not auto generate
			if len(signedHeaders[headerName]) < 1 {
				// Auto generate the time. If an HTTP date header exists use that otherwise use the current time
				amzDate := time.Now().Truncate(time.Second).UTC()
				httpDate := req.Header.Get("Date")
				if httpDate != "" {
					t, err := time.Parse(http.TimeFormat, httpDate)
					if err == nil {
						amzDate = t
					}
				}
				req.Header.Set(v4SignerHdrAmzDate, amzDate.Format(V4SignerTimeFormat))
				// Fix up the signedHeaders array to include the x-amz-date
				signedHeaders[headerName] = append(signedHeaders[headerName], req.Header.Get(v4SignerHdrAmzDate))
			}
		}
		signedHeaderStrings = append(signedHeaderStrings, v4Trimspace(headerName)+":"+v4Trimspace(strings.Join(signedHeaders[headerName], ",")))
	}
	return strings.Join(listHeaderNames, ";"), strings.Join(signedHeaderStrings, "\n") + "\n"
}

// CreateV4CanonicalQueryString returns an AWS canonical query string from an HTTP request
// The request should be a properly crafted HTTP request
func CreateV4CanonicalQueryString(req *http.Request) string {
	query := req.URL.Query()
	if len(query) == 0 {
		return ""
	}
	// Sort all the query values. AWS signing requires any repeated query keys to have the entries
	// sorted by value. The query string "Test=Value&Foo=z&Foo=J&Foo=bar" needs to sorted as
	// Foo=J&Foo=bar&Foo=z&Test=Value
	for key := range query {
		sort.Strings(query[key])
	}
	// The Encode method will output a query string sorted by the keys. This method also performs
	// Query escaping for both the key and values. Unfortunately it escapes a space with a '+' whereas
	// AWS expects this as a %20 so we do a string replace and any '+' will be replaced with a %20
	return strings.Replace(query.Encode(), "+", "%20", -1)
}

// CreateV4CanonicalURIString returns an AWS canonical URI string. The path will have any
// relative components removed and redundant separators will be merged. Characters will also be
// escaped to their %XY equivalents
func CreateV4CanonicalURIString(req *http.Request) string {
	if req.URL == nil {
		return "/"
	}
	// Remove any relative paths (/foo/../bar) or redundant path components like multiple slashes (/foo//bar)
	cleanedPath := filepath.ToSlash(filepath.Clean(req.URL.Path))
	if cleanedPath == "." {
		return "/"
	}
	pathSegments := strings.Split(cleanedPath, "/")
	for i := range pathSegments {
		// AWS requires path segments to be URI encoded twice
		// https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
		pathSegments[i] = url.PathEscape(url.PathEscape(pathSegments[i]))
	}
	// Rejoin all the segments into a URL path
	return strings.Join(pathSegments[:], "/")
}

// GetV4DefaultSignedHeaders returns an array of compiles regular expressions that determine
// if a header in an HTTP request should be included in the signed request
func GetV4DefaultSignedHeaders() []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile("(?i)^(x-amz-|content-|if-).*$"),
		regexp.MustCompile("(?i)^(accept|cache-control|expires|host|range)$"),
	}
}

// GetV4SignatureKey returns the signing key for an AWS V4 signature as an array of bytes
// datestamp should be in the short time format
func GetV4SignatureKey(secret string, signingDatestamp interface{}, region string, service string) []byte {
	var datestamp string
	switch signingDatestamp.(type) {
	case time.Time:
		datestamp = signingDatestamp.(time.Time).Format(V4SignerTimeFormatShort)
	default:
		datestamp = signingDatestamp.(string)
	}
	signedDate := GetHmacSha256([]byte(v4SignerSignaturePrefix+secret), []byte(datestamp))
	signedRegion := GetHmacSha256(signedDate, []byte(region))
	signedService := GetHmacSha256(signedRegion, []byte(service))
	signingKey := GetHmacSha256(signedService, []byte(v4SignerRequest))
	return signingKey
}

// GetV4SignatureKeyHex returns a hexadecimal string equivalent of GetV4SignatureKey
func GetV4SignatureKeyHex(secret string, signingDatestamp interface{}, region string, service string) string {
	return hex.EncodeToString(GetV4SignatureKey(secret, signingDatestamp, region, service))
}

// GetHmacSha256 returns a SHA256 HMAC of a message given a key. The return value is an array of bytes
func GetHmacSha256(key []byte, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// GetHmacSha256Hex returns a SHA256 HMAC hex encoded of a message given a key. The return value is an array of bytes
func GetHmacSha256Hex(key []byte, message []byte) string {
	return hex.EncodeToString(GetHmacSha256(key, message))
}

// GetSha256 returns a SHA256 of a message. The return value is an array of bytes
func GetSha256(message []byte) []byte {
	hash := sha256.New()
	hash.Write(message)
	return hash.Sum(nil)
}

// GetSha256Hex returns a SHA256 hex encoded string of a message. The return value is an array of bytes
func GetSha256Hex(message []byte) string {
	return hex.EncodeToString(GetSha256(message))
}

func isSignedHeader(header string, headerRegex []*regexp.Regexp) bool {
	for _, re := range headerRegex {
		if re.MatchString(header) {
			return true
		}
	}
	return false
}

func v4Trimspace(s string) string {
	trimmed := strings.TrimSpace(s)
	return v4SignerTrimspace.ReplaceAllString(trimmed, " ")
}
