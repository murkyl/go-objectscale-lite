package objectscalelite

import (
	"bytes"
	"fmt"
	"net/http"
	//"net/http/httputil"
	"strings"
	"testing"
	"time"
)

type SignatureData struct {
	U string
	A string
	K string
	D time.Time
	R string
	S string
	E string
	B string
}

func TestAwsSignerGenerateSignature(t *testing.T) {
	var signingKey string
	testData := []SignatureData{
		SignatureData{
			K: "abcd",
			R: "us-east-1",
			S: "s3",
			E: "87f97c8817d469a5f74986d63b2c3acbcb2b03fe76ed2accdf820002a665a8b9",
		},
		SignatureData{
			K: "lv38k58EnbhZ9ZrcCUg4OpCxFZbvNrmYUffjth5d",
			D: time.Date(2021, 9, 10, 7, 22, 27, 0, time.UTC),
			R: "us-east-1",
			S: "sts",
			E: "c7b0edbc73670d1e8268333bf44d215a9c87efcba64cd7c0313c699b357be11a",
		},
		SignatureData{
			K: "lv38k58EnbhZ9ZrcCUg4OpCxFZbvNrmYUffjth5d",
			D: time.Date(2021, 9, 10, 7, 22, 27, 0, time.UTC),
			R: "",
			S: "",
			E: "989b321326236031650d83beb2571b36f87bde55c99958a86c0f9d1358379f50",
		},
	}
	for _, x := range testData {
		signingKey = GetV4SignatureKeyHex(x.K, x.D, x.R, x.S)
		if x.E != "" {
			if signingKey != x.E {
				t.Logf("Signing key did not match expected value. %s != %s", x.E, signingKey)
				t.Fail()
			}
		} else {
			fmt.Printf("%s %s\n", x.K, signingKey)
		}
	}
}

func TestAwsSignatureWithBody(t *testing.T) {
	var signCtx V4SignerContext
	//var bodyBytes []byte
	var bodyReader *bytes.Reader
	var err error
	var req *http.Request
	testData := []SignatureData{
		SignatureData{
			U: "https://10.59.201.21:4443/",
			A: "accessID",
			K: "secretKey",
			D: time.Date(2021, 9, 14, 9, 54, 41, 0, time.UTC),
			R: "region",
			S: "service",
			E: "758052dc1487576e2fee39968ed2d5d5eb074ae7aefaebc2155928f3b82f7459",
			//B: "This is a simple test",
		},
		SignatureData{
			U: "https://10.59.201.21:4443/",
			A: "accessID",
			K: "secretKey",
			D: time.Date(2021, 9, 14, 10, 1, 2, 0, time.UTC),
			R: "region",
			S: "service",
			E: "929baab2e585678fbf19fff3896b14cb43d5a3dd85b8f250a8ed522a30e59225",
			B: "This is a simple test",
		},
		SignatureData{
			U: "https://10.59.201.21:4443/",
			A: "accessID",
			K: "secretKey",
			D: time.Date(2021, 9, 14, 10, 7, 18, 0, time.UTC),
			R: "region",
			S: "service",
			E: "01578ed388057ebd1206605ce60fd79f2c8cc8d4e92fe24311a58aa0c3ef8463",
			B: "More sample text",
		},
		SignatureData{
			U: "https://10.59.201.21:4443/sts?Action=AssumeRole&RoleArn=urn:ecs:iam::apj:role/upgradeJoe&RoleSessionName=SomeRandomString&DurationSeconds=3600",
			A: "AKIAF4805D92373546F1",
			K: "lv38k58EnbhZ9ZrcCUg4OpCxFZbvNrmYUffjth5d",
			D: time.Date(2021, 9, 14, 9, 52, 22, 0, time.UTC),
			R: "",
			S: "",
			E: "1e87331f32b9b332f125bcadce679cf8d1c079e6c247fd9ed7c9455be965f69b",
		},
	}
	for _, x := range testData {
		if x.B != "" {
			bodyReader = bytes.NewReader([]byte(x.B))
		} else {
			bodyReader = nil
		}
		if bodyReader == nil {
			req, err = http.NewRequest("POST", x.U, nil)
		} else {
			req, err = http.NewRequest("POST", x.U, bodyReader)
		}
		if err != nil {
			t.FailNow()
		}
		req.Header.Add("Accept", "application/json")
		req.Header.Add("X-Amz-Date", x.D.Format(V4SignerTimeFormat))
		req.Header.Add("Content-Type", "text/plain")
		signCtx = NewV4SignerContext(
			x.A,
			x.K,
			x.R,
			x.S,
		)
		signCtx.V4SignRequest(req)
		authHdr := req.Header.Get("Authorization")
		s := strings.Split(authHdr, "Signature=")
		if x.E != s[1] {
			t.Logf("Signature did not match expected value. %s != %s", x.E, s[1])
			t.Fail()
		}
		//bodyBytes, err = httputil.DumpRequestOut(req, true)
		//t.Logf("Request:\n%q", bodyBytes)
	}
}