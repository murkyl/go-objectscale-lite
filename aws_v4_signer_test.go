package objectscalelite

import (
	"fmt"
	"testing"
	"time"
)

type SignatureData struct {
	K string
	D time.Time
	R string
	S string
	E string
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
			}
		} else {
			fmt.Printf("%s %s\n", x.K, signingKey)
		}
	}
}
