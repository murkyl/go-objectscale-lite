package objectscalelite

import (
	"encoding/json"
	"fmt"
	"github.com/mitchellh/mapstructure"
	"io/ioutil"
	"time"
)

// AssumeRole returns a set of temporary credentials for an elevated role
func (conn *ObjectScaleConn) AssumeRole(roleArn string, qParams *ObjectScaleQueryParams, signingCtx *V4SignerContext) (*ObjectScaleAssumedRole, error) {
	query := map[string]string{
		apiOpAction:          "AssumeRole",
		apiOpRoleArn:         GetURNPolicyFromString(roleArn),
		apiOpRoleSessionName: fmt.Sprintf("%s-%d", signingCtx.AccessKey, time.Now().Unix()), // Session name max 64 chars [\w+=,.@-]*
	}
	if qParams != nil {
		if qParams.DurationSeconds != 0 {
			query[apiOpDurationSeconds] = fmt.Sprintf("%d", qParams.DurationSeconds)
		}
		if qParams.InlineSessionPolicy != "" {
			query[apiOpInlineSessionPolicy] = qParams.Path
		}
		if qParams.PolicyArns != "" {
			query[apiOpPolicyArns] = qParams.PolicyArns
		}
		if qParams.RoleSessionName != "" {
			query[apiOpRoleSessionName] = qParams.RoleSessionName
		}
	}
	resp, err := conn.SendRawSigned(
		"POST",
		apiPathSTS,
		query, // query
		nil,   // body
		nil,   // extra headers
		signingCtx,
	)
	defer resp.Body.Close()
	rawBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("[Send] Error reading response body: %v", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("[Send] Non 2xx response received (%d): %s", resp.StatusCode, fmt.Sprintf("%+v", string(rawBody)))
	}
	jsonBody := make(map[string]interface{})
	if err := json.Unmarshal(rawBody, &jsonBody); err != nil {
		return nil, fmt.Errorf("[Send] Error unmarshaling JSON: %v\nRaw body: %s", err, rawBody)
	}
	var result struct {
		AssumeRoleResult ObjectScaleAssumedRole
	}
	if err = mapstructure.Decode(jsonBody, &result); err != nil {
		return nil, err
	}
	return &result.AssumeRoleResult, nil
}
