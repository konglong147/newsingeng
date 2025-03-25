//go:build go1.20 && !without_contextjson

package json

import (
	json "github.com/newsingeng/sing/common/json/internal/contextjson"
)

var UnmarshalDisallowUnknownFields = json.UnmarshalDisallowUnknownFields
