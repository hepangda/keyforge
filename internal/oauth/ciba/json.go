package ciba

import (
	"encoding/json"
	"io"
)

func writeJSONEnc(w io.Writer, body any) error {
	return json.NewEncoder(w).Encode(body)
}
