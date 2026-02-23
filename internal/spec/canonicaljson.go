package spec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// CanonicalJSON encodes v into canonical JSON bytes for signing/hashing.
// Rules: UTF-8, lexicographic key order, no whitespace, no trailing newline.

func CanonicalJSON(v any) ([]byte, error) {
	// Marshal once using stdlib
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return CanonicalizeJSONBytes(raw)
}

// CanonicalizeJSONBytes canonicalizes an existing JSON byte slice.
func CanonicalizeJSONBytes(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	dec.DisallowUnknownFields()

	var x any
	if err := dec.Decode(&x); err != nil {
		return nil, fmt.Errorf("decode json: %w", err)
	}
	if dec.More() {
		return nil, errors.New("extra json tokens detected")
	}

	norm, err := normalize(x)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := encodeCanonical(&buf, norm); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// normalize converts decoded JSON values into a form suitable for canonical encoding.
func normalize(v any) (any, error) {
	switch t := v.(type) {
	case nil, bool, string, json.Number:
		return t, nil
	case float64:
		return json.Number(fmt.Sprintf("%.17g", t)), nil
	case []any:
		out := make([]any, 0, len(t))
		for _, e := range t {
			n, err := normalize(e)
			if err != nil {
				return nil, err
			}
			out = append(out, n)
		}
		return out, nil
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, vv := range t {
			n, err := normalize(vv)
			if err != nil {
				return nil, err
			}
			out[k] = n
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported json value type: %T", v)
	}
}

// encodeCanonical writes JSON without whitespace and with sorted object keys.
func encodeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
		return nil
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
		return nil
	case string:
		b, _ := json.Marshal(t)
		buf.Write(b)
		return nil
	case json.Number:
		s := t.String()
		if s == "" {
			return errors.New("empty json number")
		}
		buf.WriteString(s)
		return nil
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encodeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	case map[string]any:
		buf.WriteByte('{')
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			buf.Write(kb)
			buf.WriteByte(':')
			if err := encodeCanonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	default:
		return fmt.Errorf("unsupported canonical json type: %T", v)
	}
}
