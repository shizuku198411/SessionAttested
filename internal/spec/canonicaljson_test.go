package spec

import "testing"

func TestCanonicalizeJSONBytes_SortsKeys(t *testing.T) {
	raw := []byte(`{"b":1,"a":2}`)
	got, err := CanonicalizeJSONBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":2,"b":1}`
	if string(got) != want {
		t.Fatalf("canonical mismatch: got=%s want=%s", got, want)
	}
}

func TestCanonicalJSON_Nested(t *testing.T) {
	raw := []byte(`{"z":{"b":true,"a":null},"arr":[{"y":2,"x":1},"s"]}`)
	got, err := CanonicalizeJSONBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"arr":[{"x":1,"y":2},"s"],"z":{"a":null,"b":true}}`
	if string(got) != want {
		t.Fatalf("canonical mismatch:\n got=%s\nwant=%s", got, want)
	}
}

func TestCanonicalizeJSONBytes_PreservesNumberToken(t *testing.T) {
	// UseNumber should keep "1e3" as token, not normalize it to 1000.
	raw := []byte(`{"n":1e3}`)
	got, err := CanonicalizeJSONBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"n":1e3}`
	if string(got) != want {
		t.Fatalf("canonical mismatch: got=%s want=%s", got, want)
	}
}
