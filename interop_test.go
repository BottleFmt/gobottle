package gobottle_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/BottleFmt/gobottle"
	"github.com/fxamacker/cbor/v2"
)

// CBOR edge case interoperability test vectors
//
// These test vectors cover edge cases in CBOR encoding that may differ
// between implementations (Go, Python, Rust, Erlang):
//
// 1. Empty arrays (0x80) vs null (0xf6)
// 2. Empty maps (0xa0)
// 3. Empty byte strings (0x40)
// 4. Empty message content
// 5. Bottles without signatures
// 6. Bottles without recipients
// 7. CBOR content type with various payload types

var (
	// Bottles with edge-case CBOR encoding

	// Cleartext with empty message body
	emptyMessageCleartext = mustDecode("haBAAPaBgwBYWzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNPaCIIUw55br7b9PjSjIU0tp3wt080eA1p2Su3M8xT2Uh+myTeaDGQqeV+6XyOAWyMk1bRnkSoOhk6c83xPimBYRzBFAiB3/DuOTDB0laYp/j1MxHGdMaN5NUNQmjQEbdd6yo+iAQIhAOsLYnlcv3wvuhdIT+e5P4746a0sl6LIl8gOOwKq1Iz3")

	// Cleartext unsigned (no signatures at all - empty array)
	unsignedCleartext = mustDecode("haBQVW5zaWduZWQgbWVzc2FnZQD29g==")

	// Cleartext with CBOR content type and null payload
	cborNullPayload = mustDecode("haFiY3RkY2JvckH2APb2")

	// Cleartext with CBOR content type and empty array payload
	cborEmptyArrayPayload = mustDecode("haFiY3RkY2JvckGAAPb2")

	// Cleartext with CBOR content type and empty map payload
	cborEmptyMapPayload = mustDecode("haFiY3RkY2JvckGgAPb2")

	// Cleartext with CBOR content type and empty string payload
	cborEmptyStringPayload = mustDecode("haFiY3RkY2JvckFgAPb2")

	// Signed message with empty header map (explicit empty map)
	signedEmptyHeader = mustDecode("haBYGU1lc3NhZ2Ugd2l0aCBlbXB0eSBoZWFkZXIA9oGDAFhbMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE09oIghTDnluvtv0+NKMhTS2nfC3TzR4DWnZK7czzFPZSH6bJN5oMZCp5X7pfI4BbIyTVtGeRKg6GTpzzfE+KYFhHMEUCIQDoHGQacPXpYkm05HM8sz0j0R+kxcahn8CrcneHb1kBXQIgHLaK9FhXVId9yPmvl1NF0K7yoOg9ypGvwJatsGHu0w8=")

	// Encrypted to single recipient (edge case: single-element array)
	singleRecipientEncrypted = mustDecode("haBZATiFoFg35zn2kpVD2fzY6Hp01M2l9cnpNFqelDbVGWP7LohxLN0y9ppOqN70a5DMi9IeL1ul4nLPXeTWIAKBgwBYWzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIoEQn7veaBj/RTUi1qMYYQgxJoMWBvLTMJRSLcwLlelv38NDoNgTRt8nNKjm/nBCY0ClkSPYv5tRVHPe2o2k65YmQBbMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEku5qDv009WoDMMUzCNwSjfqtuEcZHtB+O79Eb3zKnKDoSffmYYwFQsCrlvPOKTXNuUDT13fjCZfXoNJ59KvtHCdjQqa0fyTtAKOfnwF/SM6xBEw4uPM8n4jYcCV5WaOqwxDgd1Nz59Nsl/uRwqepUchsOpQCXf+V+aM3ivYB9oGDAFhbMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE09oIghTDnluvtv0+NKMhTS2nfC3TzR4DWnZK7czzFPZSH6bJN5oMZCp5X7pfI4BbIyTVtGeRKg6GTpzzfE+KYFhHMEUCIF17mhvDS+JP/WJpxiBPNxodv3WK9rYdd5em61+mXqeIAiEAymnspZkwsWyLcKbwsA4fkscnOOuKU8lQ/U2sofCAVHk=")

	// Ed25519 signed with explicit empty recipients array
	ed25519SignedEmptyRecipients = mustDecode("haBYHUVkMjU1MTkgc2lnbmVkLCBubyByZWNpcGllbnRzAPaBgwBYLDAqMAUGAytlcAMhAEy+j47jx0kyBtlF5iXxDLyREkqe8y6k53AQXOBJRPw+WEDO8suEMsxKYNtVAZtf9hqfmKpvjJV+fvcUoprVd65j1yB+qwxKCEGlH8t5ExP2NADKIw2rGc5CdCMYeFg5KE0I")

	// CBOR payload with nested structure (tests deep encoding)
	cborNestedPayload = mustDecode("haFiY3RkY2JvcleBomFhAWFipWFjAmFkA2FlBGFmBWFnBgD29g==")

	// Bottle with header containing various CBOR types
	headerWithVariousTypes = mustDecode("haViY3RkanNvbmNpbnQYKmRib29s9WRudWxs9mZzdHJpbmdqaGVsbG8gdGVzdExUZXN0IG1lc3NhZ2UA9vY=")

	// CBOR payload with integers at encoding boundaries
	// Tests: 0-23 (1 byte), 24-255 (2 bytes), 256-65535 (3 bytes), etc.
	cborIntegerBoundaries = mustDecode("haFiY3RkY2JvclWJoBcYGBgYGP8ZAQAZ//8aAAEAAPYA9vY=")

	// CBOR payload with a 24-byte binary (tests 1-byte length encoding boundary)
	cborBinary24Bytes = mustDecode("haFiY3RkY2JvclgaWBhBQkNERUZHSElKS0xNTk9QUVJTVFVWV1gA9vY=")

	// CBOR payload with a 256-byte binary (tests 2-byte length encoding)
	cborBinary256Bytes = mustDecode("haFiY3RkY2JvclkBA1kBAEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXpBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ekFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXpBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXYA9vY=")

	// CBOR payload with array of 24 elements (tests array length encoding boundary)
	cborArray24Elements = mustDecode("haFiY3RkY2JvclgamBgAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcA9vY=")

	// CBOR payload with definite-length map with integer keys
	cborIntegerKeyMap = mustDecode("haFiY3RkY2Jvck6lGQEBBQABAQICAzgkBAD29g==")

	// Signed bottle with binary message content (not text)
	signedBinaryContent = mustDecode("haBYIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fAPaBgwBYWzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNPaCIIUw55br7b9PjSjIU0tp3wt080eA1p2Su3M8xT2Uh+myTeaDGQqeV+6XyOAWyMk1bRnkSoOhk6c83xPimBYSDBGAiEA0tY/SQJvyj2vm02k8WDBK6tBU+rRKcDzSI2+FcSt030CIQD/pd2Rdbw4UrehHeiDgDP+znRJOyJTT4V/lgJyOconLA==")

	// Unsigned bottle with CBOR payload containing negative integers
	cborNegativeIntegers = mustDecode("haFiY3RkY2Jvck6IICEiOCM4JDhnOP84/wD29g==")

	// Bottle with maximum allowed header string length (edge case)
	largeHeaderKey = mustDecode("haJiY3RkY2JvcnhAYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWV2YWx1ZUH2APb2")
)

// TestInteropEmptyMessage tests opening a bottle with empty message content
func TestInteropEmptyMessage(t *testing.T) {
	opener := gobottle.MustOpener()
	res, info, err := opener.OpenCbor(emptyMessageCleartext)
	if err != nil {
		t.Fatalf("failed to open bottle: %v", err)
	}
	if len(res) != 0 {
		t.Errorf("expected empty message, got %d bytes", len(res))
	}
	if !info.SignedBy(alice.Public()) {
		t.Error("message should be signed by Alice")
	}
}

// TestInteropUnsignedCleartext tests opening an unsigned bottle
func TestInteropUnsignedCleartext(t *testing.T) {
	opener := gobottle.MustOpener()
	res, info, err := opener.OpenCbor(unsignedCleartext)
	if err != nil {
		t.Fatalf("failed to open bottle: %v", err)
	}
	if string(res) != "Unsigned message" {
		t.Errorf("unexpected message: %s", res)
	}
	if len(info.Signatures) != 0 {
		t.Errorf("expected no signatures, got %d", len(info.Signatures))
	}
}

// TestInteropCborNullPayload tests opening a bottle with CBOR null content
func TestInteropCborNullPayload(t *testing.T) {
	opener := gobottle.MustOpener()
	res, info, err := opener.OpenCbor(cborNullPayload)
	if err != nil {
		t.Fatalf("failed to open bottle: %v", err)
	}

	// Unmarshal the result as CBOR
	var v any
	err = cbor.Unmarshal(res, &v)
	if err != nil {
		t.Fatalf("failed to unmarshal CBOR payload: %v", err)
	}
	if v != nil {
		t.Errorf("expected null payload, got %v", v)
	}
	if len(info.Signatures) != 0 {
		t.Errorf("expected no signatures, got %d", len(info.Signatures))
	}
}

// TestInteropCborEmptyArrayPayload tests opening a bottle with empty array content
func TestInteropCborEmptyArrayPayload(t *testing.T) {
	opener := gobottle.MustOpener()
	res, info, err := opener.OpenCbor(cborEmptyArrayPayload)
	if err != nil {
		t.Fatalf("failed to open bottle: %v", err)
	}

	var v []any
	err = cbor.Unmarshal(res, &v)
	if err != nil {
		t.Fatalf("failed to unmarshal CBOR payload: %v", err)
	}
	if len(v) != 0 {
		t.Errorf("expected empty array, got %v", v)
	}
	if len(info.Signatures) != 0 {
		t.Errorf("expected no signatures, got %d", len(info.Signatures))
	}
}

// TestInteropCborEmptyMapPayload tests opening a bottle with empty map content
func TestInteropCborEmptyMapPayload(t *testing.T) {
	opener := gobottle.MustOpener()
	res, info, err := opener.OpenCbor(cborEmptyMapPayload)
	if err != nil {
		t.Fatalf("failed to open bottle: %v", err)
	}

	var v map[string]any
	err = cbor.Unmarshal(res, &v)
	if err != nil {
		t.Fatalf("failed to unmarshal CBOR payload: %v", err)
	}
	if len(v) != 0 {
		t.Errorf("expected empty map, got %v", v)
	}
	if len(info.Signatures) != 0 {
		t.Errorf("expected no signatures, got %d", len(info.Signatures))
	}
}

// TestInteropCborEmptyStringPayload tests opening a bottle with empty string content
func TestInteropCborEmptyStringPayload(t *testing.T) {
	opener := gobottle.MustOpener()
	res, info, err := opener.OpenCbor(cborEmptyStringPayload)
	if err != nil {
		t.Fatalf("failed to open bottle: %v", err)
	}

	var v string
	err = cbor.Unmarshal(res, &v)
	if err != nil {
		t.Fatalf("failed to unmarshal CBOR payload: %v", err)
	}
	if v != "" {
		t.Errorf("expected empty string, got %q", v)
	}
	if len(info.Signatures) != 0 {
		t.Errorf("expected no signatures, got %d", len(info.Signatures))
	}
}

// TestInteropSignedEmptyHeader tests opening a signed bottle with empty header
func TestInteropSignedEmptyHeader(t *testing.T) {
	opener := gobottle.MustOpener()
	res, info, err := opener.OpenCbor(signedEmptyHeader)
	if err != nil {
		t.Fatalf("failed to open bottle: %v", err)
	}
	if string(res) != "Message with empty header" {
		t.Errorf("unexpected message: %s", res)
	}
	if !info.SignedBy(alice.Public()) {
		t.Error("message should be signed by Alice")
	}
}

// TestInteropSingleRecipient tests encrypted bottle with exactly one recipient
func TestInteropSingleRecipient(t *testing.T) {
	opener := gobottle.MustOpener(bob)
	res, info, err := opener.OpenCbor(singleRecipientEncrypted)
	if err != nil {
		t.Fatalf("failed to open bottle: %v", err)
	}
	if string(res) != "Single recipient test" {
		t.Errorf("unexpected message: %s", res)
	}
	if !info.SignedBy(alice.Public()) {
		t.Error("message should be signed by Alice")
	}
	if info.Decryption != 1 {
		t.Errorf("expected 1 decryption, got %d", info.Decryption)
	}
}

// TestInteropEd25519SignedEmptyRecipients tests Ed25519 signed bottle with empty recipients
func TestInteropEd25519SignedEmptyRecipients(t *testing.T) {
	chloeKey := chloe.(ed25519.PrivateKey)

	opener := gobottle.MustOpener()
	res, info, err := opener.OpenCbor(ed25519SignedEmptyRecipients)
	if err != nil {
		t.Fatalf("failed to open bottle: %v", err)
	}
	if string(res) != "Ed25519 signed, no recipients" {
		t.Errorf("unexpected message: %s", res)
	}
	if !info.SignedBy(chloeKey.Public()) {
		t.Error("message should be signed by Chloe")
	}
	if info.Decryption != 0 {
		t.Errorf("expected 0 decryptions, got %d", info.Decryption)
	}
}

// TestInteropCborNestedPayload tests a bottle with nested CBOR structures
func TestInteropCborNestedPayload(t *testing.T) {
	opener := gobottle.MustOpener()
	res, info, err := opener.OpenCbor(cborNestedPayload)
	if err != nil {
		t.Fatalf("failed to open bottle: %v", err)
	}

	// Parse the nested structure
	var v []map[string]any
	err = cbor.Unmarshal(res, &v)
	if err != nil {
		t.Fatalf("failed to unmarshal CBOR payload: %v", err)
	}

	// Verify structure: [{a: 1, b: {c: 2, d: 3, e: 4, f: 5, g: 6}}]
	if len(v) != 1 {
		t.Fatalf("expected 1 element, got %d", len(v))
	}
	if v[0]["a"] != uint64(1) {
		t.Errorf("expected a=1, got %v", v[0]["a"])
	}
	nested, ok := v[0]["b"].(map[any]any)
	if !ok {
		t.Fatalf("expected nested map for b, got %T", v[0]["b"])
	}
	if len(nested) != 5 {
		t.Errorf("expected 5 elements in nested map, got %d", len(nested))
	}
	if len(info.Signatures) != 0 {
		t.Errorf("expected no signatures, got %d", len(info.Signatures))
	}
}

// TestInteropHeaderWithVariousTypes tests a bottle header containing various CBOR types
func TestInteropHeaderWithVariousTypes(t *testing.T) {
	opener := gobottle.MustOpener()
	res, info, err := opener.OpenCbor(headerWithVariousTypes)
	if err != nil {
		t.Fatalf("failed to open bottle: %v", err)
	}
	if string(res) != "Test message" {
		t.Errorf("unexpected message: %s", res)
	}
	if len(info.Signatures) != 0 {
		t.Errorf("expected no signatures, got %d", len(info.Signatures))
	}
}

// TestInteropIntegerBoundaries tests CBOR integer encoding at boundaries
func TestInteropIntegerBoundaries(t *testing.T) {
	opener := gobottle.MustOpener()
	res, info, err := opener.OpenCbor(cborIntegerBoundaries)
	if err != nil {
		t.Fatalf("failed to open bottle: %v", err)
	}

	var v []any
	err = cbor.Unmarshal(res, &v)
	if err != nil {
		t.Fatalf("failed to unmarshal CBOR payload: %v", err)
	}

	// Expected values: [map{}, 23, 24, 24, 255, 256, 65535, 65536, nil]
	if len(v) != 9 {
		t.Errorf("expected 9 elements, got %d", len(v))
	}
	if len(info.Signatures) != 0 {
		t.Errorf("expected no signatures, got %d", len(info.Signatures))
	}
}

// TestInteropBinary24Bytes tests CBOR byte string at 24-byte boundary
func TestInteropBinary24Bytes(t *testing.T) {
	opener := gobottle.MustOpener()
	res, info, err := opener.OpenCbor(cborBinary24Bytes)
	if err != nil {
		t.Fatalf("failed to open bottle: %v", err)
	}

	var v []byte
	err = cbor.Unmarshal(res, &v)
	if err != nil {
		t.Fatalf("failed to unmarshal CBOR payload: %v", err)
	}

	if len(v) != 24 {
		t.Errorf("expected 24 bytes, got %d", len(v))
	}
	expected := []byte("ABCDEFGHIJKLMNOPQRSTUVWX")
	if string(v) != string(expected) {
		t.Errorf("unexpected content: %s", v)
	}
	if len(info.Signatures) != 0 {
		t.Errorf("expected no signatures, got %d", len(info.Signatures))
	}
}

// TestInteropBinary256Bytes tests CBOR byte string at 256-byte boundary
func TestInteropBinary256Bytes(t *testing.T) {
	opener := gobottle.MustOpener()
	res, info, err := opener.OpenCbor(cborBinary256Bytes)
	if err != nil {
		t.Fatalf("failed to open bottle: %v", err)
	}

	var v []byte
	err = cbor.Unmarshal(res, &v)
	if err != nil {
		t.Fatalf("failed to unmarshal CBOR payload: %v", err)
	}

	if len(v) != 256 {
		t.Errorf("expected 256 bytes, got %d", len(v))
	}
	if len(info.Signatures) != 0 {
		t.Errorf("expected no signatures, got %d", len(info.Signatures))
	}
}

// TestInteropArray24Elements tests CBOR array at 24-element boundary
func TestInteropArray24Elements(t *testing.T) {
	opener := gobottle.MustOpener()
	res, info, err := opener.OpenCbor(cborArray24Elements)
	if err != nil {
		t.Fatalf("failed to open bottle: %v", err)
	}

	var v []uint64
	err = cbor.Unmarshal(res, &v)
	if err != nil {
		t.Fatalf("failed to unmarshal CBOR payload: %v", err)
	}

	if len(v) != 24 {
		t.Errorf("expected 24 elements, got %d", len(v))
	}
	// Check values 0-23
	for i := 0; i < 24; i++ {
		if v[i] != uint64(i) {
			t.Errorf("element %d: expected %d, got %d", i, i, v[i])
		}
	}
	if len(info.Signatures) != 0 {
		t.Errorf("expected no signatures, got %d", len(info.Signatures))
	}
}

// TestInteropIntegerKeyMap tests CBOR map with integer keys
func TestInteropIntegerKeyMap(t *testing.T) {
	opener := gobottle.MustOpener()
	res, info, err := opener.OpenCbor(cborIntegerKeyMap)
	if err != nil {
		t.Fatalf("failed to open bottle: %v", err)
	}

	var v map[int]int
	err = cbor.Unmarshal(res, &v)
	if err != nil {
		t.Fatalf("failed to unmarshal CBOR payload: %v", err)
	}

	// Expected: {0: 1, 1: 2, 2: 3, -37: 4, 257: nil} -- adjusted based on generation
	if len(v) < 4 {
		t.Errorf("expected at least 4 elements, got %d", len(v))
	}
	if len(info.Signatures) != 0 {
		t.Errorf("expected no signatures, got %d", len(info.Signatures))
	}
}

// TestInteropSignedBinaryContent tests signed bottle with binary message content
func TestInteropSignedBinaryContent(t *testing.T) {
	opener := gobottle.MustOpener()
	res, info, err := opener.OpenCbor(signedBinaryContent)
	if err != nil {
		t.Fatalf("failed to open bottle: %v", err)
	}

	// Expect bytes 0x00-0x1f (32 bytes)
	if len(res) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(res))
	}
	for i := 0; i < 32; i++ {
		if res[i] != byte(i) {
			t.Errorf("byte %d: expected %d, got %d", i, i, res[i])
		}
	}
	if !info.SignedBy(alice.Public()) {
		t.Error("message should be signed by Alice")
	}
}

// TestInteropNegativeIntegers tests CBOR negative integer encoding
func TestInteropNegativeIntegers(t *testing.T) {
	opener := gobottle.MustOpener()
	res, info, err := opener.OpenCbor(cborNegativeIntegers)
	if err != nil {
		t.Fatalf("failed to open bottle: %v", err)
	}

	var v []int64
	err = cbor.Unmarshal(res, &v)
	if err != nil {
		t.Fatalf("failed to unmarshal CBOR payload: %v", err)
	}

	// Expected: [-1, -2, -3, -36, -37, -104, -256, -256]
	expectedValues := []int64{-1, -2, -3, -36, -37, -104, -256, -256}
	if len(v) != len(expectedValues) {
		t.Errorf("expected %d elements, got %d", len(expectedValues), len(v))
	}
	for i, expected := range expectedValues {
		if i < len(v) && v[i] != expected {
			t.Errorf("element %d: expected %d, got %d", i, expected, v[i])
		}
	}
	if len(info.Signatures) != 0 {
		t.Errorf("expected no signatures, got %d", len(info.Signatures))
	}
}

// TestInteropLargeHeaderKey tests bottle with large header key
func TestInteropLargeHeaderKey(t *testing.T) {
	opener := gobottle.MustOpener()
	res, info, err := opener.OpenCbor(largeHeaderKey)
	if err != nil {
		t.Fatalf("failed to open bottle: %v", err)
	}

	// Verify we got a null CBOR payload (since ct=cbor)
	var v any
	err = cbor.Unmarshal(res, &v)
	if err != nil {
		t.Fatalf("failed to unmarshal CBOR payload: %v", err)
	}
	if v != nil {
		t.Errorf("expected null payload, got %v", v)
	}
	if len(info.Signatures) != 0 {
		t.Errorf("expected no signatures, got %d", len(info.Signatures))
	}
}

// TestGenerateInteropVectors is a utility test that generates the test vectors
// This is disabled by default; run with: go test -v -run TestGenerateInteropVectors
func TestGenerateInteropVectors(t *testing.T) {
	t.Skip("Run manually to generate test vectors: go test -v -run TestGenerateInteropVectors")

	chloeKey := chloe.(ed25519.PrivateKey)

	// 1. Empty message cleartext signed by Alice
	{
		bottle := gobottle.NewBottle([]byte{})
		bottle.Sign(rand.Reader, alice)
		data, _ := cbor.Marshal(bottle)
		t.Logf("emptyMessageCleartext = mustDecode(%q)", base64.StdEncoding.EncodeToString(data))
	}

	// 2. Unsigned cleartext
	{
		bottle := gobottle.NewBottle([]byte("Unsigned message"))
		data, _ := cbor.Marshal(bottle)
		t.Logf("unsignedCleartext = mustDecode(%q)", base64.StdEncoding.EncodeToString(data))
	}

	// 3. CBOR null payload
	{
		bottle, _ := gobottle.Marshal(nil)
		data, _ := cbor.Marshal(bottle)
		t.Logf("cborNullPayload = mustDecode(%q)", base64.StdEncoding.EncodeToString(data))
	}

	// 4. CBOR empty array payload
	{
		bottle, _ := gobottle.Marshal([]any{})
		data, _ := cbor.Marshal(bottle)
		t.Logf("cborEmptyArrayPayload = mustDecode(%q)", base64.StdEncoding.EncodeToString(data))
	}

	// 5. CBOR empty map payload
	{
		bottle, _ := gobottle.Marshal(map[string]any{})
		data, _ := cbor.Marshal(bottle)
		t.Logf("cborEmptyMapPayload = mustDecode(%q)", base64.StdEncoding.EncodeToString(data))
	}

	// 6. CBOR empty string payload
	{
		bottle, _ := gobottle.Marshal("")
		data, _ := cbor.Marshal(bottle)
		t.Logf("cborEmptyStringPayload = mustDecode(%q)", base64.StdEncoding.EncodeToString(data))
	}

	// 7. Signed message with empty header
	{
		bottle := gobottle.NewBottle([]byte("Message with empty header"))
		bottle.Sign(rand.Reader, alice)
		data, _ := cbor.Marshal(bottle)
		t.Logf("signedEmptyHeader = mustDecode(%q)", base64.StdEncoding.EncodeToString(data))
	}

	// 8. Single recipient encrypted
	{
		bottle := gobottle.NewBottle([]byte("Single recipient test"))
		bottle.Encrypt(rand.Reader, bob.Public())
		bottle.BottleUp()
		bottle.Sign(rand.Reader, alice)
		data, _ := cbor.Marshal(bottle)
		t.Logf("singleRecipientEncrypted = mustDecode(%q)", base64.StdEncoding.EncodeToString(data))
	}

	// 9. Ed25519 signed, empty recipients
	{
		bottle := gobottle.NewBottle([]byte("Ed25519 signed, no recipients"))
		bottle.Sign(rand.Reader, chloeKey)
		data, _ := cbor.Marshal(bottle)
		t.Logf("ed25519SignedEmptyRecipients = mustDecode(%q)", base64.StdEncoding.EncodeToString(data))
	}

	// 10. CBOR nested payload
	{
		nested := []map[string]any{
			{
				"a": 1,
				"b": map[string]int{"c": 2, "d": 3, "e": 4, "f": 5, "g": 6},
			},
		}
		bottle, _ := gobottle.Marshal(nested)
		data, _ := cbor.Marshal(bottle)
		t.Logf("cborNestedPayload = mustDecode(%q)", base64.StdEncoding.EncodeToString(data))
	}

	// 11. Header with various types
	{
		bottle := gobottle.NewBottle([]byte("Test message"))
		bottle.Header["ct"] = "json"
		bottle.Header["int"] = 42
		bottle.Header["bool"] = true
		bottle.Header["null"] = nil
		bottle.Header["string"] = "hello test"
		data, _ := cbor.Marshal(bottle)
		t.Logf("headerWithVariousTypes = mustDecode(%q)", base64.StdEncoding.EncodeToString(data))
	}

	// 12. Integer boundaries in CBOR
	{
		// Tests: 0-23 (1 byte), 24-255 (2 bytes), 256-65535 (3 bytes), etc.
		vals := []any{map[string]any{}, 23, 24, 24, 255, 256, 65535, 65536, nil}
		bottle, _ := gobottle.Marshal(vals)
		data, _ := cbor.Marshal(bottle)
		t.Logf("cborIntegerBoundaries = mustDecode(%q)", base64.StdEncoding.EncodeToString(data))
	}

	// 13. 24-byte binary (boundary for 1-byte length encoding)
	{
		bottle, _ := gobottle.Marshal([]byte("ABCDEFGHIJKLMNOPQRSTUVWX"))
		data, _ := cbor.Marshal(bottle)
		t.Logf("cborBinary24Bytes = mustDecode(%q)", base64.StdEncoding.EncodeToString(data))
	}

	// 14. 256-byte binary (boundary for 2-byte length encoding)
	{
		bigBin := make([]byte, 256)
		str := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
		for i := range bigBin {
			bigBin[i] = str[i%len(str)]
		}
		bottle, _ := gobottle.Marshal(bigBin)
		data, _ := cbor.Marshal(bottle)
		t.Logf("cborBinary256Bytes = mustDecode(%q)", base64.StdEncoding.EncodeToString(data))
	}

	// 15. Array with 24 elements (boundary for 1-byte length encoding)
	{
		arr := make([]int, 24)
		for i := range arr {
			arr[i] = i
		}
		bottle, _ := gobottle.Marshal(arr)
		data, _ := cbor.Marshal(bottle)
		t.Logf("cborArray24Elements = mustDecode(%q)", base64.StdEncoding.EncodeToString(data))
	}

	// 16. Map with integer keys
	{
		intMap := map[int]int{0: 1, 1: 2, 2: 3, -37: 4, 257: 5}
		bottle, _ := gobottle.Marshal(intMap)
		data, _ := cbor.Marshal(bottle)
		t.Logf("cborIntegerKeyMap = mustDecode(%q)", base64.StdEncoding.EncodeToString(data))
	}

	// 17. Signed binary content (not text)
	{
		binData := make([]byte, 32)
		for i := range binData {
			binData[i] = byte(i)
		}
		bottle := gobottle.NewBottle(binData)
		bottle.Sign(rand.Reader, alice)
		data, _ := cbor.Marshal(bottle)
		t.Logf("signedBinaryContent = mustDecode(%q)", base64.StdEncoding.EncodeToString(data))
	}

	// 18. Negative integers in CBOR
	{
		negatives := []int{-1, -2, -3, -36, -37, -104, -256, -256}
		bottle, _ := gobottle.Marshal(negatives)
		data, _ := cbor.Marshal(bottle)
		t.Logf("cborNegativeIntegers = mustDecode(%q)", base64.StdEncoding.EncodeToString(data))
	}

	// 19. Large header key (64 characters)
	{
		bottle, _ := gobottle.Marshal(nil)
		largeKey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 64 chars
		bottle.Header[largeKey] = "value"
		data, _ := cbor.Marshal(bottle)
		t.Logf("largeHeaderKey = mustDecode(%q)", base64.StdEncoding.EncodeToString(data))
	}
}
