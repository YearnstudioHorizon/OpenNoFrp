package protocol

import (
	"bytes"
	"net"
	"testing"
)

func TestStreamMetadataRoundTrip(t *testing.T) {
	cases := []StreamMetadata{
		{Transport: TransportTCP, ClientAddr: net.ParseIP("1.2.3.4"), ClientPort: 5555, RuleID: 42},
		{Transport: TransportUDP, ClientAddr: net.ParseIP("2001:db8::1"), ClientPort: 1, RuleID: 7},
		{Transport: TransportTCP, ClientAddr: net.ParseIP("10.0.0.1"), ClientPort: 80, RuleID: 9, Flags: FlagDialAck, SNI: "a.example.com"},
	}
	for i, in := range cases {
		var buf bytes.Buffer
		if err := in.WriteHeader(&buf); err != nil {
			t.Fatalf("case %d: write: %v", i, err)
		}
		buf.WriteString("payload")
		out, err := ReadStreamMetadata(&buf)
		if err != nil {
			t.Fatalf("case %d: read: %v", i, err)
		}
		if out.Transport != in.Transport || !out.ClientAddr.Equal(in.ClientAddr) || out.ClientPort != in.ClientPort ||
			out.RuleID != in.RuleID || out.Flags != in.Flags || out.SNI != in.SNI {
			t.Errorf("case %d: got %+v want %+v", i, out, in)
		}
		if rest := buf.String(); rest != "payload" {
			t.Errorf("case %d: stream misaligned, rest=%q", i, rest)
		}
	}
}

func TestUnknownTrailerIgnored(t *testing.T) {
	m := StreamMetadata{Transport: TransportTCP, ClientAddr: net.ParseIP("1.1.1.1"), RuleID: 1}
	hdr, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	trailer := []byte{0x7f, 0, 2, 'x', 'y', TrailerSNI, 0, 1, 'z'}
	hdr[26], hdr[27] = 0, byte(len(trailer))
	r := bytes.NewReader(append(hdr, trailer...))
	out, err := ReadStreamMetadata(r)
	if err != nil {
		t.Fatal(err)
	}
	if out.SNI != "z" || r.Len() != 0 {
		t.Errorf("got SNI %q, remaining %d", out.SNI, r.Len())
	}
}
