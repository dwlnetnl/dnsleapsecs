package dnsleapsecs

import (
	"context"
	"errors"
	"testing"
)

type testResolver struct {
	addr  string
	addrs []string
	err   error
}

var _ Resolver = testResolver{}

func (tr testResolver) LookupHost(ctx context.Context, host string) (addrs []string, err error) {
	if tr.err != nil {
		return nil, tr.err
	}
	if tr.addr != "" {
		return []string{tr.addr}, nil
	}
	return tr.addrs, nil
}

func TestLookup(t *testing.T) {
	ctx := context.Background()
	for _, tv := range TestVectors {
		t.Run(tv.IP, func(t *testing.T) {
			tr := testResolver{addr: tv.IP}
			ip, r, err := Lookup(ctx, tr)

			var e *Error
			if errors.As(err, &e) && *e != *tv.Err {
				t.Fatalf("got %#v, want: %#v", e, tv.Err)
			}
			if ip != tv.IP {
				t.Errorf("got %q, want: %q", ip, tv.IP)
			}
			if r != tv.Result {
				t.Errorf("got %#v, want: %#v", r, tv.Result)
			}
		})
	}

	t.Run("manydecode", func(t *testing.T) {
		tr := testResolver{addrs: []string{
			"127.240.133.76", // invalid address
			"255.209.76.40",  // invalid checksum
			"241.179.152.73", // invalid action
			"240.3.9.77",
		}}

		ip, r, err := Lookup(ctx, tr)
		if err != nil {
			t.Errorf("got error: %#v", err)
		}
		if want := "240.3.9.77"; ip != want {
			t.Errorf("got %q, want: %q", ip, want)
		}
		if want := (Result{1971, 12, 9, +1}); r != want {
			t.Errorf("got %#v, want: %#v", r, want)
		}
	})

	testLookup := func(t *testing.T, tr testResolver, want *Error) {
		t.Helper()
		_, r, err := Lookup(ctx, tr)
		if r != (Result{}) {
			t.Errorf("got result: %#v", r)
		}
		var got *Error
		if !errors.As(err, &got) {
			t.Fatalf("got %T error but wants *Error", err)
		}
		if *got != *want {
			t.Errorf("got %#v, want: %#v", got, want)
		}
	}
	t.Run("failedlookup", func(t *testing.T) {
		tr := testResolver{err: errors.New("some lookup error")}
		testLookup(t, tr, &Error{Code: -10, Err: tr.err})
	})
	t.Run("emptyresponse", func(t *testing.T) {
		tr := testResolver{}
		testLookup(t, tr, &Error{Code: -11})
	})
	t.Run("manyinvalid", func(t *testing.T) {
		tr := testResolver{addrs: []string{
			"127.240.133.76", // invalid address
			"255.209.76.40",  // invalid checksum
			"241.179.152.73", // invalid action
		}}
		testLookup(t, tr, &Error{Code: -3})
	})
}

func TestDecode(t *testing.T) {
	for _, tv := range TestVectors {
		t.Run(tv.IP, func(t *testing.T) {
			r, err := Decode(tv.IP)
			var e *Error
			if errors.As(err, &e) && *e != *tv.Err {
				t.Errorf("got %#v, want: %#v", err, tv.Err)
			}
			if r.Year != tv.Result.Year {
				t.Errorf("got %#v, want: %#v", r.Year, tv.Result.Year)
			}
			if r.Month != tv.Result.Month {
				t.Errorf("got %#v, want: %#v", r.Month, tv.Result.Month)
			}
			if r.DTAI != tv.Result.DTAI {
				t.Errorf("got %#v, want: %#v", r.DTAI, tv.Result.DTAI)
			}
			if r.Delta != tv.Result.Delta {
				t.Errorf("got %#v, want: %#v", r.Delta, tv.Result.Delta)
			}
		})
	}
}

func TestCRC8(t *testing.T) {
	const in = uint32(0x41723ff)
	const want = 0x80
	got := crc8(in)
	if got != want {
		t.Errorf("got 0x%x, want: 0x%x", got, want)
	}
}
