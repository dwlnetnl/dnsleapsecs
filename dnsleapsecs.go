// Package dnsleapsecs provides functionality for quering leap-seconds
// via DNS using an IPv4 encoding.
//
// See for more information: http://phk.freebsd.dk/time/20151122/
// For reference and manual checks search for "IERS Bulletin C"
// (leap second announcements).
package dnsleapsecs

import (
	"context"
	"fmt"
	"net"
)

/*-
 * Reference implementation of code to retrieve current leap-second
 * announcement via DNS lookup.
 *
 * Specification:
 * --------------
 *
 * The leap second information is encoded into a IPv4 adress as follows:
 *
 *    3                   2                   1                   0
 *  1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |1 1 1 1|        month        | d |   dTAI      |    CRC-8      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * 'month' Count of months since december 1971
 *  = (year - 1971) * 12 + month - 11
 *
 * 'dTAI'  Number of seconds UTC is behind of TAI
 *	UTC = TAI - dTAI
 *
 * 'd' what happens to dTAI at the end of the month indicated
 *  0 -> nothing
 *  1 -> subtract one from dTAI
 *  2 -> add one to dTAI
 *  3 -> Illegal
 *
 *
 * Example:
 * --------
 *
 * The IPv4 address "244.23.35.255" encodes Bulletin C 49
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |1 1 1 1|0 1 0 0 0 0 0 1 0 1 1|1 0|0 1 0 0 0 1 1|1 1 1 1 1 1 1 1|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * month = 0x20b = 523 = (2015 - 1971) * 12 + 6 - 11 -> June 2015
 *
 * d = 0x2 -> +1
 *
 * dTAI = 0x23 = 35 -> UTC = TAI - 35 sec
 *
 * CRC-8 = 0xff -> Calculated message {month d dTAI}.  See below.
 *
 * Design notes:
 * -------------
 *
 * The first four bits puts the resulting IPv4 address into the "class-E"
 * space which is "reserved for future use", as a defense against lying
 * DNS resolvers.
 *
 * At this point, late 2015, it does not look like class-E will ever be
 * allocated for any use.  Most network stacks treat them as martians
 * (ie: patently invalid), and at current consumption rates, they would
 * be gobbled up far faster than we could upgrade network stacks.
 *
 * Therefore no sane DNS resolver should ever return a class-E addres,
 * unless somebody does really strange things with IPv4 numbers.
 *
 * A second layer of defense against lying DNS resolvers is the CRC8
 * integrity check in the last octet.
 *
 * The field widths should be good until about year 2140.
 *
 * At this point in time the dTAI field is considered unsigned, but
 * should strange and awe inspiring geophysical events unfold,
 * spinning up the rotation of the planet, (while implausibly leaving
 * this protocol still relevant) the field can be redefined as signed.
 *
 */

// Resolver resolves DNS host records.
type Resolver interface {
	LookupHost(ctx context.Context, host string) (addrs []string, err error)
}

// Result contains leap-second information.
type Result struct {
	// Announced horizon.
	Year, Month int

	// DTAI is what to subtract from TAI to get UTC until that month ends.
	DTAI int // dTAI

	// Delta is what needs to be applied to DTAI at the end of that month.
	Delta int
}

// Error is the error type returned.
type Error struct {
	Code int
	Err  error
}

func (e *Error) Unwrap() error { return e.Err }
func (e *Error) Error() string {
	s := errorCodeReason[e.Code]
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

var errorCodeReason = map[int]string{
	-1:  "invalid address",
	-2:  "invalid checksum",
	-3:  "invalid action",
	-10: "lookup failed",
	-11: "empty response",
}

// Fetch fetches and decodes leap-second information,
// using net.DefaultResolver and "leapsecond.utcd.org".
// Additionally the raw IPv4 address is returned as well.
//
// In the unlikely case there is more than a single result,
// first successfully parsed address is used.
func Fetch(ctx context.Context) (string, Result, error) {
	return Lookup(ctx, net.DefaultResolver)
}

// Lookup fetches and parses the leap-second information,
// using the "leapsecond.utcd.org" host record. Additionally
// the raw IPv4 address is returned as well.
//
// In the unlikely case there is more than a single result,
// first successfully parsed address is used.
func Lookup(ctx context.Context, r Resolver) (string, Result, error) {
	return LookupHost(ctx, r, "leapsecond.utcd.org")
}

// LookupHost fetches and parses the leap-second information.
// Additionally the raw IPv4 address is returned as well.
//
// In the unlikely case there is more than a single result,
// first successfully parsed address is used.
func LookupHost(ctx context.Context, r Resolver, host string) (string, Result, error) {
	if ctx == nil {
		panic("context is nil")
	}
	if r == nil {
		panic("resolver is nil")
	}
	ips, err := r.LookupHost(ctx, host)
	if err != nil {
		return "", Result{}, &Error{Code: -10, Err: err}
	}
	if len(ips) == 0 {
		return "", Result{}, &Error{Code: -11}
	}
	var ip string
	var dr Result
	for _, ip = range ips {
		dr, err = Decode(ip)
		if err == nil {
			break
		}
	}
	return ip, dr, err
}

// Decode decodes leap-second information in a numeric IPv4 string
// ("253.253.100.11").
//
// year and month is the announced horizon.
// dtai is what you subtract from TAI to get UTC until that month ends.
// delta is what you do to dtai at the end of that month.
func Decode(ip string) (Result, error) {
	// Convert to 32 bit integer
	var o1, o2, o3, o4 uint32
	n, err := fmt.Sscanf(ip, "%d.%d.%d.%d", &o1, &o2, &o3, &o4)
	if n != 4 {
		return Result{}, &Error{Code: -1, Err: err}
	}

	u := o1 << 24
	u |= o2 << 16
	u |= o3 << 8
	u |= o4

	// Check & remove class E
	if (u >> 28) != 0xf {
		return Result{}, &Error{Code: -1}
	}

	// Check & remove CRC8
	if crc8(u) != 0x80 {
		return Result{}, &Error{Code: -2}
	}
	u >>= 8

	// Split into fields
	o := u & 0x7f
	u >>= 7

	d := u & 3
	u >>= 2

	mn := (u & 0x7ff) + 10

	// Error checks
	if d == 3 {
		return Result{}, &Error{Code: -3}
	}

	// Convert to return values
	r := Result{
		Year:  1971 + (int(mn) / 12),
		Month: 1 + (int(mn) % 12),
		DTAI:  int(o),
	}
	switch d {
	case 0:
		r.Delta = 0
	case 1:
		r.Delta = -1
	case 2:
		r.Delta = +1
	}

	return r, nil
}

// crc8 computes a MSB first CRC8 with polynomium (x^8 +x^5 +x^3 +x^2 +x +1)
//
// This is by a small margin the best CRC8 for the message length (28 bits)
// For much more about CRC's than you'd ever want to know:
//  http://users.ece.cmu.edu/~koopman/crc/index.html
//
// PS:  The CRC seed is not random.
func crc8(u uint32) uint32 {
	const bits = 28
	crc := 0x54a9abf8 ^ (u << (32 - bits))
	for i := 0; i < bits; i++ {
		if crc&(1<<31) != 0 {
			crc ^= 0x12f << 23
		}
		crc <<= 1
	}
	return crc >> 24
}

// TestVectors is test data to validate the decode logic.
var TestVectors = []struct {
	IP     string
	Result Result
	Err    *Error
}{
	{"240.3.9.77", Result{1971, 12, 9, +1}, nil},
	{"240.15.10.108", Result{1972, 6, 10, +1}, nil},
	{"242.18.28.160", Result{1993, 12, 28, 0}, nil},
	{"255.76.200.237", Result{2135, 1, 72, -1}, nil},
	{"127.240.133.76", Result{0, 0, 0, 0}, &Error{Code: -1}},
	{"255.209.76.40", Result{0, 0, 0, 0}, &Error{Code: -2}},
	{"241.179.152.73", Result{0, 0, 0, 0}, &Error{Code: -3}},
}
