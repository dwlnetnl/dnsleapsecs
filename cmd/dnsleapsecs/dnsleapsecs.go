package main

import (
	"context"
	"errors"
	"log"

	"github.com/dwlnetnl/dnsleapsecs"
)

func main() {
	log.SetFlags(0)

	log.Println("Checking test-vectors:")
	log.Println()
	for _, tv := range dnsleapsecs.TestVectors {
		r, e, assert := assertDecode(testVector(tv))
		if e == nil {
			log.Printf("   IP: %-15s  Error:  0  Year: %4d  Month %2d  dTAI: %3d  Delta:  %2d",
				tv.IP, r.Year, r.Month, r.DTAI, r.Delta)
		} else {
			log.Printf("   IP: %-15s  Error: %2d  Year: %4d  Month %2d  dTAI: %3d  Delta:  %2d",
				tv.IP, e.Code, r.Year, r.Month, r.DTAI, r.Delta)
		}
		if assert != assertOK {
			log.Fatal(assertName[assert] + " assertion failed")
		}
	}
	log.Println()
	log.Println("If you see this, the tests ran OK")
	log.Println()

	log.Println("Querying currently published leapsecond announcement:")
	ctx := context.Background()
	ip, r, err := dnsleapsecs.Fetch(ctx)
	if err != nil {
		log.Fatalf("failed with error: %v", err)
	}
	log.Println()
	log.Printf("   IP: %-15s  Error: %2d  Year: %4d  Month %2d  dTAI: %3d  Delta:  %2d",
		ip, 0, r.Year, r.Month, r.DTAI, r.Delta)
	log.Println()

	log.Println("That means:")
	log.Println()
	log.Printf("   Information is valid until end of UTC-month %d of year %d",
		r.Month, r.Year)
	log.Printf("   After that month: UTC = TAI - %d seconds", r.DTAI+r.Delta)
	log.Printf("   Until then:       UTC = TAI - %d seconds", r.DTAI)
}

type testVector struct {
	IP     string
	Result dnsleapsecs.Result
	Err    *dnsleapsecs.Error
}

const (
	assertOK = iota
	assertError
	assertYear
	assertMonth
	assertDTAI
	assertDelta
)

var assertName = [...]string{
	assertError: "error",
	assertYear:  "year",
	assertMonth: "month",
	assertDTAI:  "dtai",
	assertDelta: "delta",
}

func assertDecode(tv testVector) (dnsleapsecs.Result, *dnsleapsecs.Error, int) {
	r, err := dnsleapsecs.Decode(tv.IP)
	var e *dnsleapsecs.Error
	if errors.As(err, &e) && *e != *tv.Err {
		return dnsleapsecs.Result{}, e, assertError
	}
	if r.Year != tv.Result.Year {
		return dnsleapsecs.Result{}, e, assertYear
	}
	if r.Month != tv.Result.Month {
		return dnsleapsecs.Result{}, e, assertMonth
	}
	if r.DTAI != tv.Result.DTAI {
		return dnsleapsecs.Result{}, e, assertDTAI
	}
	if r.Delta != tv.Result.Delta {
		return dnsleapsecs.Result{}, e, assertDelta
	}
	return r, e, assertOK
}
