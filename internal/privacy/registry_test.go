package privacy

import (
	"strings"
	"testing"
)

func TestExtensionRegistry(t *testing.T) {
	var r registry
	e := Extension{Build: "operator", Requirements: []string{"WBFT-SM-999"}, Catalogs: []string{strings.Repeat("a", 64)}}
	if err := r.register(e); err != nil {
		t.Fatal(err)
	}
	e.Requirements[0] = "WBFT-SM-998"
	e.Catalogs[0] = strings.Repeat("b", 64)
	if !r.profiles["operator"].requirements["WBFT-SM-999"] || !r.profiles["operator"].catalogs[strings.Repeat("a", 64)] {
		t.Fatal("registration borrowed mutable input")
	}
	if !r.private() {
		t.Fatal("extension did not require private deployment")
	}
	e.Build = "late"
	if err := r.register(e); err == nil {
		t.Fatal("late registration accepted")
	}
}

func TestExtensionRejectsInvalidProfiles(t *testing.T) {
	valid := Extension{Build: "operator", Requirements: []string{"WBFT-SM-999"}, Catalogs: []string{strings.Repeat("a", 64)}}
	for _, e := range []Extension{
		{Build: "public", Requirements: valid.Requirements, Catalogs: valid.Catalogs},
		{Build: "operator", Requirements: valid.Requirements},
		{Build: "operator", Requirements: []string{"invalid"}, Catalogs: valid.Catalogs},
		{Build: "operator", Requirements: valid.Requirements, Catalogs: []string{"bad"}},
		{Build: "operator", Requirements: append(valid.Requirements, "WBFT-SM-999"), Catalogs: valid.Catalogs},
	} {
		var r registry
		if err := r.register(e); err == nil {
			t.Fatal("invalid extension accepted")
		}
	}
	var r registry
	if err := r.register(valid); err != nil {
		t.Fatal(err)
	}
	if err := r.register(valid); err == nil {
		t.Fatal("duplicate accepted")
	}
}
