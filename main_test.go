package main

import (
	"os"
	"testing"

	"github.com/cert-manager/cert-manager/test/acme/dns"
)

var (
	zone = os.Getenv("TEST_ZONE_NAME")
)

func TestRunsSuite(t *testing.T) {
	// The manifest path should contain a file named config.json that is a
	// snippet of valid configuration that should be included on the
	// ChallengeRequest passed as part of the test cases.

	fixture := dns.NewFixture(&bunnySolver{},
		dns.SetResolvedZone(zone),
		dns.SetManifestPath("testdata/bunny"),
		dns.SetDNSServer("9.9.9.9:53"),
		dns.SetUseAuthoritative(false),
	)

	fixture.RunConformance(t)
}
