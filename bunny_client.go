package main

import (
	"context"

	bunny "github.com/simplesurance/bunny-go"
)

// bunnyDNSClient is an interface that matches the part of the bunny-go client that we use.
// This allows us to mock the client in tests.
type bunnyDNSClient interface {
	AddDNSRecord(ctx context.Context, zoneID int64, record *bunny.AddOrUpdateDNSRecordOptions) (*bunny.DNSRecord, error)
	DeleteDNSRecord(ctx context.Context, zoneID, recordID int64) error
	Get(ctx context.Context, id int64) (*bunny.DNSZone, error)
	List(ctx context.Context, opts *bunny.PaginationOptions) (*bunny.DNSZoneList, error)
}

// bunnyClientAdapter wraps the bunny.Client.DNSZone service to implement the bunnyDNSClient interface.
type bunnyClientAdapter struct {
	dnsZoneService *bunny.DNSZoneService
}

func (b *bunnyClientAdapter) AddDNSRecord(ctx context.Context, zoneID int64, record *bunny.AddOrUpdateDNSRecordOptions) (*bunny.DNSRecord, error) {
	return b.dnsZoneService.AddDNSRecord(ctx, zoneID, record)
}

func (b *bunnyClientAdapter) DeleteDNSRecord(ctx context.Context, zoneID, recordID int64) error {
	return b.dnsZoneService.DeleteDNSRecord(ctx, zoneID, recordID)
}

func (b *bunnyClientAdapter) Get(ctx context.Context, id int64) (*bunny.DNSZone, error) {
	return b.dnsZoneService.Get(ctx, id)
}

func (b *bunnyClientAdapter) List(ctx context.Context, opts *bunny.PaginationOptions) (*bunny.DNSZoneList, error) {
	return b.dnsZoneService.List(ctx, opts)
}

// newBunnyDNSClient creates a new bunnyDNSClient from an API key.
func newBunnyDNSClient(apiKey string) bunnyDNSClient {
	client := bunny.NewClient(apiKey)
	return &bunnyClientAdapter{dnsZoneService: client.DNSZone}
}
