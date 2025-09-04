package main

import (
	"context"
	"errors"
	"testing"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	bunny "github.com/simplesurance/bunny-go"
	corev1 "k8s.io/api/core/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

type mockBunnyClient struct {
	zones   []bunny.DNSZone
	records map[int64][]bunny.DNSRecord
}

func (m *mockBunnyClient) AddDNSRecord(ctx context.Context, zoneID int64, record *bunny.AddOrUpdateDNSRecordOptions) (*bunny.DNSRecord, error) {
	if m.records == nil {
		m.records = make(map[int64][]bunny.DNSRecord)
	}
	id := int64(len(m.records[zoneID]) + 1)
	newRecord := bunny.DNSRecord{
		ID:    &id,
		Type:  record.Type,
		Value: record.Value,
		Name:  record.Name,
		TTL:   record.TTL,
	}
	m.records[zoneID] = append(m.records[zoneID], newRecord)
	return &newRecord, nil
}

func (m *mockBunnyClient) DeleteDNSRecord(ctx context.Context, zoneID, recordID int64) error {
	records, ok := m.records[zoneID]
	if !ok {
		return errors.New("zone not found")
	}
	for i, record := range records {
		if *record.ID == recordID {
			m.records[zoneID] = append(records[:i], records[i+1:]...)
			return nil
		}
	}
	return errors.New("record not found")
}

func (m *mockBunnyClient) Get(ctx context.Context, id int64) (*bunny.DNSZone, error) {
	for _, zone := range m.zones {
		if *zone.ID == id {
			zone.Records = m.records[id]
			return &zone, nil
		}
	}
	return nil, errors.New("zone not found")
}

func (m *mockBunnyClient) List(ctx context.Context, opts *bunny.PaginationOptions) (*bunny.DNSZoneList, error) {
	hasMore := false
	return &bunny.DNSZoneList{
		Items:        m.zones,
		HasMoreItems: &hasMore,
	}, nil
}

func newTestSolver(client *mockBunnyClient, kubeObjects ...runtime.Object) *bunnySolver {
	return &bunnySolver{
		client: fake.NewSimpleClientset(kubeObjects...),
	}
}

func TestPresent(t *testing.T) {
	domain := "example.com"
	zoneID := int64(123)
	secretName := "bunny-credentials"
	secretKey := "accessKey"
	challengeKey := "challenge-key"

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: "default",
		},
		Data: map[string][]byte{
			secretKey: []byte("test-access-key"),
		},
	}

	ch := &v1alpha1.ChallengeRequest{
		ResolvedZone: "example.com.",
		ResolvedFQDN: "_acme-challenge.example.com.",
		ResourceNamespace: "default",
		Key: challengeKey,
		Config: &extapi.JSON{
			Raw: []byte(`{"apiSecretRef":{"name":"` + secretName + `","key":"` + secretKey + `"}}`),
		},
	}

	client := &mockBunnyClient{
		zones: []bunny.DNSZone{
			{
				ID:     &zoneID,
				Domain: &domain,
			},
		},
	}

	solver := newTestSolver(client, secret)

	// Override the newAPIClient function to return our mock client
	originalNewBunnyDNSClient := newBunnyDNSClient
	newBunnyDNSClient = func(apiKey string) bunnyDNSClient {
		return client
	}
	defer func() { newBunnyDNSClient = originalNewBunnyDNSClient }()

	err := solver.Present(ch)
	if err != nil {
		t.Fatalf("Present() failed: %v", err)
	}

	// Verify that the record was created
	zone, err := client.Get(context.Background(), zoneID)
	if err != nil {
		t.Fatalf("client.Get() failed: %v", err)
	}

	if len(zone.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(zone.Records))
	}
	record := zone.Records[0]
	if *record.Value != challengeKey {
		t.Errorf("expected record value to be %q, got %q", challengeKey, *record.Value)
	}
	if *record.Name != "_acme-challenge" {
		t.Errorf("expected record name to be %q, got %q", "_acme-challenge", *record.Name)
	}
}

func TestCleanUp(t *testing.T) {
	domain := "example.com"
	zoneID := int64(123)
	recordID := int64(1)
	secretName := "bunny-credentials"
	secretKey := "accessKey"
	challengeKey := "challenge-key"
	recordName := "_acme-challenge"

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: "default",
		},
		Data: map[string][]byte{
			secretKey: []byte("test-access-key"),
		},
	}

	ch := &v1alpha1.ChallengeRequest{
		ResolvedZone: "example.com.",
		ResolvedFQDN: "_acme-challenge.example.com.",
		ResourceNamespace: "default",
		Key: challengeKey,
		Config: &extapi.JSON{
			Raw: []byte(`{"apiSecretRef":{"name":"` + secretName + `","key":"` + secretKey + `"}}`),
		},
	}

	client := &mockBunnyClient{
		zones: []bunny.DNSZone{
			{
				ID:     &zoneID,
				Domain: &domain,
			},
		},
		records: map[int64][]bunny.DNSRecord{
			zoneID: {
				{
					ID:    &recordID,
					Type:  func(i int) *int { return &i }(3),
					Name:  &recordName,
					Value: &challengeKey,
				},
			},
		},
	}

	solver := newTestSolver(client, secret)

	// Override the newAPIClient function to return our mock client
	originalNewBunnyDNSClient := newBunnyDNSClient
	newBunnyDNSClient = func(apiKey string) bunnyDNSClient {
		return client
	}
	defer func() { newBunnyDNSClient = originalNewBunnyDNSClient }()

	err := solver.CleanUp(ch)
	if err != nil {
		t.Fatalf("CleanUp() failed: %v", err)
	}

	// Verify that the record was deleted
	zone, err := client.Get(context.Background(), zoneID)
	if err != nil {
		t.Fatalf("client.Get() failed: %v", err)
	}

	if len(zone.Records) != 0 {
		t.Fatalf("expected 0 records, got %d", len(zone.Records))
	}
}
