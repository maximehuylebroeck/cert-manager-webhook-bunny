package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"

	bunny "github.com/simplesurance/bunny-go"
)

type bunnyDNSSolver struct {
	client *kubernetes.Clientset
}

type bunnyDNSConfig struct {
	AccessKey string `json:"accessKeySecretRef"`
	ZoneID int64 `json:"zoneIDSecretRef"`
}

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	cmd.RunWebhookServer(GroupName,
		&bunnyDNSSolver{},
	)
}

func (c *bunnyDNSSolver) Name() string {
	return "bunny"
}

func loadConfig(cfgJSON *extapi.JSON) (bunnyDNSConfig, error) {
	cfg := bunnyDNSConfig{}

	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}
	return cfg, nil
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
func (c *bunnyDNSSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	recordName := strings.TrimSuffix(strings.TrimSuffix(ch.ResolvedFQDN, ch.ResolvedZone), ".")

	val, err := c.HasTXTRecord(cfg, recordName, ch.Key)
	if err != nil {
		return err
	}

	// The record is already there.
	if val != nil {
		log.Println("TXT record is present, skipping")
		return nil
	}

	recordType := 3
	var ttl int32 = 180
	record := &bunny.AddOrUpdateDNSRecordOptions{
		Type: &recordType,
		Value: &ch.Key,
		Name: &recordName,
		TTL: &ttl,
	}

	log.Printf("attempting to add record: value=%s, recordname=%s\n", ch.Key, recordName)
	api := bunny.NewClient(cfg.AccessKey)
	_, err = api.DNSZone.AddDNSRecord(context.Background(), cfg.ZoneID, record)
	if err != nil {
		return fmt.Errorf("failed to add TXT record: %s", err.Error())
	}
	log.Println("added TXT record")
	return nil
}

// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *bunnyDNSSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	recordName := strings.TrimSuffix(strings.TrimSuffix(ch.ResolvedFQDN, ch.ResolvedZone), ".")

	record, err := c.HasTXTRecord(cfg, recordName, ch.Key)
	if err != nil {
		return fmt.Errorf("failed to get zone records: %v", err)
	}
	if record == nil {
		return nil
	}

	api := bunny.NewClient(cfg.AccessKey)
	if err := api.DNSZone.DeleteDNSRecord(context.Background(), cfg.ZoneID,
	    *record.ID); err != nil {
		return fmt.Errorf("failed to delete TXT record: %v", err)
	}

	return nil
}

func (c *bunnyDNSSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}
	c.client = cl
	return nil
}

func (c *bunnyDNSSolver) HasTXTRecord(cfg bunnyDNSConfig, name, key string) (*bunny.DNSRecord, error) {
	api := bunny.NewClient(cfg.AccessKey)
	zone, err := api.DNSZone.Get(context.Background(), cfg.ZoneID)
	if err != nil {
		return nil, fmt.Errorf("error getting zone records: %v", err)
	}
	for _, record := range zone.Records {
		if *record.Type == 3 && *record.Name == name && *record.Value == key {
			return &record, nil
		}
	}
	return nil, nil
}
