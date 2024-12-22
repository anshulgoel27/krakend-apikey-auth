package auth

import (
	"context"
	"os"

	"github.com/google/uuid"
	"github.com/luraproject/lura/v2/logging"
	"github.com/nats-io/nats.go"
)

func startConsumer(ctx context.Context, l logging.Logger, logPrefix string) {
	// TODO: create a nats consumer to listen to events for create/delete key build the cache
	// Connect to NATS server
	url := os.Getenv("NATS_SERVER_URL")
	if url == "" {
		url = nats.DefaultURL
	}

	topic := os.Getenv("NATS_APIKEY_MANAGE_TOPIC")
	if topic == "" {
		l.Error(logPrefix, "Error NATS_APIKEY_MANAGE_TOPIC variable not defined")
	}

	nc, err := nats.Connect(url)
	if err != nil {
		l.Error(logPrefix, "Error connecting to NATS", err)
		return
	}

	// Access JetStream context
	js, err := nc.JetStream()
	if err != nil {
		l.Error(logPrefix, "Error accessing JetStream", err)
		return
	}

	// Generate a GUID for the consumer name
	consumerID := uuid.New().String()
	l.Info(logPrefix, "Starting consumer with ID", consumerID)

	// Subscribe using the GUID as the durable name
	sub, err := js.Subscribe(topic, func(msg *nats.Msg) {
		l.Info(logPrefix, "Received message", consumerID, string(msg.Data))
		// Acknowledge the message
		msg.Ack()
	}, nats.Durable(consumerID), nats.ManualAck())
	if err != nil {
		l.Error(logPrefix, "Error subscribing", err)
		return
	}
	defer func() {
		sub.Unsubscribe()
		l.Info(logPrefix, "Unsubscribed consumer", consumerID)
	}()

	// Wait for context cancellation
	<-ctx.Done()
	nc.Close()
	l.Info(logPrefix, "Closed NATS connection")
	l.Info(logPrefix, "Consumer shutting down", consumerID)
}
