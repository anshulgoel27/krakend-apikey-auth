package auth

import (
	"context"
	"os"

	"github.com/google/uuid"
	"github.com/luraproject/lura/v2/logging"
	"github.com/nats-io/nats.go"
)

func startConsumer(ctx context.Context, l logging.Logger, logPrefix string) {
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
		// TODO consume the message and update the API Key Cache
		l.Info(logPrefix, "Received message for consumer", consumerID, string(msg.Data))
		// Acknowledge the message
		msg.Ack()
	}, nats.Durable(consumerID), nats.ManualAck())
	if err != nil {
		l.Error(logPrefix, "Error subscribing", err)
		return
	}

	// Wait for context cancellation
	<-ctx.Done()
	sub.Unsubscribe()
	l.Debug(logPrefix, "Unsubscribed consumer", consumerID)
	nc.Close()
	l.Debug(logPrefix, "Closed NATS connection")
}
