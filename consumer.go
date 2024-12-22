package auth

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/luraproject/lura/v2/logging"
	"github.com/nats-io/nats.go"
)

func startConsumer(l logging.Logger) {
	// Create a context with cancellation
	ctx, cancel := context.WithCancel(context.Background())

	// Handle OS signals for graceful shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	go natsConsumer(ctx, l)

	// Wait for an interrupt signal
	<-signalChan
	l.Info("Received shutdown signal")
	cancel() // Cancel the context

	time.Sleep(1 * time.Second)
}

func natsConsumer(ctx context.Context, l logging.Logger) {
	// TODO: create a nats consumer to listen to events for create/delete key build the cache
	// Connect to NATS server
	url := os.Getenv("NATS_SERVER_URL")
	if url == "" {
		url = nats.DefaultURL
	}
	nc, err := nats.Connect(url)
	if err != nil {
		l.Error("Error connecting to NATS: %v", err)
		return
	}
	defer func() {
		nc.Close()
		l.Info("Closed NATS connection")
	}()

	// Access JetStream context
	js, err := nc.JetStream()
	if err != nil {
		l.Error("Error accessing JetStream: %v", err)
		return
	}

	// Generate a GUID for the consumer name
	consumerID := uuid.New().String()
	l.Info("Starting consumer with ID: %s", consumerID)

	// Subscribe using the GUID as the durable name
	sub, err := js.Subscribe("event.key.created", func(msg *nats.Msg) {
		log.Printf("[%s] Received message: %s", consumerID, string(msg.Data))
		// Acknowledge the message
		msg.Ack()
	}, nats.Durable(consumerID), nats.ManualAck())
	if err != nil {
		l.Error("Error subscribing: %v", err)
		return
	}
	defer func() {
		sub.Unsubscribe()
		l.Info("Unsubscribed consumer %s", consumerID)
	}()

	// Wait for context cancellation
	<-ctx.Done()
	l.Info("Consumer %s shutting down", consumerID)
}
