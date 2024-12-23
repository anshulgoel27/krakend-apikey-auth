package auth

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/luraproject/lura/v2/logging"
	"github.com/nats-io/nats.go"
)

// Define a custom type for the enum
type MessageType string

// Define constants for the allowed values
const (
	Created MessageType = "CREATED"
	Deleted MessageType = "DELETED"
)

type KeyAdminMessage struct {
	Type MessageType            `json:"type"`
	Data map[string]interface{} `json:"data"`
}

// Data structure for CREATED messages
type CreatedKeyData struct {
	UserID         string    `json:"user_id"`
	Key            string    `json:"key"`
	Email          string    `json:"email"`
	ExpirationDate time.Time `json:"expiration_date"`
	CreationDate   time.Time `json:"creation_date"`
	Enabled        bool      `json:"enabled"`
	Plan           string    `json:"plan"`
}

// Data structure for DELETED messages
type DeletedKeyData struct {
	Key string `json:"key"`
}

// Validate the Type field
func (mt MessageType) IsValid() bool {
	return mt == Created || mt == Deleted
}

// Helper function to map generic map[string]interface{} to a specific struct
func mapToStruct(input map[string]interface{}, output interface{}) error {
	data, err := json.Marshal(input)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, output)
}

func processMessage(data []byte, logPrefix string, consumerID string, l logging.Logger, authManager *AuthKeyLookupManager) bool {
	// Deserialize the message into KeyAdminMessage
	var keyAdminMsg KeyAdminMessage
	err := json.Unmarshal(data, &keyAdminMsg)
	if err != nil {
		l.Error(logPrefix, "Error unmarshalling message:", err)
		return false
	}

	// Validate the message type
	if !keyAdminMsg.Type.IsValid() {
		l.Error(logPrefix, "Invalid message type:", keyAdminMsg.Type)
		return false
	}

	// Process based on the type
	switch keyAdminMsg.Type {
	case Created:
		var createdKeyData CreatedKeyData
		err := mapToStruct(keyAdminMsg.Data, &createdKeyData)
		if err != nil {
			l.Error(logPrefix, "Error parsing CREATED data:", err)
			return false
		}
		l.Debug(logPrefix, "Recieved CREATED data for consumer", consumerID, createdKeyData)

		ok, err := authManager.addKey(&createdKeyData)
		if !ok {
			if err != nil {
				l.Debug(logPrefix, "Key CREATED failed for consumer", consumerID, createdKeyData, err.Error())
			}
		} else {
			l.Debug(logPrefix, "Processed CREATED data for consumer", consumerID, createdKeyData)
		}
	case Deleted:
		var deletedKeyData DeletedKeyData
		err := mapToStruct(keyAdminMsg.Data, &deletedKeyData)
		if err != nil {
			l.Error(logPrefix, "Error parsing DELETED data:", err)
			return false
		}
		l.Debug(logPrefix, "Recieved DELETED data for consumer", consumerID, deletedKeyData)

		deletedKey, ok := authManager.deleteKey(deletedKeyData.Key)
		if !ok {
			l.Debug(logPrefix, "Key Deletion failed for consumer", consumerID, deletedKeyData)
		} else {
			l.Debug(logPrefix, "Processed DELETED data for consumer", consumerID, deletedKey)
		}

	default:
		l.Error(logPrefix, "Unsupported message type:", keyAdminMsg.Type)
		return false
	}

	return true
}

func StartConsumer(ctx context.Context, l logging.Logger, logPrefix string, authManager *AuthKeyLookupManager) {
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
		processMessage(msg.Data, logPrefix, consumerID, l, authManager)
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
	l.Debug(logPrefix, "Closed NATS connection for consumer", consumerID)
}
