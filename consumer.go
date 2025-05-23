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
	Updated MessageType = "UPDATED"
)

type KeyAdminMessage struct {
	Type MessageType            `json:"message_type"`
	Data map[string]interface{} `json:"data"`
}

// Data structure for CREATED messages
type CreatedKeyData struct {
	UserID         string    `json:"user_id"`
	OrgID          string    `json:"org_id"`
	OrgName        string    `json:"org_name"`
	Key            string    `json:"hashed_key"`
	Email          string    `json:"email"`
	ExpirationDate time.Time `json:"expiration_date"`
	CreationDate   time.Time `json:"creation_date"`
	Enabled        bool      `json:"enabled"`
	Plan           string    `json:"plan_name"`
	KeyLabel       string    `json:"key_label"`
}

type CreatedEvent struct {
	Keys []CreatedKeyData `json:"keys"`
}

// Data structure for DELETED messages
type DeletedKeyData struct {
	Key string `json:"hashed_key"`
}

type DeleteEvent struct {
	Keys []DeletedKeyData `json:"keys"`
}

// Validate the Type field
func (mt MessageType) IsValid() bool {
	return mt == Created || mt == Deleted || mt == Updated
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
		var createdKeyEvent CreatedEvent
		err := mapToStruct(keyAdminMsg.Data, &createdKeyEvent)
		if err != nil {
			l.Error(logPrefix, "Error parsing CREATED data:", err)
			return false
		}
		l.Debug(logPrefix, "Recieved CREATED data for consumer", consumerID, createdKeyEvent)
		for _, key := range createdKeyEvent.Keys {
			ok, err := authManager.addKey(&key)
			if !ok {
				if err != nil {
					l.Debug(logPrefix, "Key CREATED failed for consumer", consumerID, key, err.Error())
				}
			} else {
				l.Debug(logPrefix, "Processed CREATED data for consumer", consumerID, key)
			}
		}
	case Deleted:
		var deletedKeyEvent DeleteEvent
		err := mapToStruct(keyAdminMsg.Data, &deletedKeyEvent)
		if err != nil {
			l.Error(logPrefix, "Error parsing DELETED data:", err)
			return false
		}
		l.Debug(logPrefix, "Recieved DELETED data for consumer", consumerID, deletedKeyEvent)

		for _, key := range deletedKeyEvent.Keys {
			deletedKey, ok := authManager.deleteKey(key.Key)
			if !ok {
				l.Debug(logPrefix, "Key Deletion failed for consumer", consumerID, key)
			} else {
				l.Debug(logPrefix, "Processed DELETED data for consumer", consumerID, deletedKey)
			}
		}
	case Updated:
		var enabledKeyEvent CreatedEvent
		err := mapToStruct(keyAdminMsg.Data, &enabledKeyEvent)
		if err != nil {
			l.Error(logPrefix, "Error parsing ENABLED data:", err)
			return false
		}
		l.Debug(logPrefix, "Recieved UPDATED data for consumer", consumerID, enabledKeyEvent)

		for _, key := range enabledKeyEvent.Keys {
			deletedKey, ok := authManager.updateKey(key.Key, key.Enabled, key.Plan)
			if !ok {
				l.Debug(logPrefix, "Key UPDATE failed for consumer", consumerID, key)
			} else {
				l.Debug(logPrefix, "Processed UPDATE data for consumer", consumerID, deletedKey)
			}
		}

	default:
		l.Error(logPrefix, "Unsupported event type:", keyAdminMsg.Type)
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

	opts := []nats.Option{
		nats.ReconnectWait(2 * time.Second), // Wait time between reconnect attempts
		nats.MaxReconnects(10),              // Max number of reconnection attempts
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			l.Info("Disconnected from NATS server!")
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			l.Info("Reconnected to NATS server!")
		}),
	}
	nc, err := nats.Connect(url, opts...)
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
