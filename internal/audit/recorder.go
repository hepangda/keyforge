// Package audit owns keyforge's append-only audit log.
//
// The Recorder is the only blessed write path: it persists to Postgres
// and mirrors to slog so an operator without DB access still sees the
// event in the structured log stream. The Postgres table grants only
// INSERT to the keyforge role; any UPDATE/DELETE attempt will fail.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/hepangda/keyforge/internal/storage/postgres"
	"github.com/hepangda/keyforge/internal/storage/postgres/db"
)

// Event captures one audit row. Either ActorUserID or ActorClientID
// should be set (a human admin or a machine actor); both may be set if
// e.g. a service-account token also carries an end-user context.
type Event struct {
	TenantID      uuid.UUID
	ActorUserID   *uuid.UUID
	ActorClientID *uuid.UUID
	Action        string
	TargetType    string
	TargetID      string
	IP            string
	UserAgent     string
	RequestID     string
	Attributes    map[string]any
}

// Sink is the persistence contract for audit events. Production wires a
// PostgresSink; tests can wire a fake.
type Sink interface {
	Insert(ctx context.Context, e Event) error
}

// Recorder writes events to a Sink and mirrors them to slog.
type Recorder struct {
	sink   Sink
	logger *slog.Logger
}

// NewRecorder constructs a Recorder.
func NewRecorder(s Sink, logger *slog.Logger) *Recorder {
	if logger == nil {
		logger = slog.Default()
	}
	return &Recorder{sink: s, logger: logger}
}

// Record persists the event. Errors are logged but never propagated to
// the caller — the auditing path must not break the user's request.
func (r *Recorder) Record(ctx context.Context, e Event) {
	if err := r.sink.Insert(ctx, e); err != nil {
		r.logger.Error("audit insert failed",
			slog.String("action", e.Action),
			slog.String("target_type", e.TargetType),
			slog.Any("error", err))
	}
	r.logger.Info("audit",
		slog.String("action", e.Action),
		slog.String("target_type", e.TargetType),
		slog.String("target_id", e.TargetID),
		slog.String("request_id", e.RequestID),
		slog.Any("tenant_id", e.TenantID),
	)
}

// PostgresSink writes audit events to the audit_log table.
type PostgresSink struct {
	q *db.Queries
}

// NewPostgresSink constructs a PostgresSink.
func NewPostgresSink(q *db.Queries) *PostgresSink { return &PostgresSink{q: q} }

// Insert implements Sink.
func (s *PostgresSink) Insert(ctx context.Context, e Event) error {
	// Audit insertion must not depend on a tenant being on context;
	// the recorder already carries e.TenantID. Inject it so any
	// tenant-bound queries the recorder downstream might add still
	// work.
	if _, err := postgres.MustTenant(ctx); errors.Is(err, postgres.ErrNoTenant) {
		ctx = postgres.ContextWithTenant(ctx, e.TenantID)
	}
	attrs, err := json.Marshal(e.Attributes)
	if err != nil {
		return err
	}
	actorUser := pgtype.UUID{}
	if e.ActorUserID != nil {
		actorUser = pgtype.UUID{Bytes: *e.ActorUserID, Valid: true}
	}
	actorClient := pgtype.UUID{}
	if e.ActorClientID != nil {
		actorClient = pgtype.UUID{Bytes: *e.ActorClientID, Valid: true}
	}
	targetID := pgtype.Text{}
	if e.TargetID != "" {
		targetID = pgtype.Text{String: e.TargetID, Valid: true}
	}
	_, err = s.q.InsertAuditEvent(ctx, db.InsertAuditEventParams{
		TenantID:      e.TenantID,
		ActorUserID:   actorUser,
		ActorClientID: actorClient,
		Action:        e.Action,
		TargetType:    e.TargetType,
		TargetID:      targetID,
		Ip:            textOpt(e.IP),
		UserAgent:     textOpt(e.UserAgent),
		RequestID:     textOpt(e.RequestID),
		Attributes:    attrs,
	})
	return err
}

func textOpt(s string) pgtype.Text { return pgtype.Text{String: s, Valid: s != ""} }
