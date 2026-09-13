package binlog

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"auditlogd/internal/source"
	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/replication"
)

// Config holds MySQL replication connection details.
type Config struct {
	Host     string
	Port     uint16
	User     string
	Password string
	ServerID uint32
	Flavor   string // "mysql"
}

// MySQLBinlogSource implements source.ChangeSource using go-mysql.
type MySQLBinlogSource struct {
	cfg        Config
	syncer     *replication.BinlogSyncer
	streamer   *replication.BinlogStreamer
	mu         sync.RWMutex
	currentPos source.Position
	closed     bool
}

// NewMySQLBinlogSource creates a new CDC MySQL binlog source.
func NewMySQLBinlogSource(cfg Config) *MySQLBinlogSource {
	if cfg.ServerID == 0 {
		cfg.ServerID = 1001
	}
	if cfg.Flavor == "" {
		cfg.Flavor = "mysql"
	}
	return &MySQLBinlogSource{
		cfg: cfg,
	}
}

// Checkpoint returns the current binlog coordinate.
func (s *MySQLBinlogSource) Checkpoint() source.Position {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentPos
}

// ResumeFrom sets the initial starting position before streaming begins.
func (s *MySQLBinlogSource) ResumeFrom(pos source.Position) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.currentPos = pos
	return nil
}

// Stream starts the binlog replication worker and yields grouped transactions.
func (s *MySQLBinlogSource) Stream(ctx context.Context) (<-chan source.Transaction, error) {
	s.mu.Lock()
	syncerCfg := replication.BinlogSyncerConfig{
		ServerID: s.cfg.ServerID,
		Flavor:   s.cfg.Flavor,
		Host:     s.cfg.Host,
		Port:     s.cfg.Port,
		User:     s.cfg.User,
		Password: s.cfg.Password,
	}

	s.syncer = replication.NewBinlogSyncer(syncerCfg)

	var startPos mysql.Position
	if s.currentPos.File != "" && s.currentPos.Position > 0 {
		startPos = mysql.Position{
			Name: s.currentPos.File,
			Pos:  s.currentPos.Position,
		}
	} else {
		// Seek to end or start from empty
		startPos = mysql.Position{}
	}

	streamer, err := s.syncer.StartSync(startPos)
	if err != nil {
		s.syncer.Close()
		s.mu.Unlock()
		return nil, fmt.Errorf("failed to start binlog sync at %v: %w", startPos, err)
	}
	s.streamer = streamer
	s.closed = false
	s.mu.Unlock()

	outCh := make(chan source.Transaction, 100)

	go s.readLoop(ctx, outCh)

	return outCh, nil
}

func (s *MySQLBinlogSource) readLoop(ctx context.Context, outCh chan<- source.Transaction) {
	defer close(outCh)

	var inTx bool
	var currentTx source.Transaction

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		s.mu.RLock()
		streamer := s.streamer
		closed := s.closed
		s.mu.RUnlock()

		if closed || streamer == nil {
			return
		}

		ev, err := streamer.GetEvent(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// Transient error or EOF
			time.Sleep(100 * time.Millisecond)
			continue
		}

		header := ev.Header
		pos := source.Position{
			Position: header.LogPos,
		}

		switch e := ev.Event.(type) {
		case *replication.RotateEvent:
			s.mu.Lock()
			s.currentPos.File = string(e.NextLogName)
			s.currentPos.Position = uint32(e.Position)
			s.mu.Unlock()

		case *replication.QueryEvent:
			query := strings.ToUpper(strings.TrimSpace(string(e.Query)))
			schema := string(e.Schema)

			if query == "BEGIN" {
				inTx = true
				s.mu.RLock()
				currentTx = source.Transaction{
					TransactionID: fmt.Sprintf("%s:%d", s.currentPos.File, header.LogPos),
					Position: source.Position{
						File:     s.currentPos.File,
						Position: header.LogPos,
					},
					CommittedAt: time.Unix(int64(header.Timestamp), 0).UTC(),
					Changes:     make([]source.RowChange, 0),
				}
				s.mu.RUnlock()
			} else if query == "COMMIT" {
				if inTx {
					currentTx.Position.Position = header.LogPos
					s.updateCheckpoint(currentTx.Position)
					outCh <- currentTx
					inTx = false
					currentTx = source.Transaction{}
				}
			} else if query == "ROLLBACK" {
				inTx = false
				currentTx = source.Transaction{}
			} else if isDDL(query) {
				// DDL event: dispatch as immediate transaction
				s.mu.RLock()
				file := s.currentPos.File
				s.mu.RUnlock()
				ddlTx := source.Transaction{
					TransactionID: fmt.Sprintf("%s:%d", file, header.LogPos),
					Position: source.Position{
						File:     file,
						Position: header.LogPos,
					},
					CommittedAt:  time.Unix(int64(header.Timestamp), 0).UTC(),
					DDLStatement: string(e.Query),
					Changes: []source.RowChange{
						{
							Schema: schema,
							Action: source.EventTypeDDL,
						},
					},
				}
				s.updateCheckpoint(ddlTx.Position)
				outCh <- ddlTx
			}

		case *replication.XIDEvent:
			if inTx {
				currentTx.TransactionID = fmt.Sprintf("xid:%d", e.XID)
				currentTx.Position.Position = header.LogPos
				s.updateCheckpoint(currentTx.Position)
				outCh <- currentTx
				inTx = false
				currentTx = source.Transaction{}
			}

		case *replication.RowsEvent:
			tableName := string(e.Table.Table)
			schema := string(e.Table.Schema)

			var action source.EventType
			switch ev.Header.EventType {
			case replication.WRITE_ROWS_EVENTv1, replication.WRITE_ROWS_EVENTv2:
				action = source.EventTypeInsert
			case replication.UPDATE_ROWS_EVENTv1, replication.UPDATE_ROWS_EVENTv2:
				action = source.EventTypeUpdate
			case replication.DELETE_ROWS_EVENTv1, replication.DELETE_ROWS_EVENTv2:
				action = source.EventTypeDelete
			}

			changes := parseRowChanges(e, action, schema, tableName)
			if inTx {
				currentTx.Changes = append(currentTx.Changes, changes...)
			} else {
				// Autocommit statement outside explicit BEGIN/COMMIT
				s.mu.RLock()
				file := s.currentPos.File
				s.mu.RUnlock()
				autoTx := source.Transaction{
					TransactionID: fmt.Sprintf("%s:%d", file, header.LogPos),
					Position: source.Position{
						File:     file,
						Position: header.LogPos,
					},
					CommittedAt: time.Unix(int64(header.Timestamp), 0).UTC(),
					Changes:     changes,
				}
				s.updateCheckpoint(autoTx.Position)
				outCh <- autoTx
			}
		}

		s.mu.Lock()
		if pos.Position > 0 {
			s.currentPos.Position = pos.Position
		}
		s.mu.Unlock()
	}
}

func (s *MySQLBinlogSource) updateCheckpoint(pos source.Position) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if pos.File != "" {
		s.currentPos.File = pos.File
	}
	s.currentPos.Position = pos.Position
}

func (s *MySQLBinlogSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.syncer != nil {
		s.syncer.Close()
	}
	return nil
}

func isDDL(query string) bool {
	q := strings.ToUpper(strings.TrimSpace(query))
	return strings.HasPrefix(q, "ALTER TABLE") ||
		strings.HasPrefix(q, "CREATE TABLE") ||
		strings.HasPrefix(q, "DROP TABLE") ||
		strings.HasPrefix(q, "RENAME TABLE")
}

func parseRowChanges(e *replication.RowsEvent, action source.EventType, schema, table string) []source.RowChange {
	var changes []source.RowChange

	switch action {
	case source.EventTypeInsert:
		for _, row := range e.Rows {
			afterMap := make(map[string]interface{})
			for colIdx, val := range row {
				colName := fmt.Sprintf("col_%d", colIdx)
				afterMap[colName] = val
			}
			changes = append(changes, source.RowChange{
				Schema:     schema,
				Table:      table,
				Action:     action,
				AfterImage: afterMap,
			})
		}

	case source.EventTypeDelete:
		for _, row := range e.Rows {
			beforeMap := make(map[string]interface{})
			for colIdx, val := range row {
				colName := fmt.Sprintf("col_%d", colIdx)
				beforeMap[colName] = val
			}
			changes = append(changes, source.RowChange{
				Schema:      schema,
				Table:       table,
				Action:      action,
				BeforeImage: beforeMap,
			})
		}

	case source.EventTypeUpdate:
		// Rows in update events come in pairs: [0]=before, [1]=after, [2]=before, [3]=after...
		for i := 0; i < len(e.Rows); i += 2 {
			if i+1 >= len(e.Rows) {
				break
			}
			beforeRow := e.Rows[i]
			afterRow := e.Rows[i+1]

			beforeMap := make(map[string]interface{})
			for colIdx, val := range beforeRow {
				colName := fmt.Sprintf("col_%d", colIdx)
				beforeMap[colName] = val
			}
			afterMap := make(map[string]interface{})
			for colIdx, val := range afterRow {
				colName := fmt.Sprintf("col_%d", colIdx)
				afterMap[colName] = val
			}

			changes = append(changes, source.RowChange{
				Schema:      schema,
				Table:       table,
				Action:      action,
				BeforeImage: beforeMap,
				AfterImage:  afterMap,
			})
		}
	}

	return changes
}
