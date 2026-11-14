// Package pgwire implements a pure-Go PostgreSQL 17 protocol v3.0 read-only
// wire client over net.Conn and crypto/tls using only the Go standard library.
//
// Errors returned by pgwire are strictly sanitized to the three ClearedStack
// public error codes (E_TIMEOUT, E_PARSE, E_NEEDS_SUBTOOL) and never contain
// DSNs, hostnames, IP addresses, ports, usernames, or passwords.
package pgwire

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Public ClearedStack error codes.
const (
	CodeTimeout      = "E_TIMEOUT"
	CodeParse        = "E_PARSE"
	CodeNeedsSubtool = "E_NEEDS_SUBTOOL"
)

// PostgreSQL SQLSTATE codes handled specifically by Conn.
const (
	SQLStateInsufficientPrivilege = "42501"
	SQLStateUndefinedTable        = "42P01"
)

// Protocol v3.0 constants and safety bounds.
const (
	protocolVersion30 = 196608   // 0x00030000
	sslRequestCode    = 80877103 // 0x04d2162f

	authOK                = 0
	authCleartextPassword = 3
	authSASL              = 10
	authSASLContinue      = 11
	authSASLFinal         = 12

	DefaultMaxConns       = 4
	DefaultConnectTimeout = 5 * time.Second
	DefaultQueryTimeout   = 5 * time.Second
	DefaultMaxRows        = 2048
	DefaultMaxMsgBytes    = 4 << 20 // 4 MiB per wire frame
	DefaultMaxResultBytes = 8 << 20 // 8 MiB per query result
)

// SSLMode configures TLS negotiation during connection startup.
type SSLMode string

const (
	SSLDisable    SSLMode = "disable"
	SSLPrefer     SSLMode = "prefer"
	SSLRequire    SSLMode = "require"
	SSLVerifyFull SSLMode = "verify-full"
)

// Error is a sanitized PostgreSQL client error safe for logs and callers.
type Error struct {
	Code     string
	SQLState string
	Message  string
}

func (e *Error) Error() string {
	if e.SQLState != "" {
		return e.Code + " (" + e.SQLState + "): " + e.Message
	}
	return e.Code + ": " + e.Message
}

// PublicCode extracts one of the three public error codes from err.
func PublicCode(err error) string {
	if err == nil {
		return ""
	}
	var pe *Error
	if errors.As(err, &pe) && pe.Code != "" {
		return pe.Code
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return CodeTimeout
	}
	return CodeTimeout
}

// IsInsufficientPrivilege reports whether PostgreSQL refused the query with SQLSTATE 42501.
func IsInsufficientPrivilege(err error) bool {
	var pe *Error
	return errors.As(err, &pe) && pe.SQLState == SQLStateInsufficientPrivilege
}

// IsUndefinedTable reports whether PostgreSQL refused the query with SQLSTATE 42P01.
func IsUndefinedTable(err error) bool {
	var pe *Error
	return errors.As(err, &pe) && pe.SQLState == SQLStateUndefinedTable
}

// Config configures a read-only PostgreSQL v3 connection pool.
type Config struct {
	Address        string
	ServerName     string
	User           string
	Password       string
	Database       string
	SSLMode        SSLMode
	TLSConfig      *tls.Config
	MaxConns       int
	ConnectTimeout time.Duration
	QueryTimeout   time.Duration
	MaxRows        int
	MaxMsgBytes    int
	MaxResultBytes int
}

// ParseConfig parses a postgres:// or postgresql:// DSN and applies an optional
// passwordOverride (read from a mounted Secret file so no password appears in URLs).
func ParseConfig(dsn, passwordOverride string) (Config, error) {
	u, err := url.Parse(strings.TrimSpace(dsn))
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return Config{}, &Error{Code: CodeParse, Message: "invalid database url scheme"}
	}
	host := u.Hostname()
	if host == "" {
		return Config{}, &Error{Code: CodeParse, Message: "database url missing host"}
	}
	port := u.Port()
	if port == "" {
		port = "5432"
	}
	if pNum, perr := strconv.Atoi(port); perr != nil || pNum < 1 || pNum > 65535 {
		return Config{}, &Error{Code: CodeParse, Message: "database url has invalid port"}
	}

	user := ""
	password := ""
	if u.User != nil {
		user = u.User.Username()
		if pw, ok := u.User.Password(); ok {
			password = pw
		}
	}
	if passwordOverride != "" {
		password = passwordOverride
	}
	if user == "" {
		user = "pub_ro"
	}

	dbName := strings.TrimPrefix(u.Path, "/")
	if dbName == "" || strings.Contains(dbName, "/") {
		return Config{}, &Error{Code: CodeParse, Message: "database url missing database name"}
	}

	q := u.Query()
	sslMode := SSLMode(q.Get("sslmode"))
	switch sslMode {
	case "":
		sslMode = SSLPrefer
	case SSLDisable, SSLPrefer, SSLRequire, SSLVerifyFull:
	default:
		return Config{}, &Error{Code: CodeParse, Message: "unsupported sslmode value"}
	}

	connectTimeout := DefaultConnectTimeout
	if ct := q.Get("connect_timeout"); ct != "" {
		secs, serr := strconv.Atoi(ct)
		if serr != nil || secs < 1 || secs > 120 {
			return Config{}, &Error{Code: CodeParse, Message: "invalid connect_timeout value"}
		}
		connectTimeout = time.Duration(secs) * time.Second
	}

	return Config{
		Address:        net.JoinHostPort(host, port),
		ServerName:     host,
		User:           user,
		Password:       password,
		Database:       dbName,
		SSLMode:        sslMode,
		MaxConns:       DefaultMaxConns,
		ConnectTimeout: connectTimeout,
		QueryTimeout:   DefaultQueryTimeout,
		MaxRows:        DefaultMaxRows,
		MaxMsgBytes:    DefaultMaxMsgBytes,
		MaxResultBytes: DefaultMaxResultBytes,
	}, nil
}

// Value represents one column cell in a DataRow.
type Value struct {
	Null bool
	Text string
}

// Result holds the columns and rows returned by a Simple Query.
type Result struct {
	Columns []string
	Rows    [][]Value
}

// QuoteLiteral formats s as a standard-conforming PostgreSQL string literal ('...'),
// rejecting invalid UTF-8 and NUL bytes so interpolated values cannot alter SQL syntax.
func QuoteLiteral(s string) (string, error) {
	if !utf8.ValidString(s) || strings.IndexByte(s, 0) >= 0 {
		return "", &Error{Code: CodeParse, Message: "query literal contains invalid bytes"}
	}
	var b strings.Builder
	b.Grow(len(s) + 4)
	b.WriteByte('\'')
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			b.WriteString("''")
		} else {
			b.WriteByte(s[i])
		}
	}
	b.WriteByte('\'')
	return b.String(), nil
}

var coreSchemaRef = regexp.MustCompile(`(?i)\bcore\s*\.`)

// validateReadOnlySQL ensures Conn only ever emits a single SELECT statement
// and never touches Logbook's core.* schema.
func validateReadOnlySQL(sql string) error {
	trimmed := strings.TrimSpace(sql)
	if trimmed == "" || !utf8.ValidString(trimmed) || strings.IndexByte(trimmed, 0) >= 0 {
		return &Error{Code: CodeParse, Message: "empty or malformed sql statement"}
	}
	if strings.ContainsRune(trimmed, ';') {
		return &Error{Code: CodeParse, Message: "multi-statement sql is forbidden"}
	}
	if len(trimmed) < 6 || !strings.EqualFold(trimmed[:6], "SELECT") {
		return &Error{Code: CodeParse, Message: "only SELECT queries are permitted"}
	}
	if len(trimmed) > 6 {
		next := trimmed[6]
		if next != ' ' && next != '\t' && next != '\n' && next != '\r' {
			return &Error{Code: CodeParse, Message: "only SELECT queries are permitted"}
		}
	}
	if coreSchemaRef.MatchString(trimmed) {
		return &Error{Code: CodeParse, SQLState: SQLStateInsufficientPrivilege, Message: "core schema access is forbidden"}
	}
	return nil
}

// Pool manages a bounded set of serialized, read-only PostgreSQL v3 connections.
type Pool struct {
	cfg Config

	sem    chan struct{}
	mu     sync.Mutex
	closed bool
	idle   []*wireConn
}

// NewPool creates a new bounded read-only connection pool.
func NewPool(cfg Config) (*Pool, error) {
	if cfg.Address == "" || cfg.User == "" || cfg.Database == "" {
		return nil, &Error{Code: CodeParse, Message: "incomplete database configuration"}
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = DefaultMaxConns
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = DefaultConnectTimeout
	}
	if cfg.QueryTimeout <= 0 {
		cfg.QueryTimeout = DefaultQueryTimeout
	}
	if cfg.MaxRows <= 0 {
		cfg.MaxRows = DefaultMaxRows
	}
	if cfg.MaxMsgBytes <= 0 {
		cfg.MaxMsgBytes = DefaultMaxMsgBytes
	}
	if cfg.MaxResultBytes <= 0 {
		cfg.MaxResultBytes = DefaultMaxResultBytes
	}
	if cfg.SSLMode == "" {
		cfg.SSLMode = SSLDisable
	}
	return &Pool{
		cfg: cfg,
		sem: make(chan struct{}, cfg.MaxConns),
	}, nil
}

// Close closes all idle connections and prevents new queries.
func (p *Pool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	conns := p.idle
	p.idle = nil
	p.mu.Unlock()

	for _, c := range conns {
		c.close()
	}
	return nil
}

// Query executes a single read-only SELECT query with serialized wire safety.
func (p *Pool) Query(ctx context.Context, sql string) (*Result, error) {
	if err := validateReadOnlySQL(sql); err != nil {
		return nil, err
	}

	if p.cfg.QueryTimeout > 0 {
		if _, hasDeadline := ctx.Deadline(); !hasDeadline {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, p.cfg.QueryTimeout)
			defer cancel()
		}
	}

	select {
	case p.sem <- struct{}{}:
		defer func() { <-p.sem }()
	case <-ctx.Done():
		return nil, &Error{Code: CodeTimeout, Message: "database connection pool busy or timed out"}
	}

	c, reused, err := p.acquire(ctx)
	if err != nil {
		return nil, err
	}

	res, reusable, qerr := c.simpleQuery(ctx, sql, p.cfg.MaxRows, p.cfg.MaxMsgBytes, p.cfg.MaxResultBytes)
	if qerr != nil && reused && !reusable && ctx.Err() == nil {
		// Idle connection may have been closed server-side; dial once cleanly.
		c.close()
		fresh, ferr := dialConn(ctx, p.cfg)
		if ferr != nil {
			return nil, ferr
		}
		res, reusable, qerr = fresh.simpleQuery(ctx, sql, p.cfg.MaxRows, p.cfg.MaxMsgBytes, p.cfg.MaxResultBytes)
		c = fresh
	}

	if reusable {
		p.release(c)
	} else {
		c.close()
	}
	return res, qerr
}

func (p *Pool) acquire(ctx context.Context) (*wireConn, bool, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, false, &Error{Code: CodeTimeout, Message: "database pool is closed"}
	}
	n := len(p.idle)
	if n > 0 {
		c := p.idle[n-1]
		p.idle = p.idle[:n-1]
		p.mu.Unlock()
		return c, true, nil
	}
	p.mu.Unlock()

	c, err := dialConn(ctx, p.cfg)
	if err != nil {
		return nil, false, err
	}
	return c, false, nil
}

func (p *Pool) release(c *wireConn) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		c.close()
		return
	}
	p.idle = append(p.idle, c)
	p.mu.Unlock()
}

type wireConn struct {
	nc net.Conn
	br *bufio.Reader
	bw *bufio.Writer
}

func (c *wireConn) close() {
	if c == nil || c.nc == nil {
		return
	}
	// Best-effort PostgreSQL Terminate message ('X', length 4).
	_ = c.nc.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
	_, _ = c.nc.Write([]byte{'X', 0, 0, 0, 4})
	_ = c.nc.Close()
}

func dialConn(ctx context.Context, cfg Config) (*wireConn, error) {
	dialCtx := ctx
	if cfg.ConnectTimeout > 0 {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, cfg.ConnectTimeout)
		defer cancel()
	}

	var d net.Dialer
	nc, err := d.DialContext(dialCtx, "tcp", cfg.Address)
	if err != nil {
		return nil, &Error{Code: CodeTimeout, Message: "unable to connect to database"}
	}

	stopWatch := watchContextDeadline(dialCtx, nc)
	defer stopWatch()

	if cfg.SSLMode != SSLDisable {
		upgraded, uerr := negotiateSSL(nc, cfg)
		if uerr != nil {
			_ = nc.Close()
			return nil, uerr
		}
		nc = upgraded
	}

	wc := &wireConn{
		nc: nc,
		br: bufio.NewReaderSize(nc, 16*1024),
		bw: bufio.NewWriterSize(nc, 4*1024),
	}
	if err := wc.startup(cfg); err != nil {
		_ = nc.Close()
		return nil, err
	}
	_ = nc.SetDeadline(time.Time{})
	return wc, nil
}

func negotiateSSL(nc net.Conn, cfg Config) (net.Conn, error) {
	var sslReq [8]byte
	binary.BigEndian.PutUint32(sslReq[0:4], 8)
	binary.BigEndian.PutUint32(sslReq[4:8], sslRequestCode)
	if _, err := nc.Write(sslReq[:]); err != nil {
		return nil, &Error{Code: CodeTimeout, Message: "database tls negotiation write failed"}
	}
	var resp [1]byte
	if _, err := io.ReadFull(nc, resp[:]); err != nil {
		return nil, &Error{Code: CodeTimeout, Message: "database tls negotiation read failed"}
	}
	switch resp[0] {
	case 'S':
		var tlsCfg *tls.Config
		if cfg.TLSConfig != nil {
			tlsCfg = cfg.TLSConfig.Clone()
		} else {
			tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		if cfg.SSLMode == SSLVerifyFull {
			tlsCfg.InsecureSkipVerify = false
			if tlsCfg.ServerName == "" {
				tlsCfg.ServerName = cfg.ServerName
			}
		} else if cfg.TLSConfig == nil {
			// PostgreSQL sslmode=require / prefer encrypts transport without CA verification
			// unless verify-full or a custom TLSConfig is supplied.
			tlsCfg.InsecureSkipVerify = true
		}
		tc := tls.Client(nc, tlsCfg)
		if err := tc.Handshake(); err != nil {
			return nil, &Error{Code: CodeTimeout, Message: "database tls handshake failed"}
		}
		return tc, nil
	case 'N':
		if cfg.SSLMode == SSLPrefer {
			return nc, nil
		}
		return nil, &Error{Code: CodeParse, Message: "database server refused required tls"}
	default:
		return nil, &Error{Code: CodeParse, Message: "unexpected database tls negotiation byte"}
	}
}

func (c *wireConn) startup(cfg Config) error {
	var payload bytes.Buffer
	var ver [4]byte
	binary.BigEndian.PutUint32(ver[:], protocolVersion30)
	payload.Write(ver[:])

	writeKV := func(k, v string) {
		payload.WriteString(k)
		payload.WriteByte(0)
		payload.WriteString(v)
		payload.WriteByte(0)
	}
	writeKV("user", cfg.User)
	writeKV("database", cfg.Database)
	writeKV("client_encoding", "UTF8")
	writeKV("application_name", "conn")
	writeKV("default_transaction_read_only", "on")
	payload.WriteByte(0)

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(4+payload.Len()))
	if _, err := c.bw.Write(lenBuf[:]); err != nil {
		return &Error{Code: CodeTimeout, Message: "failed writing database startup header"}
	}
	if _, err := c.bw.Write(payload.Bytes()); err != nil {
		return &Error{Code: CodeTimeout, Message: "failed writing database startup payload"}
	}
	if err := c.bw.Flush(); err != nil {
		return &Error{Code: CodeTimeout, Message: "failed flushing database startup message"}
	}

	var scram *scramClient
	authenticated := false

	for {
		typ, body, err := c.readFrame(cfg.MaxMsgBytes)
		if err != nil {
			return err
		}
		switch typ {
		case 'R':
			if len(body) < 4 {
				return &Error{Code: CodeParse, Message: "truncated authentication frame"}
			}
			authCode := binary.BigEndian.Uint32(body[:4])
			switch authCode {
			case authOK:
				authenticated = true
			case authCleartextPassword:
				if err := c.writePasswordMessage([]byte(cfg.Password), true); err != nil {
					return err
				}
			case authSASL:
				if !offersSCRAM256(body[4:]) {
					return &Error{Code: CodeParse, Message: "database did not offer SCRAM-SHA-256"}
				}
				var serr error
				scram, serr = newSCRAMClient(cfg.Password, "")
				if serr != nil {
					return &Error{Code: CodeParse, Message: "failed initializing SCRAM exchange"}
				}
				first := scram.clientFirst()
				var saslInit bytes.Buffer
				saslInit.WriteString(scramMechanism)
				saslInit.WriteByte(0)
				var firstLen [4]byte
				binary.BigEndian.PutUint32(firstLen[:], uint32(len(first)))
				saslInit.Write(firstLen[:])
				saslInit.Write(first)
				if err := c.writeFrame('p', saslInit.Bytes()); err != nil {
					return err
				}
			case authSASLContinue:
				if scram == nil {
					return &Error{Code: CodeParse, Message: "unexpected SASL continue frame"}
				}
				finalMsg, serr := scram.stepContinue(body[4:])
				if serr != nil {
					return &Error{Code: CodeParse, Message: "SCRAM authentication challenge invalid"}
				}
				if err := c.writeFrame('p', finalMsg); err != nil {
					return err
				}
			case authSASLFinal:
				if scram == nil {
					return &Error{Code: CodeParse, Message: "unexpected SASL final frame"}
				}
				if serr := scram.stepFinal(body[4:]); serr != nil {
					return &Error{Code: CodeParse, Message: "SCRAM server verification failed"}
				}
			default:
				return &Error{Code: CodeParse, Message: "unsupported database authentication method"}
			}
		case 'S', 'K', 'N':
			// ParameterStatus, BackendKeyData, NoticeResponse: safe to ignore.
		case 'Z':
			if !authenticated || len(body) != 1 || body[0] != 'I' {
				return &Error{Code: CodeParse, Message: "unexpected database ready state during startup"}
			}
			return nil
		case 'E':
			return parseErrorResponse(body)
		default:
			return &Error{Code: CodeParse, Message: "unexpected frame during database startup"}
		}
	}
}

func (c *wireConn) simpleQuery(ctx context.Context, sql string, maxRows, maxMsgBytes, maxResultBytes int) (*Result, bool, error) {
	stopWatch := watchContextDeadline(ctx, c.nc)
	defer func() {
		stopWatch()
		_ = c.nc.SetDeadline(time.Time{})
	}()

	qBytes := make([]byte, len(sql)+1)
	copy(qBytes, sql)
	qBytes[len(sql)] = 0
	if err := c.writeFrame('Q', qBytes); err != nil {
		return nil, false, err
	}

	res := &Result{}
	var queryErr *Error
	totalBytes := 0

	for {
		typ, body, err := c.readFrame(maxMsgBytes)
		if err != nil {
			if ctx.Err() != nil {
				return nil, false, &Error{Code: CodeTimeout, Message: "database query timed out"}
			}
			return nil, false, err
		}
		totalBytes += len(body)
		if totalBytes > maxResultBytes {
			return nil, false, &Error{Code: CodeParse, Message: "database query result exceeded byte limit"}
		}

		switch typ {
		case 'T':
			cols, perr := parseRowDescription(body)
			if perr != nil {
				return nil, false, perr
			}
			res.Columns = cols
		case 'D':
			if len(res.Rows) >= maxRows {
				return nil, false, &Error{Code: CodeParse, Message: "database query result exceeded row limit"}
			}
			row, perr := parseDataRow(body, len(res.Columns))
			if perr != nil {
				return nil, false, perr
			}
			res.Rows = append(res.Rows, row)
		case 'C', 'I', 'N', 'S':
			// CommandComplete, EmptyQueryResponse, NoticeResponse, ParameterStatus.
		case 'E':
			queryErr = parseErrorResponse(body)
		case 'Z':
			reusable := len(body) == 1 && body[0] == 'I'
			if queryErr != nil {
				return nil, reusable, queryErr
			}
			return res, reusable, nil
		default:
			return nil, false, &Error{Code: CodeParse, Message: "unexpected database wire frame"}
		}
	}
}

func (c *wireConn) writePasswordMessage(pw []byte, nullTerminate bool) error {
	payload := pw
	if nullTerminate {
		payload = make([]byte, len(pw)+1)
		copy(payload, pw)
	}
	return c.writeFrame('p', payload)
}

func (c *wireConn) writeFrame(typ byte, payload []byte) error {
	if err := c.bw.WriteByte(typ); err != nil {
		return &Error{Code: CodeTimeout, Message: "database write failed"}
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(4+len(payload)))
	if _, err := c.bw.Write(lenBuf[:]); err != nil {
		return &Error{Code: CodeTimeout, Message: "database write failed"}
	}
	if _, err := c.bw.Write(payload); err != nil {
		return &Error{Code: CodeTimeout, Message: "database write failed"}
	}
	if err := c.bw.Flush(); err != nil {
		return &Error{Code: CodeTimeout, Message: "database flush failed"}
	}
	return nil
}

func (c *wireConn) readFrame(maxBytes int) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
		return 0, nil, &Error{Code: CodeTimeout, Message: "database connection closed or timed out"}
	}
	typ := hdr[0]
	frameLen := int(int32(binary.BigEndian.Uint32(hdr[1:5])))
	if frameLen < 4 || frameLen-4 > maxBytes {
		return 0, nil, &Error{Code: CodeParse, Message: "database frame size out of bounds"}
	}
	payload := make([]byte, frameLen-4)
	if _, err := io.ReadFull(c.br, payload); err != nil {
		return 0, nil, &Error{Code: CodeTimeout, Message: "database frame read interrupted"}
	}
	return typ, payload, nil
}

func offersSCRAM256(buf []byte) bool {
	for len(buf) > 0 {
		idx := bytes.IndexByte(buf, 0)
		if idx <= 0 {
			break
		}
		if string(buf[:idx]) == scramMechanism {
			return true
		}
		buf = buf[idx+1:]
	}
	return false
}

func parseRowDescription(body []byte) ([]string, error) {
	if len(body) < 2 {
		return nil, &Error{Code: CodeParse, Message: "truncated RowDescription"}
	}
	count := int(int16(binary.BigEndian.Uint16(body[:2])))
	if count < 0 || count > 256 {
		return nil, &Error{Code: CodeParse, Message: "invalid column count in RowDescription"}
	}
	cols := make([]string, 0, count)
	pos := 2
	for i := 0; i < count; i++ {
		nul := bytes.IndexByte(body[pos:], 0)
		if nul < 0 {
			return nil, &Error{Code: CodeParse, Message: "unterminated column name in RowDescription"}
		}
		name := string(body[pos : pos+nul])
		pos += nul + 1
		if pos+18 > len(body) {
			return nil, &Error{Code: CodeParse, Message: "truncated column metadata in RowDescription"}
		}
		fmtCode := binary.BigEndian.Uint16(body[pos+16 : pos+18])
		if fmtCode != 0 {
			return nil, &Error{Code: CodeParse, Message: "unexpected binary column format in Simple Query"}
		}
		pos += 18
		cols = append(cols, name)
	}
	return cols, nil
}

func parseDataRow(body []byte, expectedCols int) ([]Value, error) {
	if len(body) < 2 {
		return nil, &Error{Code: CodeParse, Message: "truncated DataRow"}
	}
	count := int(int16(binary.BigEndian.Uint16(body[:2])))
	if count < 0 || (expectedCols > 0 && count != expectedCols) {
		return nil, &Error{Code: CodeParse, Message: "column count mismatch in DataRow"}
	}
	vals := make([]Value, count)
	pos := 2
	for i := 0; i < count; i++ {
		if pos+4 > len(body) {
			return nil, &Error{Code: CodeParse, Message: "truncated value length in DataRow"}
		}
		vLen := int(int32(binary.BigEndian.Uint32(body[pos : pos+4])))
		pos += 4
		if vLen == -1 {
			vals[i] = Value{Null: true}
			continue
		}
		if vLen < 0 || pos+vLen > len(body) {
			return nil, &Error{Code: CodeParse, Message: "invalid value length in DataRow"}
		}
		vals[i] = Value{Null: false, Text: string(body[pos : pos+vLen])}
		pos += vLen
	}
	return vals, nil
}

// parseErrorResponse extracts ONLY the 5-character SQLSTATE ('C' field) and
// maps it to fixed sanitized text, discarding server detail/host/user messages.
func parseErrorResponse(body []byte) *Error {
	sqlState := ""
	pos := 0
	for pos < len(body) {
		fieldType := body[pos]
		pos++
		if fieldType == 0 {
			break
		}
		nul := bytes.IndexByte(body[pos:], 0)
		if nul < 0 {
			break
		}
		val := string(body[pos : pos+nul])
		pos += nul + 1
		if fieldType == 'C' && len(val) == 5 && isAlphaNumASCII(val) {
			sqlState = val
		}
	}

	switch {
	case sqlState == SQLStateInsufficientPrivilege:
		return &Error{
			Code:     CodeParse,
			SQLState: sqlState,
			Message:  "insufficient database privilege on requested relation",
		}
	case sqlState == SQLStateUndefinedTable:
		return &Error{
			Code:     CodeNeedsSubtool,
			SQLState: sqlState,
			Message:  "requested public view is not defined",
		}
	case strings.HasPrefix(sqlState, "28"):
		return &Error{
			Code:     CodeParse,
			SQLState: sqlState,
			Message:  "database authentication rejected",
		}
	case strings.HasPrefix(sqlState, "53") || strings.HasPrefix(sqlState, "57") || sqlState == "57014":
		return &Error{
			Code:     CodeTimeout,
			SQLState: sqlState,
			Message:  "database unavailable or statement canceled",
		}
	default:
		return &Error{
			Code:     CodeParse,
			SQLState: sqlState,
			Message:  "database refused query",
		}
	}
}

func isAlphaNumASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
			return false
		}
	}
	return true
}

func watchContextDeadline(ctx context.Context, nc net.Conn) func() {
	if deadline, ok := ctx.Deadline(); ok {
		_ = nc.SetDeadline(deadline)
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = nc.SetDeadline(time.Unix(1, 0))
		case <-done:
		}
	}()
	return func() {
		close(done)
	}
}
