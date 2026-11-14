package pgwire

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type mockAuthMode int

const (
	mockAuthSCRAM mockAuthMode = iota
	mockAuthCleartext
	mockAuthTrust
)

type mockPGServer struct {
	t         *testing.T
	ln        net.Listener
	authMode  mockAuthMode
	user      string
	password  string
	tlsConfig *tls.Config
	handler   func(sql string) (*Result, string, string) // res, sqlState, sensitiveServerMsg
	wg        sync.WaitGroup
}

func startMockPGServer(t *testing.T, mode mockAuthMode, user, password string, tlsCfg *tls.Config, handler func(string) (*Result, string, string)) *mockPGServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &mockPGServer{
		t:         t,
		ln:        ln,
		authMode:  mode,
		user:      user,
		password:  password,
		tlsConfig: tlsCfg,
		handler:   handler,
	}
	s.wg.Add(1)
	go s.acceptLoop()
	t.Cleanup(func() {
		_ = ln.Close()
		s.wg.Wait()
	})
	return s
}

func (s *mockPGServer) Addr() string { return s.ln.Addr().String() }

func (s *mockPGServer) acceptLoop() {
	defer s.wg.Done()
	for {
		nc, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			defer c.Close()
			s.serveConn(c)
		}(nc)
	}
}

func (s *mockPGServer) serveConn(nc net.Conn) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(nc, lenBuf[:]); err != nil {
		return
	}
	firstLen := int(binary.BigEndian.Uint32(lenBuf[:]))
	payload := make([]byte, firstLen-4)
	if _, err := io.ReadFull(nc, payload); err != nil {
		return
	}

	// Check for SSLRequest (length 8, code 80877103).
	if firstLen == 8 && binary.BigEndian.Uint32(payload) == sslRequestCode {
		if s.tlsConfig != nil {
			_, _ = nc.Write([]byte{'S'})
			tc := tls.Server(nc, s.tlsConfig)
			if err := tc.Handshake(); err != nil {
				return
			}
			nc = tc
		} else {
			_, _ = nc.Write([]byte{'N'})
		}
		if _, err := io.ReadFull(nc, lenBuf[:]); err != nil {
			return
		}
		firstLen = int(binary.BigEndian.Uint32(lenBuf[:]))
		payload = make([]byte, firstLen-4)
		if _, err := io.ReadFull(nc, payload); err != nil {
			return
		}
	}

	if len(payload) < 4 || binary.BigEndian.Uint32(payload[:4]) != protocolVersion30 {
		writeBackendError(nc, "08P01", "invalid protocol version on host secret-db.internal")
		return
	}
	params := parseStartupParams(payload[4:])
	if params["default_transaction_read_only"] != "on" {
		writeBackendError(nc, "25006", "read-only parameter missing")
		return
	}

	br := bufio.NewReader(nc)
	switch s.authMode {
	case mockAuthTrust:
		if params["user"] != s.user {
			writeBackendError(nc, "28P01", "password authentication failed for user "+params["user"]+" with secret "+s.password)
			return
		}
		writeAuthOKAndReady(nc)

	case mockAuthCleartext:
		var req [4]byte
		binary.BigEndian.PutUint32(req[:], authCleartextPassword)
		writeBackendFrame(nc, 'R', req[:])
		typ, pwBody, err := readFrontendFrame(br)
		if err != nil || typ != 'p' {
			return
		}
		gotPW := strings.TrimSuffix(string(pwBody), "\x00")
		if params["user"] != s.user || gotPW != s.password {
			writeBackendError(nc, "28P01", "password authentication failed for "+params["user"]+": tried "+gotPW+" at 10.42.0.99")
			return
		}
		writeAuthOKAndReady(nc)

	case mockAuthSCRAM:
		if !s.performServerSCRAM(nc, br, params["user"]) {
			return
		}
		writeAuthOKAndReady(nc)
	}

	// Query loop.
	for {
		typ, body, err := readFrontendFrame(br)
		if err != nil {
			return
		}
		if typ == 'X' {
			return
		}
		if typ != 'Q' {
			writeBackendError(nc, "08P01", "unsupported frontend message")
			return
		}
		sql := strings.TrimSuffix(string(body), "\x00")

		// Emit a harmless NoticeResponse before answering to exercise 'N' handling.
		writeBackendNotice(nc, "00000", "synthetic notice from logbook")

		res, sqlState, secretMsg := s.handler(sql)
		if sqlState != "" {
			writeBackendError(nc, sqlState, secretMsg)
			writeBackendFrame(nc, 'Z', []byte{'I'})
			continue
		}
		writeRowDescription(nc, res.Columns)
		for _, row := range res.Rows {
			writeDataRow(nc, row)
		}
		cmdTag := fmt.Sprintf("SELECT %d\x00", len(res.Rows))
		writeBackendFrame(nc, 'C', []byte(cmdTag))
		writeBackendFrame(nc, 'Z', []byte{'I'})
	}
}

func (s *mockPGServer) performServerSCRAM(nc net.Conn, br *bufio.Reader, gotUser string) bool {
	var mech bytes.Buffer
	var code [4]byte
	binary.BigEndian.PutUint32(code[:], authSASL)
	mech.Write(code[:])
	mech.WriteString("SCRAM-SHA-256\x00\x00")
	writeBackendFrame(nc, 'R', mech.Bytes())

	typ, initBody, err := readFrontendFrame(br)
	if err != nil || typ != 'p' {
		return false
	}
	nul := bytes.IndexByte(initBody, 0)
	if nul < 0 || string(initBody[:nul]) != "SCRAM-SHA-256" || len(initBody) < nul+5 {
		writeBackendError(nc, "08P01", "bad SASLInitialResponse")
		return false
	}
	cfLen := int(binary.BigEndian.Uint32(initBody[nul+1 : nul+5]))
	clientFirst := string(initBody[nul+5 : nul+5+cfLen])
	if !strings.HasPrefix(clientFirst, "n,,") {
		writeBackendError(nc, "08P01", "missing gs2 header")
		return false
	}
	clientFirstBare := clientFirst[3:]
	clientNonce := ""
	for _, part := range strings.Split(clientFirstBare, ",") {
		if strings.HasPrefix(part, "r=") {
			clientNonce = part[2:]
		}
	}

	salt := []byte("synthetic-scram-salt")
	iters := 4096
	combinedNonce := clientNonce + "srvNonce987654"
	serverFirst := fmt.Sprintf("r=%s,s=%s,i=%d", combinedNonce, base64.StdEncoding.EncodeToString(salt), iters)

	var cont bytes.Buffer
	binary.BigEndian.PutUint32(code[:], authSASLContinue)
	cont.Write(code[:])
	cont.WriteString(serverFirst)
	writeBackendFrame(nc, 'R', cont.Bytes())

	typ, finalBody, err := readFrontendFrame(br)
	if err != nil || typ != 'p' {
		return false
	}
	clientFinal := string(finalBody)
	idxP := strings.LastIndex(clientFinal, ",p=")
	if idxP < 0 {
		writeBackendError(nc, "28P01", "missing client proof")
		return false
	}
	clientFinalWithoutProof := clientFinal[:idxP]
	gotProof, err := base64.StdEncoding.DecodeString(clientFinal[idxP+3:])
	if err != nil {
		writeBackendError(nc, "28P01", "malformed proof")
		return false
	}

	saltedPW := pbkdf2SHA256([]byte(s.password), salt, iters)
	clientKey := hmacSHA256(saltedPW, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)
	authMessage := clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof
	expectedSig := hmacSHA256(storedKey[:], []byte(authMessage))

	recoveredClientKey := make([]byte, len(gotProof))
	for i := range gotProof {
		recoveredClientKey[i] = gotProof[i] ^ expectedSig[i]
	}
	gotStored := sha256.Sum256(recoveredClientKey)
	if gotUser != s.user || !hmac.Equal(gotStored[:], storedKey[:]) {
		writeBackendError(nc, "28P01", "SCRAM failed for user "+gotUser+" on db logbook.internal password="+s.password)
		return false
	}

	serverKey := hmacSHA256(saltedPW, []byte("Server Key"))
	serverSig := hmacSHA256(serverKey, []byte(authMessage))

	var fin bytes.Buffer
	binary.BigEndian.PutUint32(code[:], authSASLFinal)
	fin.Write(code[:])
	fin.WriteString("v=" + base64.StdEncoding.EncodeToString(serverSig))
	writeBackendFrame(nc, 'R', fin.Bytes())
	return true
}

func parseStartupParams(b []byte) map[string]string {
	out := map[string]string{}
	for len(b) > 1 {
		kEnd := bytes.IndexByte(b, 0)
		if kEnd <= 0 {
			break
		}
		k := string(b[:kEnd])
		b = b[kEnd+1:]
		vEnd := bytes.IndexByte(b, 0)
		if vEnd < 0 {
			break
		}
		v := string(b[:vEnd])
		b = b[vEnd+1:]
		out[k] = v
	}
	return out
}

func readFrontendFrame(r *bufio.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint32(hdr[1:5])) - 4
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	return hdr[0], body, nil
}

func writeBackendFrame(w io.Writer, typ byte, payload []byte) {
	var hdr [5]byte
	hdr[0] = typ
	binary.BigEndian.PutUint32(hdr[1:5], uint32(4+len(payload)))
	_, _ = w.Write(hdr[:])
	_, _ = w.Write(payload)
}

func writeAuthOKAndReady(w io.Writer) {
	var ok [4]byte
	binary.BigEndian.PutUint32(ok[:], authOK)
	writeBackendFrame(w, 'R', ok[:])
	writeBackendFrame(w, 'S', []byte("server_version\x0017.4\x00"))
	var keyData [8]byte
	binary.BigEndian.PutUint32(keyData[0:4], 101)
	binary.BigEndian.PutUint32(keyData[4:8], 202)
	writeBackendFrame(w, 'K', keyData[:])
	writeBackendFrame(w, 'Z', []byte{'I'})
}

func writeBackendError(w io.Writer, sqlState, msg string) {
	var b bytes.Buffer
	b.WriteByte('S')
	b.WriteString("ERROR\x00")
	b.WriteByte('C')
	b.WriteString(sqlState + "\x00")
	b.WriteByte('M')
	b.WriteString(msg + "\x00")
	b.WriteByte(0)
	writeBackendFrame(w, 'E', b.Bytes())
}

func writeBackendNotice(w io.Writer, sqlState, msg string) {
	var b bytes.Buffer
	b.WriteByte('S')
	b.WriteString("NOTICE\x00")
	b.WriteByte('C')
	b.WriteString(sqlState + "\x00")
	b.WriteByte('M')
	b.WriteString(msg + "\x00")
	b.WriteByte(0)
	writeBackendFrame(w, 'N', b.Bytes())
}

func writeRowDescription(w io.Writer, cols []string) {
	var b bytes.Buffer
	var cnt [2]byte
	binary.BigEndian.PutUint16(cnt[:], uint16(len(cols)))
	b.Write(cnt[:])
	for _, col := range cols {
		b.WriteString(col)
		b.WriteByte(0)
		var meta [18]byte // formatCode 0 = text
		b.Write(meta[:])
	}
	writeBackendFrame(w, 'T', b.Bytes())
}

func writeDataRow(w io.Writer, vals []Value) {
	var b bytes.Buffer
	var cnt [2]byte
	binary.BigEndian.PutUint16(cnt[:], uint16(len(vals)))
	b.Write(cnt[:])
	for _, v := range vals {
		var l [4]byte
		if v.Null {
			binary.BigEndian.PutUint32(l[:], ^uint32(0)) // -1
			b.Write(l[:])
			continue
		}
		binary.BigEndian.PutUint32(l[:], uint32(len(v.Text)))
		b.Write(l[:])
		b.WriteString(v.Text)
	}
	writeBackendFrame(w, 'D', b.Bytes())
}

func selfSignedTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
}

func TestSCRAMAndTLSHandshakeMultiRowNullJSONAndConcurrentPool(t *testing.T) {
	srv := startMockPGServer(t, mockAuthSCRAM, "pub_ro", "made-up-scram-pass-99", selfSignedTLSConfig(t), func(sql string) (*Result, string, string) {
		return &Result{
			Columns: []string{"item_id", "title", "note", "provenance"},
			Rows: [][]Value{
				{
					{Text: "PA-0001"},
					{Text: "Sample Clause Matrix"},
					{Null: true},
					{Text: `{"citations":["FAR 52.204-21"],"clean_room":true}`},
				},
				{
					{Text: "PA-0002"},
					{Text: "Sample Rate Calculator"},
					{Text: "approved by owner"},
					{Text: `{"citations":["DFARS 252.204-7012"],"clean_room":true}`},
				},
			},
		}, "", ""
	})

	dsn := fmt.Sprintf("postgres://pub_ro@%s/logbook?sslmode=require&connect_timeout=5", srv.Addr())
	cfg, err := ParseConfig(dsn, "made-up-scram-pass-99")
	if err != nil {
		t.Fatalf("ParseConfig failed: %v", err)
	}
	pool, err := NewPool(cfg)
	if err != nil {
		t.Fatalf("NewPool failed: %v", err)
	}
	defer pool.Close()

	res, err := pool.Query(context.Background(), "SELECT item_id, title, note, provenance FROM pub.catalog_entry")
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if len(res.Columns) != 4 || len(res.Rows) != 2 {
		t.Fatalf("unexpected shape cols=%d rows=%d", len(res.Columns), len(res.Rows))
	}
	if !res.Rows[0][2].Null || res.Rows[1][2].Text != "approved by owner" {
		t.Fatalf("unexpected NULL/text decoding: %+v", res.Rows)
	}
	if !strings.Contains(res.Rows[0][3].Text, "FAR 52.204-21") {
		t.Fatalf("unexpected JSON column text: %q", res.Rows[0][3].Text)
	}

	// Exercise concurrent pooled queries under -race.
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, qerr := pool.Query(context.Background(), "SELECT item_id, title, note, provenance FROM pub.catalog_entry")
			if qerr != nil {
				t.Errorf("concurrent query failed: %v", qerr)
				return
			}
			if len(r.Rows) != 2 {
				t.Errorf("concurrent rows = %d, want 2", len(r.Rows))
			}
		}()
	}
	wg.Wait()
}

func TestCleartextTrustAndAuthFailureSanitization(t *testing.T) {
	secretPW := "synthetic-ultra-sensitive-pw"
	srv := startMockPGServer(t, mockAuthSCRAM, "pub_ro", secretPW, nil, func(sql string) (*Result, string, string) {
		return &Result{Columns: []string{"ok"}, Rows: [][]Value{{{Text: "1"}}}}, "", ""
	})

	cfg, err := ParseConfig("postgres://pub_ro@"+srv.Addr()+"/logbook?sslmode=disable", "wrong-password-attempt")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := NewPool(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	_, qerr := pool.Query(context.Background(), "SELECT 1 FROM pub.item")
	if qerr == nil {
		t.Fatal("expected authentication failure")
	}
	errMsg := qerr.Error()
	for _, forbidden := range []string{
		secretPW,
		"wrong-password-attempt",
		srv.Addr(),
		"127.0.0.1",
		"logbook.internal",
		"pub_ro",
	} {
		if strings.Contains(errMsg, forbidden) {
			t.Fatalf("sanitized error leaked sensitive token %q: %s", forbidden, errMsg)
		}
	}
	if PublicCode(qerr) != CodeParse {
		t.Fatalf("PublicCode = %q, want %q", PublicCode(qerr), CodeParse)
	}

	// Verify cleartext password mode also succeeds cleanly.
	clearSrv := startMockPGServer(t, mockAuthCleartext, "pub_ro", "made-up-clear-pw", nil, func(sql string) (*Result, string, string) {
		return &Result{Columns: []string{"n"}, Rows: [][]Value{{{Text: "42"}}}}, "", ""
	})
	clearCfg, err := ParseConfig("postgres://pub_ro@"+clearSrv.Addr()+"/logbook?sslmode=disable", "made-up-clear-pw")
	if err != nil {
		t.Fatal(err)
	}
	clearPool, err := NewPool(clearCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer clearPool.Close()
	r, err := clearPool.Query(context.Background(), "SELECT n FROM pub.queue_depth")
	if err != nil || len(r.Rows) != 1 || r.Rows[0][0].Text != "42" {
		t.Fatalf("cleartext query failed: %v %+v", err, r)
	}
}

func TestInsufficientPrivilegeAndMissingViewGracefulRecovery(t *testing.T) {
	srv := startMockPGServer(t, mockAuthTrust, "pub_ro", "", nil, func(sql string) (*Result, string, string) {
		switch {
		case strings.Contains(sql, "pub.catalog_entry"):
			return nil, "42P01", "relation \"pub.catalog_entry\" does not exist on node pg-node-01"
		case strings.Contains(sql, "pub.forbidden_view"):
			return nil, "42501", "permission denied for view forbidden_view for role pub_ro"
		default:
			return &Result{Columns: []string{"item_id"}, Rows: [][]Value{{{Text: "PA-0001"}}}}, "", ""
		}
	})

	cfg, err := ParseConfig("postgres://pub_ro@"+srv.Addr()+"/logbook?sslmode=disable", "")
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 1 // Prove the single pooled connection stays reusable after 42P01 and 42501!
	pool, err := NewPool(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	// 1. Missing view (42P01).
	_, err = pool.Query(context.Background(), "SELECT item_id FROM pub.catalog_entry")
	if !IsUndefinedTable(err) {
		t.Fatalf("expected IsUndefinedTable(err)=true, got %v", err)
	}
	if strings.Contains(err.Error(), "pg-node-01") {
		t.Fatalf("error leaked node hostname: %v", err)
	}

	// 2. Insufficient privilege (42501) on same pooled connection.
	_, err = pool.Query(context.Background(), "SELECT item_id FROM pub.forbidden_view")
	if !IsInsufficientPrivilege(err) {
		t.Fatalf("expected IsInsufficientPrivilege(err)=true, got %v", err)
	}

	// 3. Subsequent valid query reuses the healthy connection cleanly.
	res, err := pool.Query(context.Background(), "SELECT item_id FROM pub.item")
	if err != nil || len(res.Rows) != 1 || res.Rows[0][0].Text != "PA-0001" {
		t.Fatalf("expected pooled connection recovery, got err=%v res=%+v", err, res)
	}
}

func TestReadOnlyGuardAndRowCap(t *testing.T) {
	srv := startMockPGServer(t, mockAuthTrust, "pub_ro", "", nil, func(sql string) (*Result, string, string) {
		rows := make([][]Value, 10)
		for i := range rows {
			rows[i] = []Value{{Text: fmt.Sprintf("PA-%04d", i+1)}}
		}
		return &Result{Columns: []string{"item_id"}, Rows: rows}, "", ""
	})
	cfg, err := ParseConfig("postgres://pub_ro@"+srv.Addr()+"/logbook?sslmode=disable", "")
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxRows = 5
	pool, err := NewPool(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	// Client-side SQL guard checks.
	for _, badSQL := range []string{
		"DELETE FROM pub.item",
		"SELECT item_id FROM core.item",
		"SELECT 1 FROM pub.item; SELECT 2 FROM pub.item",
		"",
	} {
		if _, err := pool.Query(context.Background(), badSQL); err == nil {
			t.Errorf("expected client-side guard to reject %q", badSQL)
		}
	}

	// Row cap check.
	if _, err := pool.Query(context.Background(), "SELECT item_id FROM pub.item"); err == nil {
		t.Fatal("expected MaxRows=5 cap to refuse 10-row response")
	} else {
		var pe *Error
		if !errors.As(err, &pe) || pe.Code != CodeParse {
			t.Fatalf("expected E_PARSE on row cap, got %v", err)
		}
	}

	// QuoteLiteral safety.
	lit, err := QuoteLiteral("sample'slug")
	if err != nil || lit != "'sample''slug'" {
		t.Fatalf("QuoteLiteral = %q, %v", lit, err)
	}
	if _, err := QuoteLiteral("bad\x00byte"); err == nil {
		t.Fatal("expected QuoteLiteral to reject NUL byte")
	}
}
