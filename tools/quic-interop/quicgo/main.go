// quicgo-peer: a minimal quic-go client and server speaking the same
// echo protocol as `purecrypto q_client` / `q_server`, for the QUIC interop
// matrix in tools/quic-interop/run.sh.
//
// Application protocol (ALPN chosen by the caller, `pc-echo` in the matrix):
//
//   - Every client-initiated bidirectional stream is echoed: the server
//     writes back what it reads and FINs its side once the client has.
//   - Every client-initiated unidirectional stream is read to its FIN, then
//     answered on a fresh server-initiated unidirectional stream carrying the
//     same bytes.
//   - Every DATAGRAM frame (RFC 9221) is echoed as a DATAGRAM.
//
// The server logs one line per connection with the negotiated parameters
// (ALPN, TLS cipher suite, key-exchange group, QUIC version, whether 0-RTT
// was used, whether the address was verified by a Retry), one line per
// stream with the byte count and SHA-256 of what it echoed, and the close
// reason. The client logs the same for its side, writes the echoed bytes to
// stdout, and can repeat the exchange, migrate between repeats, resume with
// and without 0-RTT, close with an application error code, or sit idle
// until the peer's idle timeout fires. With QLOGDIR set, quic-go writes a
// qlog trace per connection, which the matrix greps for the events it
// cannot observe from the application (Retry, key update, version
// negotiation, ECN validation, stateless reset).
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("quicgo-peer: ")
	if len(os.Args) < 2 {
		log.Fatal("usage: quicgo-peer server|client [flags]")
	}
	switch os.Args[1] {
	case "server":
		runServer(os.Args[2:])
	case "client":
		runClient(os.Args[2:])
	default:
		log.Fatalf("unknown mode %q (want server|client)", os.Args[1])
	}
}

// ---------------------------------------------------------------- shared

func describe(cs quic.ConnectionState) string {
	return fmt.Sprintf("alpn=%s suite=%s curve=%s version=%x used0rtt=%v resumed=%v",
		cs.TLS.NegotiatedProtocol, tls.CipherSuiteName(cs.TLS.CipherSuite),
		curveName(cs.TLS.CurveID), uint32(cs.Version), cs.Used0RTT, cs.TLS.DidResume)
}

func curveName(id tls.CurveID) string {
	if id == 0 {
		return "none"
	}
	return id.String()
}

// parseCurves turns a comma-separated list of TLS group names (as
// crypto/tls prints them) into CurvePreferences; "" keeps Go's default.
// Note that crypto/tls ignores the order of the list and applies its own
// (post-quantum groups first, then the client's shares), so a list of one
// is how a group is pinned.
func parseCurves(s string) []tls.CurveID {
	if s == "" {
		return nil
	}
	names := map[string]tls.CurveID{
		"X25519":             tls.X25519,
		"P-256":              tls.CurveP256,
		"P-384":              tls.CurveP384,
		"P-521":              tls.CurveP521,
		"X25519MLKEM768":     tls.X25519MLKEM768,
		"SecP256r1MLKEM768":  tls.SecP256r1MLKEM768,
		"SecP384r1MLKEM1024": tls.SecP384r1MLKEM1024,
	}
	var out []tls.CurveID
	for _, n := range strings.Split(s, ",") {
		id, ok := names[strings.TrimSpace(n)]
		if !ok {
			log.Fatalf("unknown TLS group %q", n)
		}
		out = append(out, id)
	}
	return out
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func parseVersions(s string) []quic.Version {
	if s == "" {
		return nil
	}
	var out []quic.Version
	for _, v := range strings.Split(s, ",") {
		switch strings.TrimSpace(v) {
		case "v1", "1":
			out = append(out, quic.Version1)
		case "v2", "2":
			out = append(out, quic.Version2)
		default:
			log.Fatalf("unknown QUIC version %q (want v1|v2)", v)
		}
	}
	return out
}

func parseKey32(hexKey string) *[32]byte {
	if hexKey == "" {
		return nil
	}
	raw, err := hex.DecodeString(hexKey)
	if err != nil || len(raw) != 32 {
		log.Fatalf("key must be 32 bytes of hex, got %q", hexKey)
	}
	var k [32]byte
	copy(k[:], raw)
	return &k
}

// closeReason renders a connection error the way the matrix greps for it.
func closeReason(err error) string {
	var appErr *quic.ApplicationError
	var transErr *quic.TransportError
	var idle *quic.IdleTimeoutError
	var reset *quic.StatelessResetError
	var vn *quic.VersionNegotiationError
	switch {
	case err == nil:
		return "closed: no error"
	case errors.As(err, &appErr):
		who := "local"
		if appErr.Remote {
			who = "remote"
		}
		return fmt.Sprintf("closed: application error %#x (%s) by %s", uint64(appErr.ErrorCode), appErr.ErrorMessage, who)
	case errors.As(err, &transErr):
		who := "local"
		if transErr.Remote {
			who = "remote"
		}
		return fmt.Sprintf("closed: transport error %#x (%s) by %s", uint64(transErr.ErrorCode), transErr.ErrorMessage, who)
	case errors.As(err, &idle):
		return "closed: idle timeout"
	case errors.As(err, &reset):
		return "closed: stateless reset"
	case errors.As(err, &vn):
		return "closed: version negotiation failed"
	default:
		return "closed: " + err.Error()
	}
}

// echoBidi copies a bidirectional stream back onto itself until the peer's
// FIN, then FINs. Returns the bytes seen.
func echoBidi(s *quic.Stream) ([]byte, error) {
	var seen []byte
	buf := make([]byte, 64*1024)
	for {
		n, err := s.Read(buf)
		if n > 0 {
			seen = append(seen, buf[:n]...)
			if _, werr := s.Write(buf[:n]); werr != nil {
				return seen, werr
			}
		}
		if err == io.EOF {
			return seen, s.Close()
		}
		if err != nil {
			return seen, err
		}
	}
}

// ---------------------------------------------------------------- server

// addrVerifiedKey carries ClientInfo.AddrVerified into the connection
// context.
type addrVerifiedKey struct{}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:0", "UDP address to listen on")
	certFile := fs.String("cert", "", "server certificate (PEM)")
	keyFile := fs.String("key", "", "server key (PEM)")
	alpn := fs.String("alpn", "pc-echo", "ALPN protocol to offer")
	retry := fs.Bool("retry", false, "validate every new client address with a Retry")
	allow0RTT := fs.Bool("0rtt", false, "accept 0-RTT")
	idle := fs.Duration("idle", 30*time.Second, "max_idle_timeout")
	naccept := fs.Int("naccept", 1, "exit after this many connections have closed (0 = never)")
	resetKey := fs.String("reset-key", "", "32-byte hex stateless-reset key (defaults to random)")
	deadline := fs.Duration("timeout", 60*time.Second, "exit after this long regardless")
	loss := fs.Int("loss", 0, "drop one in N datagrams in each direction (0 = none)")
	curves := fs.String("curves", "", "TLS groups to accept, comma-separated (default: Go's)")
	versions := fs.String("versions", "", "QUIC versions to accept, in order (v1,v2); default both")
	fs.Parse(args)

	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("cannot load identity: %v", err)
	}
	tlsConf := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		NextProtos:       []string{*alpn},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: parseCurves(*curves),
	}
	conf := &quic.Config{
		MaxIdleTimeout:  *idle,
		Allow0RTT:       *allow0RTT,
		EnableDatagrams: true,
		Versions:        parseVersions(*versions),
		Tracer:          qlog.DefaultConnectionTracer,
	}

	udp, err := net.ListenUDP("udp", mustUDPAddr(*addr))
	if err != nil {
		log.Fatalf("cannot bind %s: %v", *addr, err)
	}
	tr := &quic.Transport{Conn: maybeLossy(udp, *loss)}
	if k := parseKey32(*resetKey); k != nil {
		tr.StatelessResetKey = (*quic.StatelessResetKey)(k)
	} else {
		var k quic.StatelessResetKey
		mustRandom(k[:])
		tr.StatelessResetKey = &k
	}
	if *retry {
		tr.VerifySourceAddress = func(net.Addr) bool { return true }
	}
	// Remember whether the address was validated (by our Retry token or a
	// NEW_TOKEN one) so the per-connection log line can report it.
	tr.ConnContext = func(ctx context.Context, info *quic.ClientInfo) (context.Context, error) {
		return context.WithValue(ctx, addrVerifiedKey{}, info.AddrVerified), nil
	}
	ln, err := tr.ListenEarly(tlsConf, conf)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	// The matrix parses this line for the port.
	log.Printf("listening on %s (QUIC / UDP)", udp.LocalAddr())

	ctx, cancel := context.WithTimeout(context.Background(), *deadline)
	defer cancel()
	conns := make(chan *quic.Conn)
	go func() {
		for {
			conn, err := ln.Accept(ctx)
			if err != nil {
				close(conns)
				return
			}
			conns <- conn
		}
	}()
	var wg sync.WaitGroup
	done := make(chan struct{}, 1024)
	closed := 0
	n := 0
loop:
	for {
		select {
		case conn, ok := <-conns:
			if !ok {
				break loop
			}
			n++
			wg.Add(1)
			go func(id int, conn *quic.Conn) {
				defer wg.Done()
				serveConn(ctx, id, conn)
				done <- struct{}{}
			}(n, conn)
		case <-done:
			closed++
			if *naccept > 0 && closed >= *naccept {
				break loop
			}
		case <-ctx.Done():
			break loop
		}
	}
	ln.Close()
	wg.Wait()
	log.Printf("served %d connection(s)", n)
}

func serveConn(ctx context.Context, id int, conn *quic.Conn) {
	// Wait for the handshake so the negotiated state is final (with 0-RTT,
	// Accept returns before the client is authenticated).
	select {
	case <-conn.HandshakeComplete():
	case <-conn.Context().Done():
		log.Printf("conn %d: handshake failed: %s", id, closeReason(context.Cause(conn.Context())))
		return
	}
	cs := conn.ConnectionState()
	verified, _ := conn.Context().Value(addrVerifiedKey{}).(bool)
	log.Printf("conn %d from %s: %s addr_verified=%v", id, conn.RemoteAddr(), describe(cs), verified)

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for {
			s, err := conn.AcceptStream(ctx)
			if err != nil {
				return
			}
			go func() {
				seen, err := echoBidi(s)
				if err != nil {
					log.Printf("conn %d stream %d: echo error: %v", id, s.StreamID(), err)
					return
				}
				log.Printf("conn %d stream %d: echoed %d bytes sha256=%s from %s", id, s.StreamID(), len(seen), sha(seen), conn.RemoteAddr())
			}()
		}
	}()
	go func() {
		defer wg.Done()
		for {
			rs, err := conn.AcceptUniStream(ctx)
			if err != nil {
				return
			}
			go func() {
				data, err := io.ReadAll(rs)
				if err != nil {
					log.Printf("conn %d uni %d: read error: %v", id, rs.StreamID(), err)
					return
				}
				ss, err := conn.OpenUniStreamSync(ctx)
				if err != nil {
					log.Printf("conn %d: cannot open uni reply: %v", id, err)
					return
				}
				if _, err := ss.Write(data); err != nil {
					log.Printf("conn %d uni %d: write error: %v", id, ss.StreamID(), err)
					return
				}
				ss.Close()
				log.Printf("conn %d uni %d: echoed %d bytes sha256=%s on uni %d", id, rs.StreamID(), len(data), sha(data), ss.StreamID())
			}()
		}
	}()
	go func() {
		defer wg.Done()
		for {
			d, err := conn.ReceiveDatagram(ctx)
			if err != nil {
				return
			}
			if err := conn.SendDatagram(d); err != nil {
				log.Printf("conn %d: datagram echo error: %v", id, err)
				continue
			}
			log.Printf("conn %d: echoed datagram %d bytes sha256=%s", id, len(d), sha(d))
		}
	}()
	<-conn.Context().Done()
	// The address is the one the connection ended on: after a client
	// migration it differs from the one it was accepted from.
	log.Printf("conn %d: %s (last address %s)", id, closeReason(context.Cause(conn.Context())), conn.RemoteAddr())
	wg.Wait()
}

// ---------------------------------------------------------------- client

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	addr := fs.String("addr", "", "server host:port")
	sni := fs.String("sni", "localhost", "server name to verify")
	caFile := fs.String("cafile", "", "CA bundle (PEM)")
	alpn := fs.String("alpn", "pc-echo", "ALPN protocol to offer")
	mode := fs.String("mode", "bidi", "exchange kind: bidi|uni|datagram")
	in := fs.String("in", "", "payload file (default: stdin)")
	exchanges := fs.Int("exchanges", 1, "repeat the exchange this many times")
	pause := fs.Duration("pause", 0, "wait between exchanges")
	migrate := fs.Bool("migrate", false, "switch to a new UDP socket between exchanges")
	reconnect := fs.Bool("reconnect", false, "connect a second time, resuming the first session")
	zeroRTT := fs.Bool("0rtt", false, "send the second connection's data as 0-RTT")
	closeCode := fs.Uint64("close-code", 0, "application error code to close with")
	closeReasonStr := fs.String("close-reason", "", "reason phrase to close with")
	idle := fs.Duration("idle", 30*time.Second, "max_idle_timeout")
	linger := fs.Duration("linger", 0, "after the exchanges, wait this long for the peer to close")
	versions := fs.String("versions", "", "QUIC versions to offer, in order (v1,v2)")
	deadline := fs.Duration("timeout", 30*time.Second, "give up after this long")
	loss := fs.Int("loss", 0, "drop one in N datagrams in each direction (0 = none)")
	curves := fs.String("curves", "", "TLS groups to offer, comma-separated (default: Go's)")
	fs.Parse(args)
	if *addr == "" {
		log.Fatal("-addr is required")
	}

	var payload []byte
	var err error
	if *in != "" {
		payload, err = os.ReadFile(*in)
	} else {
		payload, err = io.ReadAll(os.Stdin)
	}
	if err != nil {
		log.Fatalf("cannot read payload: %v", err)
	}

	roots := x509.NewCertPool()
	if *caFile != "" {
		pem, err := os.ReadFile(*caFile)
		if err != nil {
			log.Fatalf("cannot read %s: %v", *caFile, err)
		}
		if !roots.AppendCertsFromPEM(pem) {
			log.Fatalf("no certificates in %s", *caFile)
		}
	}
	tlsConf := &tls.Config{
		RootCAs:            roots,
		ServerName:         *sni,
		NextProtos:         []string{*alpn},
		MinVersion:         tls.VersionTLS13,
		ClientSessionCache: tls.NewLRUClientSessionCache(8),
		CurvePreferences:   parseCurves(*curves),
	}
	conf := &quic.Config{
		MaxIdleTimeout:  *idle,
		EnableDatagrams: true,
		Versions:        parseVersions(*versions),
		Tracer:          qlog.DefaultConnectionTracer,
	}

	ctx, cancel := context.WithTimeout(context.Background(), *deadline)
	defer cancel()
	remote := mustUDPAddr(*addr)

	runs := 1
	if *reconnect {
		runs = 2
	}
	for run := 1; run <= runs; run++ {
		udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			log.Fatalf("cannot bind: %v", err)
		}
		tr := &quic.Transport{Conn: maybeLossy(udp, *loss)}
		early := run == 2 && *zeroRTT
		var conn *quic.Conn
		if early {
			conn, err = tr.DialEarly(ctx, remote, tlsConf, conf)
		} else {
			conn, err = tr.Dial(ctx, remote, tlsConf, conf)
		}
		if err != nil {
			log.Fatalf("connection %d: dial: %s", run, closeReason(err))
		}
		if early {
			// 0-RTT: run the first exchange before the handshake completes so
			// the data really travels in 0-RTT packets.
			log.Printf("connection %d: 0-RTT offered", run)
		}
		exchange(ctx, run, conn, tr, *mode, payload, *exchanges, *pause, *migrate, early)
		<-conn.HandshakeComplete()
		cs := conn.ConnectionState()
		log.Printf("connection %d: %s", run, describe(cs))
		if *linger > 0 {
			log.Printf("connection %d: lingering %s", run, *linger)
			select {
			case <-conn.Context().Done():
				log.Printf("connection %d: %s", run, closeReason(context.Cause(conn.Context())))
			case <-time.After(*linger):
				log.Printf("connection %d: still open after %s", run, *linger)
				conn.CloseWithError(0, "")
			}
		} else {
			select {
			case <-conn.Context().Done():
				log.Printf("connection %d: %s", run, closeReason(context.Cause(conn.Context())))
			default:
				err := conn.CloseWithError(quic.ApplicationErrorCode(*closeCode), *closeReasonStr)
				log.Printf("connection %d: closed locally with %#x (%q): err=%v", run, *closeCode, *closeReasonStr, err)
			}
		}
		// Let the CONNECTION_CLOSE go out before the socket disappears.
		time.Sleep(100 * time.Millisecond)
		tr.Close()
	}
}

// exchange performs `count` echo round trips of `payload` on `conn` and
// writes each reply to stdout.
func exchange(ctx context.Context, run int, conn *quic.Conn, tr *quic.Transport, mode string, payload []byte, count int, pause time.Duration, migrate bool, early bool) {
	for i := 1; i <= count; i++ {
		if i > 1 {
			if pause > 0 {
				time.Sleep(pause)
			}
			if migrate {
				udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
				if err != nil {
					log.Fatalf("cannot bind for migration: %v", err)
				}
				tr2 := &quic.Transport{Conn: udp}
				path, err := conn.AddPath(tr2)
				if err != nil {
					log.Fatalf("connection %d: AddPath: %v", run, err)
				}
				if err := path.Probe(ctx); err != nil {
					log.Fatalf("connection %d: path probe: %v", run, err)
				}
				if err := path.Switch(); err != nil {
					log.Fatalf("connection %d: path switch: %v", run, err)
				}
				log.Printf("connection %d: migrated to %s", run, udp.LocalAddr())
			}
		}
		var reply []byte
		var err error
		switch mode {
		case "bidi":
			reply, err = exchangeBidi(ctx, conn, payload)
		case "uni":
			reply, err = exchangeUni(ctx, conn, payload)
		case "datagram":
			reply, err = exchangeDatagram(ctx, conn, payload, early)
		default:
			log.Fatalf("unknown mode %q", mode)
		}
		if err != nil {
			log.Printf("connection %d exchange %d: error: %v", run, i, err)
			// The connection error (if any) is what the matrix wants to see.
			select {
			case <-conn.Context().Done():
				log.Printf("connection %d: %s", run, closeReason(context.Cause(conn.Context())))
			default:
			}
			os.Exit(1)
		}
		os.Stdout.Write(reply)
		log.Printf("connection %d exchange %d: %s %d bytes sent sha256=%s, %d bytes received sha256=%s, from %s",
			run, i, mode, len(payload), sha(payload), len(reply), sha(reply), conn.LocalAddr())
	}
}

func exchangeBidi(ctx context.Context, conn *quic.Conn, payload []byte) ([]byte, error) {
	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	var werr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, werr = s.Write(payload); werr == nil {
			werr = s.Close()
		}
	}()
	reply, rerr := io.ReadAll(s)
	wg.Wait()
	if werr != nil {
		return reply, werr
	}
	return reply, rerr
}

func exchangeUni(ctx context.Context, conn *quic.Conn, payload []byte) ([]byte, error) {
	ss, err := conn.OpenUniStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := ss.Write(payload); err != nil {
		return nil, err
	}
	if err := ss.Close(); err != nil {
		return nil, err
	}
	rs, err := conn.AcceptUniStream(ctx)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(rs)
}

// exchangeDatagram sends every line of payload as one DATAGRAM and collects
// the echoes (in any order) until all are back or two seconds pass.
func exchangeDatagram(ctx context.Context, conn *quic.Conn, payload []byte, early bool) ([]byte, error) {
	if early {
		<-conn.HandshakeComplete()
	}
	lines := strings.SplitAfter(strings.TrimRight(string(payload), "\n"), "\n")
	want := 0
	for _, l := range lines {
		if l == "" {
			continue
		}
		if !strings.HasSuffix(l, "\n") {
			l += "\n"
		}
		if err := conn.SendDatagram([]byte(l)); err != nil {
			return nil, err
		}
		want++
	}
	var got []byte
	dctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	for i := 0; i < want; i++ {
		d, err := conn.ReceiveDatagram(dctx)
		if err != nil {
			return got, fmt.Errorf("received %d of %d datagrams: %w", i, want, err)
		}
		got = append(got, d...)
	}
	return got, nil
}

// ---------------------------------------------------------------- loss

// lossyConn drops one in every `every` datagrams in each direction, so RFC
// 9002 loss recovery on both ends has real holes to fill. Deterministic
// (a counter, not a coin), so a run is reproducible. Wrapping the UDPConn
// hides it from quic-go's fast paths (no GSO / ECN), which is fine for
// this case.
type lossyConn struct {
	net.PacketConn
	every  int
	nRead  int
	nWrite int
}

func maybeLossy(c net.PacketConn, every int) net.PacketConn {
	if every <= 0 {
		return c
	}
	return &lossyConn{PacketConn: c, every: every}
}

func (l *lossyConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := l.PacketConn.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		l.nRead++
		if l.nRead%l.every == 0 {
			continue // dropped on receive
		}
		return n, addr, nil
	}
}

func (l *lossyConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	l.nWrite++
	// Offset from the read counter so the two directions do not drop the
	// same round trip.
	if (l.nWrite+l.every/2)%l.every == 0 {
		return len(p), nil // dropped on send
	}
	return l.PacketConn.WriteTo(p, addr)
}

// ---------------------------------------------------------------- misc

func mustUDPAddr(s string) *net.UDPAddr {
	a, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		log.Fatalf("bad address %q: %v", s, err)
	}
	return a
}

func mustRandom(b []byte) {
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("crypto/rand: %v", err)
	}
}
