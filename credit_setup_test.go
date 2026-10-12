package smb2

// The account opens with the one credit a server implicitly grants for
// NEGOTIATE. Every request has to be paid for out of the balance, or out of
// its own response's grant, for the client's balance to match the window the
// server has granted. A client whose balance runs ahead of the server's books
// eventually sends a MessageId past the window, and the server drops the
// connection (MS-SMB2 3.3.5.2.3).

import (
	"context"
	"encoding/asn1"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudsoda/go-smb2/internal/erref"
	"github.com/cloudsoda/go-smb2/internal/smb2"
	"github.com/cloudsoda/go-smb2/internal/spnego"
)

var stubMechOid = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 99}

// stubInitiator completes a session setup in two legs without real
// authentication; the fake server marks the session as guest, so no keys are
// needed.
type stubInitiator struct{}

func (stubInitiator) OID() asn1.ObjectIdentifier              { return stubMechOid }
func (stubInitiator) InitSecContext() ([]byte, error)         { return []byte("negotiate"), nil }
func (stubInitiator) AcceptSecContext([]byte) ([]byte, error) { return []byte("authenticate"), nil }
func (stubInitiator) Sum([]byte) []byte                       { return nil }
func (stubInitiator) SessionKey() []byte                      { return nil }

const (
	windowSessionId = 0x5e55
	windowTreeId    = 7
)

type windowRequest struct {
	hdr    smb2.PacketHeader
	cmd    uint16
	length uint32 // READ only
}

// windowServer grants exactly the credits each request asks for, which MS-SMB2
// allows and Windows does, so it never leaves the client slack to hide a
// miscounted balance. It records any request that reaches past the credits it
// has granted.
type windowServer struct {
	t transport

	mu         sync.Mutex
	granted    uint64
	consumed   uint64
	violations int
	setupLegs  int

	queue chan windowRequest
}

func newWindowServer(t transport) *windowServer {
	return &windowServer{t: t, granted: 1, queue: make(chan windowRequest, 1024)}
}

func (s *windowServer) outstanding() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.granted - s.consumed
}

func (s *windowServer) violationCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.violations
}

func (s *windowServer) run() {
	go s.respond()

	buf := make([]byte, bufSize)
	for {
		n, err := s.t.ReadSize()
		if err != nil {
			close(s.queue)
			return
		}
		if _, err := s.t.Read(buf[:n]); err != nil {
			close(s.queue)
			return
		}

		p := smb2.PacketCodec(buf[:n])
		req := windowRequest{
			hdr: smb2.PacketHeader{
				CreditCharge:          max(p.CreditCharge(), 1),
				CreditRequestResponse: p.CreditRequest(),
				MessageId:             p.MessageId(),
				SessionId:             p.SessionId(),
				TreeId:                p.TreeId(),
			},
			cmd: p.Command(),
		}
		if req.cmd == smb2.SMB2_READ {
			req.length = smb2.ReadRequestDecoder(buf[64:n]).Length()
		}

		s.mu.Lock()
		if req.hdr.MessageId+uint64(req.hdr.CreditCharge) > s.granted {
			s.violations++
		}
		s.consumed += uint64(req.hdr.CreditCharge)
		s.mu.Unlock()

		s.queue <- req
	}
}

func (s *windowServer) respond() {
	for req := range s.queue {
		hdr := smb2.PacketHeader{
			Flags:                 smb2.SMB2_FLAGS_SERVER_TO_REDIR,
			MessageId:             req.hdr.MessageId,
			SessionId:             req.hdr.SessionId,
			TreeId:                req.hdr.TreeId,
			CreditRequestResponse: max(req.hdr.CreditRequestResponse, 1),
		}

		var resp smb2.Packet
		switch req.cmd {
		case smb2.SMB2_NEGOTIATE:
			resp = &smb2.NegotiateResponse{
				PacketHeader:    hdr,
				SecurityMode:    smb2.SMB2_NEGOTIATE_SIGNING_ENABLED,
				DialectRevision: smb2.SMB302,
				Capabilities:    smb2.SMB2_GLOBAL_CAP_LARGE_MTU,
				MaxTransactSize: bufSize,
				MaxReadSize:     bufSize,
				MaxWriteSize:    bufSize,
				SystemTime:      &smb2.Filetime{},
				ServerStartTime: &smb2.Filetime{},
			}
		case smb2.SMB2_SESSION_SETUP:
			s.setupLegs++
			hdr.SessionId = windowSessionId
			r := &smb2.SessionSetupResponse{SessionFlags: smb2.SMB2_SESSION_FLAG_IS_GUEST}
			if s.setupLegs == 1 {
				hdr.Status = uint32(erref.STATUS_MORE_PROCESSING_REQUIRED)
				token, err := spnego.EncodeNegTokenResp(1, stubMechOid, []byte("challenge"), nil)
				if err != nil {
					panic(err)
				}
				r.SecurityBuffer = token
			}
			r.PacketHeader = hdr
			resp = r
		case smb2.SMB2_TREE_CONNECT:
			hdr.TreeId = windowTreeId
			resp = &smb2.TreeConnectResponse{PacketHeader: hdr, ShareType: smb2.SMB2_SHARE_TYPE_DISK}
		case smb2.SMB2_TREE_DISCONNECT:
			resp = &smb2.TreeDisconnectResponse{PacketHeader: hdr}
		case smb2.SMB2_ECHO:
			resp = &smb2.EchoResponse{PacketHeader: hdr}
		case smb2.SMB2_LOGOFF:
			resp = &smb2.LogoffResponse{PacketHeader: hdr}
		case smb2.SMB2_READ:
			// Delay reads so a burst holds the whole balance in flight.
			time.Sleep(100 * time.Microsecond)
			resp = &smb2.ReadResponse{PacketHeader: hdr, Data: make([]byte, req.length)}
		default:
			resp = &smb2.ErrorResponse{PacketHeader: hdr}
		}

		pkt := make([]byte, resp.Size())
		resp.Encode(pkt)
		if req.cmd == smb2.SMB2_READ {
			pkt[64+2] = 80 // DataOffset from packet start
		}

		s.mu.Lock()
		s.granted += uint64(hdr.CreditRequestResponse)
		s.mu.Unlock()

		if _, err := s.t.Write(pkt); err != nil {
			return
		}
	}
}

// drainBalance reads from enough goroutines at once to have every credit the
// client believes it holds in flight.
func drainBalance(t *testing.T, fs *Share) {
	t.Helper()
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			f := &File{fs: fs, fd: &smb2.FileId{}}
			buf := make([]byte, 512*1024)
			for range 4 {
				_, err := f.readAt(buf, 0)
				assert.NoError(t, err)
			}
		})
	}
	wg.Wait()
}

// TestSetupRequestsPayForTheirCredits dials, mounts, and drains the balance,
// then remounts and drains it again. NEGOTIATE, SESSION_SETUP, TREE_CONNECT,
// TREE_DISCONNECT and ECHO must each be paid for, so the client never spends a
// credit the server did not grant and the books agree at the end.
func TestSetupRequestsPayForTheirCredits(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	srv := newWindowServer(direct(serverConn))
	go srv.run()

	d := &Dialer{Initiator: stubInitiator{}}
	sess, err := d.DialConn(context.Background(), clientConn, "fakehost")
	require.NoError(t, err)
	defer func() {
		_ = sess.Logoff()
	}()
	account := sess.s.conn.account

	assert.EqualValues(t, srv.outstanding(), len(account.balance), "books diverged after session setup")

	fs, err := sess.Mount("share")
	require.NoError(t, err)
	assert.EqualValues(t, srv.outstanding(), len(account.balance), "books diverged after tree connect")

	drainBalance(t, fs)

	require.NoError(t, fs.Umount())
	assert.EqualValues(t, srv.outstanding(), len(account.balance), "books diverged after tree disconnect")

	fs, err = sess.Mount("share")
	require.NoError(t, err)
	require.NoError(t, sess.Echo())
	drainBalance(t, fs)

	assert.Zero(t, srv.violationCount(), "client sent MessageIds past the server's window")
	assert.EqualValues(t, srv.outstanding(), len(account.balance), "books diverged")
}
