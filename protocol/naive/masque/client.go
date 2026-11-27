// Package masque implements an RFC 9298 CONNECT-UDP client over HTTP/3,
// using the same sagernet/quic-go fork as sing-box and Caddy.
package masque

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/quic-go/quicvarint"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	defaultMaxDatagramSize = 1200
	masquePathPrefix       = "/.well-known/masque/udp/"
)

var (
	ErrDatagramTooLarge = errors.New("masque: datagram too large")
	ErrNoConnection     = errors.New("masque: no connection")
)

var contextIDZero = quicvarint.Append(nil, 0)

type Config struct {
	// ServerAddr is the HTTP/3 proxy address (host:port).
	ServerAddr string
	// ServerName is the TLS SNI / certificate name.
	ServerName string
	// TLSConfig is used for the HTTP/3 connection. NextProtos is forced to h3.
	TLSConfig *tls.Config
	// Username and Password are sent as Proxy-Authorization: Basic.
	Username string
	Password string
	// ExtraHeaders are added to every CONNECT-UDP request.
	ExtraHeaders map[string]string
	// ChromeParrot makes the QUIC handshake look like Chrome's.
	ChromeParrot bool
	// MaxDatagramSize is the largest UDP payload sent in one HTTP Datagram.
	MaxDatagramSize int
	// Dialer creates the UDP socket for the HTTP/3 connection. When set, the
	// socket goes through the outbound dialer (and is protected from the TUN
	// on Android); without it the OS route is used, which loops inside a TUN.
	Dialer N.Dialer
}

type Client struct {
	config Config

	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex
	udpConn   net.Conn
	conn      *quic.Conn
	transport *http3.Transport
	h3        *http3.ClientConn
	maxSize   int

	// connectMu serializes dials. Close never takes it, so stopping the
	// client is not blocked by an in-flight (possibly failing) H3 dial.
	connectMu sync.Mutex
}

func New(config Config) *Client {
	if config.MaxDatagramSize <= 0 {
		config.MaxDatagramSize = defaultMaxDatagramSize
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{config: config, maxSize: config.MaxDatagramSize, ctx: ctx, cancel: cancel}
}

// ListenPacket opens a CONNECT-UDP flow to destination and returns it as a
// net.PacketConn. Each call creates one HTTP/3 request stream.
func (c *Client) ListenPacket(ctx context.Context, destination string) (net.PacketConn, error) {
	return c.open(ctx, destination)
}

// DialContext opens a CONNECT-UDP flow and returns it as a connected net.Conn.
func (c *Client) DialContext(ctx context.Context, destination string) (net.Conn, error) {
	return c.open(ctx, destination)
}

func (c *Client) open(ctx context.Context, destination string) (*Flow, error) {
	host, portStr, err := net.SplitHostPort(destination)
	if err != nil {
		return nil, fmt.Errorf("masque: invalid destination %q: %w", destination, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("masque: invalid port in %q", destination)
	}
	h3, err := c.ensureConn(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := h3.OpenRequestStream(ctx)
	if err != nil {
		c.reset()
		return nil, fmt.Errorf("masque: open request stream: %w", err)
	}
	request := &http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Scheme: "https",
			Host:   c.config.ServerAddr,
			Path:   masquePathPrefix + escapeHost(host) + "/" + strconv.Itoa(port) + "/",
		},
		Host:   c.config.ServerAddr,
		Proto:  "connect-udp",
		Header: make(http.Header),
	}
	request.Header.Set("Capsule-Protocol", "?1")
	if c.config.Username != "" || c.config.Password != "" {
		credentials := base64.StdEncoding.EncodeToString(
			[]byte(c.config.Username + ":" + c.config.Password))
		request.Header.Set("Proxy-Authorization", "Basic "+credentials)
	}
	for key, value := range c.config.ExtraHeaders {
		request.Header.Set(key, value)
	}
	if err = stream.SendRequestHeader(request); err != nil {
		stream.Close()
		return nil, fmt.Errorf("masque: send request: %w", err)
	}
	response, err := stream.ReadResponse()
	if err != nil {
		stream.Close()
		return nil, fmt.Errorf("masque: read response: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		stream.Close()
		return nil, fmt.Errorf("masque: proxy returned %s", response.Status)
	}
	remoteAddr, err := net.ResolveUDPAddr("udp", destination)
	if err != nil {
		remoteAddr = &net.UDPAddr{}
	}
	return &Flow{
		client:     c,
		stream:     stream,
		remoteAddr: remoteAddr,
		maxSize:    c.maxSize,
	}, nil
}

func (c *Client) ensureConn(ctx context.Context) (*http3.ClientConn, error) {
	c.mu.Lock()
	if c.h3 != nil && c.conn != nil && c.conn.Context().Err() == nil {
		h3 := c.h3
		c.mu.Unlock()
		return h3, nil
	}
	c.mu.Unlock()

	c.connectMu.Lock()
	defer c.connectMu.Unlock()

	// Another flow may have connected while we waited for connectMu.
	c.mu.Lock()
	if c.h3 != nil && c.conn != nil && c.conn.Context().Err() == nil {
		h3 := c.h3
		c.mu.Unlock()
		return h3, nil
	}
	c.mu.Unlock()
	if err := c.ctx.Err(); err != nil {
		return nil, fmt.Errorf("masque: client closed")
	}

	tlsConfig := &tls.Config{NextProtos: []string{http3.NextProtoH3}}
	if c.config.TLSConfig != nil {
		tlsConfig = c.config.TLSConfig.Clone()
	}
	if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = c.config.ServerName
	}
	if len(tlsConfig.NextProtos) == 0 {
		tlsConfig.NextProtos = []string{http3.NextProtoH3}
	}
	quicConfig := &quic.Config{
		EnableDatagrams:      true,
		ChromeParrot:         c.config.ChromeParrot,
		HandshakeIdleTimeout: 10 * time.Second,
	}
	// A failed handshake must never hold the dial past its deadline: Close
	// cancels c.ctx and stops the wait (otherwise VPN shutdown ANRs).
	dialCtx, cancelDial := context.WithTimeout(ctx, 12*time.Second)
	stopAfter := context.AfterFunc(c.ctx, cancelDial)
	defer func() {
		stopAfter()
		cancelDial()
	}()

	var conn *quic.Conn
	var udpConn net.Conn
	var err error
	if c.config.Dialer != nil {
		// Protected socket: on Android a raw UDP socket would be captured by
		// the VPN's TUN and never reach the proxy.
		udpConn, err = c.config.Dialer.DialContext(dialCtx, N.NetworkUDP,
			M.ParseSocksaddr(c.config.ServerAddr))
		if err != nil {
			return nil, fmt.Errorf("masque: dial %s: %w", c.config.ServerAddr, err)
		}
		conn, err = quic.DialConn(dialCtx, udpConn, tlsConfig, quicConfig)
	} else {
		conn, err = quic.DialAddr(dialCtx, c.config.ServerAddr, tlsConfig, quicConfig)
	}
	if err != nil {
		if udpConn != nil {
			_ = udpConn.Close()
		}
		return nil, fmt.Errorf("masque: dial %s: %w", c.config.ServerAddr, err)
	}

	transport := &http3.Transport{
		EnableDatagrams: true,
		TLSClientConfig: tlsConfig,
	}
	h3 := transport.NewClientConn(conn)

	c.mu.Lock()
	if err = c.ctx.Err(); err != nil {
		c.mu.Unlock()
		_ = conn.CloseWithError(0, "")
		if udpConn != nil {
			_ = udpConn.Close()
		}
		return nil, fmt.Errorf("masque: client closed")
	}
	c.udpConn = udpConn
	c.conn = conn
	c.transport = transport
	c.h3 = h3
	c.mu.Unlock()
	return h3, nil
}

func (c *Client) reset() {
	c.mu.Lock()
	conn := c.conn
	udpConn := c.udpConn
	c.conn = nil
	c.udpConn = nil
	c.transport = nil
	c.h3 = nil
	c.mu.Unlock()
	if conn != nil {
		_ = conn.CloseWithError(0, "")
	}
	if udpConn != nil {
		_ = udpConn.Close()
	}
}

// Close stops the client without waiting for an in-flight dial. The caller
// (libbox/VPN shutdown) runs on the Android main thread, so blocking here
// turns into an ANR.
func (c *Client) Close() error {
	c.cancel()
	c.reset()
	return nil
}

func escapeHost(host string) string {
	if ip := net.ParseIP(host); ip != nil {
		// RFC 9298 Section 2: IPv6 literals must have their colons
		// percent-encoded, e.g. 2001%3Adb8%3A%3A42.
		if strings.Contains(host, ":") {
			return strings.ReplaceAll(host, ":", "%3A")
		}
		return host
	}
	return url.PathEscape(host)
}

// Flow is one CONNECT-UDP request stream. It implements net.PacketConn and
// net.Conn; the destination is fixed for the lifetime of the flow.
type Flow struct {
	client     *Client
	stream     *http3.RequestStream
	remoteAddr net.Addr
	maxSize    int

	deadlineMu    sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time

	closeOnce sync.Once
}

func (f *Flow) Read(p []byte) (int, error) {
	n, _, err := f.ReadFrom(p)
	return n, err
}

func (f *Flow) Write(p []byte) (int, error) {
	return f.WriteTo(p, f.remoteAddr)
}

func (f *Flow) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		ctx, cancel := f.readContext()
		datagram, err := f.stream.ReceiveDatagram(ctx)
		cancel()
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				return 0, nil, os.ErrDeadlineExceeded
			}
			return 0, nil, err
		}
		contextID, n, err := quicvarint.Parse(datagram)
		if err != nil || contextID != 0 {
			continue
		}
		payload := datagram[n:]
		if len(payload) > len(p) {
			return 0, nil, io.ErrShortBuffer
		}
		copy(p, payload)
		return len(payload), f.remoteAddr, nil
	}
}

func (f *Flow) WriteTo(p []byte, _ net.Addr) (int, error) {
	if len(p) > f.maxSize {
		return 0, ErrDatagramTooLarge
	}
	datagram := make([]byte, 0, len(contextIDZero)+len(p))
	datagram = append(datagram, contextIDZero...)
	datagram = append(datagram, p...)
	if err := f.stream.SendDatagram(datagram); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (f *Flow) Close() error {
	var err error
	f.closeOnce.Do(func() {
		f.stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
		err = f.stream.Close()
	})
	return err
}

func (f *Flow) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (f *Flow) RemoteAddr() net.Addr {
	return f.remoteAddr
}

func (f *Flow) SetDeadline(t time.Time) error {
	f.deadlineMu.Lock()
	f.readDeadline = t
	f.writeDeadline = t
	f.deadlineMu.Unlock()
	return nil
}

func (f *Flow) SetReadDeadline(t time.Time) error {
	f.deadlineMu.Lock()
	f.readDeadline = t
	f.deadlineMu.Unlock()
	return nil
}

func (f *Flow) SetWriteDeadline(t time.Time) error {
	f.deadlineMu.Lock()
	f.writeDeadline = t
	f.deadlineMu.Unlock()
	return nil
}

func (f *Flow) readContext() (context.Context, context.CancelFunc) {
	f.deadlineMu.Lock()
	deadline := f.readDeadline
	f.deadlineMu.Unlock()
	if deadline.IsZero() {
		return context.WithCancel(context.Background())
	}
	return context.WithDeadline(context.Background(), deadline)
}
