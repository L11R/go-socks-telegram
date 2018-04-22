package socks

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

var (
	Commands = []string{"CONNECT", "BIND", "UDP ASSOCIATE"}

	errAddrType      = errors.New("[socks] addr type not supported")
	errVer           = errors.New("[socks] unsupported socks version")
	errAuthExtraData = errors.New("[socks] extra authentication data")
	errReqExtraData  = errors.New("[socks] extra data requested")
	errCmd           = errors.New("[socks] only connect command supported")
)

type Config struct {
	// Func to valid username/password pair
	ValidAuth func(username, password string) bool
	// Connections per user limit
	ConnsPerUser int
	// Verbose logs
	Verbose bool
}

type Server struct {
	Conns     []net.Conn
	UserConns sync.Map
	config    *Config
}

type AuthContext struct {
	Method  int
	Payload map[string]string
}

const (
	socksVer5       = 0x05
	socksCmdConnect = 0x01
)

func NewServer(config *Config) *Server {
	if config.ValidAuth == nil {
		config.ValidAuth = func(username, password string) bool {
			return false
		}
	}

	server := &Server{
		Conns:  make([]net.Conn, 0),
		config: config,
	}

	return server
}

func netCopy(input, output net.Conn) (err error) {
	buf := make([]byte, 8192)
	for {
		count, err := input.Read(buf)
		if err != nil {
			if err == io.EOF && count > 0 {
				output.Write(buf[:count])
			}
			break
		}
		if count > 0 {
			output.Write(buf[:count])
		}
	}
	return
}

func (srv *Server) handShake(conn net.Conn) (*AuthContext, error) {
	const (
		idVer     = 0
		idNmethod = 1
	)

	buf := make([]byte, 258)

	// Make sure we get the nmethod field
	n, err := io.ReadAtLeast(conn, buf, idNmethod+1)
	if err != nil {
		return nil, err
	}

	if buf[idVer] != socksVer5 {
		return nil, errVer
	}

	nmethods := int(buf[idNmethod]) // Client support auth mode
	msgLen := nmethods + 2          // Auth msg length

	if n == msgLen {
		// Handshake done, common case
		// Do nothing, jump directly to auth methods
	} else if n < msgLen {
		// Has more methods to read
		if _, err := io.ReadFull(conn, buf[n:msgLen]); err != nil {
			return nil, err
		}
	} else {
		// Error, shouldn't get extra data
		return nil, errAuthExtraData
	}

	/*
	   X'00' NO AUTHENTICATION REQUIRED
	   X'01' GSSAPI
	   X'02' USERNAME/PASSWORD
	   X'03' to X'7F' IANA ASSIGNED
	   X'80' to X'FE' RESERVED FOR PRIVATE METHODS
	   X'FF' NO ACCEPTABLE METHODS
	*/

	// Do we need to use username/password auth?
	if srv.config.ValidAuth == nil {
		_, err := conn.Write([]byte{socksVer5, 0})
		if err != nil {
			return nil, err
		}

		return &AuthContext{
			Method: 0,
		}, nil
	}

	methods := buf[2 : 2+nmethods]

	for _, method := range methods {
		// It's username/password method
		if method == 2 {
			bufConn := bufio.NewReader(conn)

			// Tell client to use USERNAME/PASSWORD auth method
			if _, err := conn.Write([]byte{
				socksVer5,
				// USERNAME/PASSWORD auth method
				2,
			}); err != nil {
				return nil, err
			}

			return srv.authenticate(conn, bufConn)
		}
	}

	conn.Write([]byte{socksVer5, 255})
	return &AuthContext{
		Method: 255,
	}, fmt.Errorf("[socks] no supported auth mechanism")
}

func (srv *Server) authenticate(conn net.Conn, bufConn io.Reader) (*AuthContext, error) {
	const (
		authVersion = 1
		authSuccess = 0
		authFailure = 1
	)

	// Get version and username length
	header := []byte{0, 0}
	if _, err := io.ReadAtLeast(bufConn, header, 2); err != nil {
		return nil, err
	}

	// Ensure about auth version
	if header[0] != authVersion {
		return nil, fmt.Errorf("[socks] unsupported auth version: %v", header[0])
	}

	// Get username
	usernameLen := int(header[1])

	usernameBytes := make([]byte, usernameLen)
	if _, err := io.ReadAtLeast(bufConn, usernameBytes, usernameLen); err != nil {
		return nil, err
	}
	username := string(usernameBytes)

	// Get the password length
	if _, err := bufConn.Read(header[:1]); err != nil {
		return nil, err
	}

	// Get password
	passwordLen := int(header[0])

	passwordBytes := make([]byte, passwordLen)
	if _, err := io.ReadAtLeast(bufConn, passwordBytes, passwordLen); err != nil {
		return nil, err
	}
	password := string(passwordBytes)

	if srv.config.ValidAuth(username, password) {
		if _, err := conn.Write([]byte{
			authVersion,
			authSuccess,
		}); err != nil {
			return nil, err
		}
	} else {
		if _, err := conn.Write([]byte{
			authVersion,
			authFailure,
		}); err != nil {
			return nil, err
		}
	}

	return &AuthContext{
		Method: 2,
		Payload: map[string]string{
			"username": username,
		},
	}, nil
}

func (srv *Server) parseTarget(conn net.Conn) (host string, err error) {
	const (
		idVer   = 0
		idCmd   = 1
		idType  = 3 // Address type index
		idIP0   = 4 // IP address start index
		idDmLen = 4 // Domain address length index
		idDm0   = 5 // Domain address start index

		typeIPv4 = 1 // IPv4 address
		typeDm   = 3 // Domain
		typeIPv6 = 4 // IPv6 address

		lenIPv4   = 3 + 1 + net.IPv4len + 2 // 3 (ver + cmd + rsv) + 1 addrType + IPv4 + 2 port
		lenIPv6   = 3 + 1 + net.IPv6len + 2 // 3 (ver + cmd + rsv) + 1 addrType + IPv6 + 2 port
		lenDmBase = 3 + 1 + 1 + 2           // 3 (ver + cmd + rsv) + 1 addrType + 1 addrLen + 2 port + addrLen
	)

	// refer to getRequest in server.go for why set buffer size to 263
	buf := make([]byte, 263)
	var n int

	// read till we get possible domain length field
	if n, err = io.ReadAtLeast(conn, buf, idDmLen+1); err != nil {
		return
	}

	// check version and cmd
	if buf[idVer] != socksVer5 {
		err = errVer
		return
	}

	/*
	   CONNECT X'01'
	   BIND X'02'
	   UDP ASSOCIATE X'03'
	*/

	if buf[idCmd] > 0x03 || buf[idCmd] == 0x00 {
		log.Printf("[socks] unknown command: %v\n", buf[idCmd])
	}

	if srv.config.Verbose {
		log.Printf("[socks] command: %v\n", Commands[buf[idCmd]-1])
	}

	if buf[idCmd] != socksCmdConnect { //  only support CONNECT mode
		err = errCmd
		return
	}

	// read target address
	reqLen := -1
	switch buf[idType] {
	case typeIPv4:
		reqLen = lenIPv4
	case typeIPv6:
		reqLen = lenIPv6
	case typeDm: // domain name
		reqLen = int(buf[idDmLen]) + lenDmBase
	default:
		err = errAddrType
		return
	}

	if n == reqLen {
		// common case, do nothing
	} else if n < reqLen { // rare case
		if _, err = io.ReadFull(conn, buf[n:reqLen]); err != nil {
			return
		}
	} else {
		err = errReqExtraData
		return
	}

	switch buf[idType] {
	case typeIPv4:
		host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
	case typeIPv6:
		host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
	case typeDm:
		host = string(buf[idDm0 : idDm0+buf[idDmLen]])
	}
	port := binary.BigEndian.Uint16(buf[reqLen-2 : reqLen])
	host = net.JoinHostPort(host, strconv.Itoa(int(port)))

	return
}

func (srv *Server) pipeWhenClose(conn net.Conn, target string) {
	if srv.config.Verbose {
		log.Printf("[socks] connect: %s\n", target)
	}

	remoteConn, err := net.DialTimeout("tcp", target, time.Duration(time.Second*15))
	if err != nil {
		log.Printf("[socks] connect: %v\n", err)
		return
	}

	// Don't forget to close connection
	defer remoteConn.Close()

	tcpAddr := remoteConn.LocalAddr().(*net.TCPAddr)
	if tcpAddr.Zone == "" {
		if tcpAddr.IP.Equal(tcpAddr.IP.To4()) {
			tcpAddr.Zone = "ip4"
		} else {
			tcpAddr.Zone = "ip6"
		}
	}

	if srv.config.Verbose {
		log.Printf("[socks] connect: %s:%d\n", tcpAddr.IP.String(), tcpAddr.Port)
	}

	rep := make([]byte, 256)
	rep[0] = 0x05
	rep[1] = 0x00 // succeeded
	rep[2] = 0x00 // RSV

	//IP
	if tcpAddr.Zone == "ip6" {
		rep[3] = 0x04 //IPv6
	} else {
		rep[3] = 0x01 //IPv4
	}

	var ip net.IP
	if "ip6" == tcpAddr.Zone {
		ip = tcpAddr.IP.To16()
	} else {
		ip = tcpAddr.IP.To4()
	}
	pindex := 4
	for _, b := range ip {
		rep[pindex] = b
		pindex += 1
	}
	rep[pindex] = byte((tcpAddr.Port >> 8) & 0xff)
	rep[pindex+1] = byte(tcpAddr.Port & 0xff)
	conn.Write(rep[0 : pindex+2])

	// Copy local to remote
	go netCopy(conn, remoteConn)

	// Copy remote to local
	netCopy(remoteConn, conn)
}

func (srv *Server) handleConnection(conn net.Conn) {
	// Don't forget to close connection
	defer func() {
		for i, c := range srv.Conns {
			if c == conn {
				// Remove connection from array
				srv.Conns = append(
					srv.Conns[:i],
					srv.Conns[i+1:]...,
				)
			}
		}

		conn.Close()
	}()

	// Add new connection
	srv.Conns = append(srv.Conns, conn)
	auth, err := srv.handShake(conn)
	if err != nil {
		log.Printf("[socks] handshake: %v\n", err)
		return
	}

	// Check username in Payload map
	if username, found := auth.Payload["username"]; found {
		// Get count of connections from sync.Map
		if count, found := srv.UserConns.Load(username); found {
			// Don't forget to decrement one connection after closing it
			defer func() {
				if count, found := srv.UserConns.Load(username); found {
					srv.UserConns.Store(username, count.(int)-1)
				}
			}()

			// Refuse if there are more connections than we allow
			if count.(int) > srv.config.ConnsPerUser {
				log.Printf("[socks] failed to authenticate: max count of connections for %s has exceeded", username)
				if _, err = conn.Write([]byte{
					socksVer5,
					5,
				}); err != nil {
					return
				}

				return
			}

			// Increment one connection
			srv.UserConns.Store(username, count.(int)+1)
		} else {
			// If there are no connections, store one
			srv.UserConns.Store(username, 1)
		}

		// Show it in log
		if count, found := srv.UserConns.Load(username); found {
			if srv.config.Verbose {
				log.Printf("[socks] %d %s authenticated (%s)\n", count, username, conn.RemoteAddr())
			}
		}
	}

	// Parse
	addr, err := srv.parseTarget(conn)
	if err == io.EOF {
		log.Printf("[socks] connection closed by client or server")
		return
	} else if err != nil {
		log.Printf("[socks] consult transfer mode or parse target: %v\n", err)
		return
	}

	srv.pipeWhenClose(conn, addr)
}

// ListenAndServe is used to create a listener and serve on it
func (srv *Server) ListenAndServe(network, addr string) error {
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	return srv.Serve(l)
}

// Serve is used to serve connections from a listener
func (srv *Server) Serve(l net.Listener) error {
	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}

		go srv.handleConnection(conn)
	}
}

/*
// FOR TESTING
func main() {
	// Create a SOCKS5 server
	conf := &Config{
		ValidAuth: func(username, password string) bool {
			return true
		},

		UsernamePasswordAuth: true,
		ConnsPerUser: 2,
		Verbose: true,
	}

	server := NewServer(conf)

	// Create SOCKS5 proxy on localhost
	err := server.ListenAndServe("tcp", fmt.Sprintf(":%d", 1080))
	if err != nil {
		log.Println("ERROR: ", err.Error())
	}
}
*/
