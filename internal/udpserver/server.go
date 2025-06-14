{{ ... }}
	"log/slog"
	"net"

	"e:/socksip-server/internal/config"
)

const (
	// Assuming 0 is the standard authentication request type from the client
	AuthRequestType = 0x00
)

// Server represents the UDP relay server.
type Server struct {
	config *config.Config
{{ ... }}
// handlePacket processes an incoming UDP packet.
func (s *Server) handlePacket(conn *net.UDPConn, clientAddr *net.UDPAddr, data []byte) {
	s.logger.Debug("received UDP packet", "from", clientAddr.String(), "size", len(data))

	if len(data) < 2 { // Must have at least request type and one length byte
		s.logger.Warn("dropping undersized UDP packet", "from", clientAddr.String())
		return
	}

	reader := bytes.NewReader(data)

	// 1. Read Request Type
	reqType, err := reader.ReadByte()
	if err != nil {
		s.logger.Warn("failed to read request type", "from", clientAddr.String(), "error", err)
		return
	}

	if reqType != AuthRequestType {
		s.logger.Warn("unsupported UDP request type", "from", clientAddr.String(), "type", reqType)
		return
	}

	// 2. Read Username
	username, err := readLVString(reader)
	if err != nil {
		s.logger.Warn("failed to read username from UDP packet", "from", clientAddr.String(), "error", err)
		return
	}

	// 3. Read Password
	password, err := readLVString(reader)
	if err != nil {
		s.logger.Warn("failed to read password from UDP packet", "from", clientAddr.String(), "error", err)
		return
	}

	// 4. Authenticate User
	if !s.authenticate(username, password) {
		s.logger.Warn("UDP authentication failed", "from", clientAddr.String(), "username", username)
		return
	}

	s.logger.Info("UDP user authenticated successfully", "from", clientAddr.String(), "username", username)

	// 5. The rest of the data is the payload to be relayed
	payload := data[reader.Size()-int64(reader.Len()):]
	if len(payload) == 0 {
		s.logger.Debug("dropping empty UDP payload after auth", "from", clientAddr.String())
		return
	}

	// TODO: Implement the relay logic to forward the payload to its destination.
	s.logger.Debug("UDP payload ready for relay", "from", clientAddr.String(), "payload_size", len(payload))
}

// authenticate checks if the provided credentials are valid.
func (s *Server) authenticate(username, password string) bool {
	for _, user := range s.config.Users {
		if user.Username == username && user.Password == password {
			return true
		}
	}
	return false
}

// readLVString reads a length-prefixed string from the reader.
func readLVString(r *bytes.Reader) (string, error) {
	length, err := r.ReadByte()
	if err != nil {
		return "", fmt.Errorf("failed to read length: %w", err)
	}

	if r.Len() < int(length) {
		return "", fmt.Errorf("not enough data for string of length %d", length)
	}

	strBytes := make([]byte, length)
	_, err = r.Read(strBytes)
	if err != nil {
		return "", fmt.Errorf("failed to read string data: %w", err)
	}

	return string(strBytes), nil
}
