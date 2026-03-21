package proxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/schrodit/ssh-proxy/pkg/config"
	"golang.org/x/crypto/ssh"
)

type tcpipForwardRequest struct {
	Addr string
	Port uint32
}

type forwardedTCPIPPayload struct {
	Addr       string
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

type directTCPIPPayload struct {
	Addr       string
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

var _ = Describe("Port Forwarding", func() {
	It("proxies remote tcp forwards opened by the target back to the client", func() {
		tempDir := GinkgoT().TempDir()
		proxyHostKeyPath := filepath.Join(tempDir, "proxy_host_key")
		err := writePrivateKeyFile(proxyHostKeyPath)
		Expect(err).NotTo(HaveOccurred())

		targetHostKey, err := generateSigner()
		Expect(err).NotTo(HaveOccurred())

		targetListener, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())
		defer func() {
			Expect(targetListener.Close()).To(Succeed())
		}()

		targetConnCh := make(chan *ssh.ServerConn, 1)
		targetForwardCh := make(chan tcpipForwardRequest, 1)
		targetErrCh := make(chan error, 1)

		targetConfig := &ssh.ServerConfig{
			PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
				if conn.User() == "backend" && string(password) == "backend-secret" {
					return nil, nil
				}
				return nil, fmt.Errorf("unexpected target credentials for %s", conn.User())
			},
		}
		targetConfig.AddHostKey(targetHostKey)

		go func() {
			conn, err := targetListener.Accept()
			if err != nil {
				targetErrCh <- err
				return
			}
			defer func() {
				_ = conn.Close()
			}()

			sshConn, chans, reqs, err := ssh.NewServerConn(conn, targetConfig)
			if err != nil {
				targetErrCh <- err
				return
			}
			defer func() {
				_ = sshConn.Close()
			}()

			targetConnCh <- sshConn

			go func() {
				for newChannel := range chans {
					_ = newChannel.Reject(ssh.UnknownChannelType, "unsupported in test backend")
				}
			}()

			for req := range reqs {
				switch req.Type {
				case "tcpip-forward":
					var msg tcpipForwardRequest
					if err := ssh.Unmarshal(req.Payload, &msg); err != nil {
						targetErrCh <- err
						return
					}
					targetForwardCh <- msg
					if req.WantReply {
						if err := req.Reply(true, nil); err != nil {
							targetErrCh <- err
							return
						}
					}
				case "cancel-tcpip-forward":
					if req.WantReply {
						if err := req.Reply(true, nil); err != nil {
							targetErrCh <- err
							return
						}
					}
				default:
					if req.WantReply {
						if err := req.Reply(false, nil); err != nil {
							targetErrCh <- err
							return
						}
					}
				}
			}

			targetErrCh <- nil
		}()

		configPath := filepath.Join(tempDir, "config.yaml")
		configYAML := fmt.Sprintf(`routes:
- username: ide-user
  target:
    host: 127.0.0.1
    port: %d
    user: backend
    insecure: true
    auth:
      type: password
      password: backend-secret
  auth:
  - type: password
    password: client-secret
`, targetListener.Addr().(*net.TCPAddr).Port)
		err = os.WriteFile(configPath, []byte(configYAML), 0600)
		Expect(err).NotTo(HaveOccurred())

		configManager, err := config.NewConfigManager(configPath)
		Expect(err).NotTo(HaveOccurred())
		defer func() {
			Expect(configManager.Close()).To(Succeed())
		}()

		proxy := New(configManager, "127.0.0.1", 0, proxyHostKeyPath)

		proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())
		defer func() {
			Expect(proxyListener.Close()).To(Succeed())
		}()

		proxyDone := make(chan error, 1)
		go func() {
			conn, err := proxyListener.Accept()
			if err != nil {
				proxyDone <- err
				return
			}
			proxy.handleConnection(conn)
			proxyDone <- nil
		}()

		clientConfig := &ssh.ClientConfig{
			User:            "ide-user",
			Auth:            []ssh.AuthMethod{ssh.Password("client-secret")},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         5 * time.Second,
		}

		client, err := ssh.Dial("tcp", proxyListener.Addr().String(), clientConfig)
		Expect(err).NotTo(HaveOccurred())

		var targetConn *ssh.ServerConn
		Eventually(targetConnCh, "5s", "100ms").Should(Receive(&targetConn))

		forwardListener, err := client.Listen("tcp", "127.0.0.1:43123")
		Expect(err).NotTo(HaveOccurred())

		var forwardReq tcpipForwardRequest
		Eventually(targetForwardCh, "5s", "100ms").Should(Receive(&forwardReq))
		Expect(forwardReq).To(Equal(tcpipForwardRequest{
			Addr: "127.0.0.1",
			Port: 43123,
		}))

		acceptedConnCh := make(chan net.Conn, 1)
		acceptErrCh := make(chan error, 1)
		go func() {
			conn, err := forwardListener.Accept()
			if err != nil {
				acceptErrCh <- err
				return
			}
			acceptedConnCh <- conn
		}()

		forwardPayload := ssh.Marshal(&forwardedTCPIPPayload{
			Addr:       forwardReq.Addr,
			Port:       forwardReq.Port,
			OriginAddr: "127.0.0.1",
			OriginPort: 54321,
		})
		targetChannel, targetReqs, err := targetConn.OpenChannel("forwarded-tcpip", forwardPayload)
		Expect(err).NotTo(HaveOccurred())
		defer func() {
			_ = targetChannel.Close()
		}()
		go ssh.DiscardRequests(targetReqs)

		var acceptedConn net.Conn
		Eventually(acceptedConnCh, "5s", "100ms").Should(Receive(&acceptedConn))
		defer func() {
			_ = acceptedConn.Close()
		}()

		message := []byte("remote-forward-ok")
		messageCh := make(chan []byte, 1)
		messageErrCh := make(chan error, 1)
		go func() {
			buf := make([]byte, len(message))
			_, err := io.ReadFull(acceptedConn, buf)
			if err != nil {
				messageErrCh <- err
				return
			}
			messageCh <- buf
		}()

		_, err = targetChannel.Write(message)
		Expect(err).NotTo(HaveOccurred())

		var receivedMessage []byte
		Eventually(messageCh, "5s", "100ms").Should(Receive(&receivedMessage))
		Expect(string(receivedMessage)).To(Equal(string(message)))

		reply := []byte("ack")
		_, err = acceptedConn.Write(reply)
		Expect(err).NotTo(HaveOccurred())

		replyCh := make(chan []byte, 1)
		replyErrCh := make(chan error, 1)
		go func() {
			buf := make([]byte, len(reply))
			_, err := io.ReadFull(targetChannel, buf)
			if err != nil {
				replyErrCh <- err
				return
			}
			replyCh <- buf
		}()

		var receivedReply []byte
		Eventually(replyCh, "5s", "100ms").Should(Receive(&receivedReply))
		Expect(string(receivedReply)).To(Equal(string(reply)))
		Consistently(acceptErrCh, "200ms", "50ms").ShouldNot(Receive())
		Consistently(messageErrCh, "200ms", "50ms").ShouldNot(Receive())
		Consistently(replyErrCh, "200ms", "50ms").ShouldNot(Receive())

		Expect(forwardListener.Close()).To(Succeed())
		Expect(client.Close()).To(Succeed())

		var proxyErr error
		Eventually(proxyDone, "5s", "100ms").Should(Receive(&proxyErr))
		Expect(proxyErr).NotTo(HaveOccurred())

		var targetErr error
		Eventually(targetErrCh, "5s", "100ms").Should(Receive(&targetErr))
		Expect(targetErr).NotTo(HaveOccurred())
	})

	It("allows direct-tcpip channels while a session channel is still open", func() {
		tempDir := GinkgoT().TempDir()
		proxyHostKeyPath := filepath.Join(tempDir, "proxy_host_key")
		err := writePrivateKeyFile(proxyHostKeyPath)
		Expect(err).NotTo(HaveOccurred())

		echoListener, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())
		defer func() {
			_ = echoListener.Close()
		}()

		echoErrCh := make(chan error, 1)
		go func() {
			conn, err := echoListener.Accept()
			if err != nil {
				echoErrCh <- err
				return
			}
			defer func() {
				_ = conn.Close()
			}()

			_, err = io.Copy(conn, conn)
			if err != nil && err != io.EOF {
				echoErrCh <- err
				return
			}
			echoErrCh <- nil
		}()

		targetHostKey, err := generateSigner()
		Expect(err).NotTo(HaveOccurred())

		targetListener, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())
		defer func() {
			_ = targetListener.Close()
		}()

		targetErrCh := make(chan error, 1)
		targetConfig := &ssh.ServerConfig{
			PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
				if conn.User() == "backend" && string(password) == "backend-secret" {
					return nil, nil
				}
				return nil, fmt.Errorf("unexpected target credentials for %s", conn.User())
			},
		}
		targetConfig.AddHostKey(targetHostKey)

		go func() {
			conn, err := targetListener.Accept()
			if err != nil {
				targetErrCh <- err
				return
			}
			defer func() {
				_ = conn.Close()
			}()

			sshConn, chans, reqs, err := ssh.NewServerConn(conn, targetConfig)
			if err != nil {
				targetErrCh <- err
				return
			}
			defer func() {
				_ = sshConn.Close()
			}()

			go func() {
				for req := range reqs {
					if req.WantReply {
						_ = req.Reply(false, nil)
					}
				}
			}()

			channelErrCh := make(chan error, 2)
			for newChannel := range chans {
				switch newChannel.ChannelType() {
				case "session":
					channel, channelReqs, err := newChannel.Accept()
					if err != nil {
						targetErrCh <- err
						return
					}
					go func() {
						defer func() {
							_ = channel.Close()
						}()
						for req := range channelReqs {
							if req.WantReply {
								_ = req.Reply(req.Type == "shell", nil)
							}
						}
					}()
				case "direct-tcpip":
					var payload directTCPIPPayload
					if err := ssh.Unmarshal(newChannel.ExtraData(), &payload); err != nil {
						targetErrCh <- err
						return
					}

					upstream, err := net.Dial("tcp", net.JoinHostPort(payload.Addr, strconv.Itoa(int(payload.Port))))
					if err != nil {
						_ = newChannel.Reject(ssh.ConnectionFailed, err.Error())
						targetErrCh <- err
						return
					}

					channel, channelReqs, err := newChannel.Accept()
					if err != nil {
						_ = upstream.Close()
						targetErrCh <- err
						return
					}

					go ssh.DiscardRequests(channelReqs)
					go func() {
						defer func() {
							_ = channel.Close()
							_ = upstream.Close()
						}()
						_, err := io.Copy(channel, upstream)
						if err != nil && err != io.EOF {
							channelErrCh <- err
						}
					}()
					go func() {
						defer func() {
							_ = channel.Close()
							_ = upstream.Close()
						}()
						_, err := io.Copy(upstream, channel)
						if err != nil && err != io.EOF {
							channelErrCh <- err
						}
					}()
				default:
					_ = newChannel.Reject(ssh.UnknownChannelType, "unsupported in test backend")
				}
			}

			select {
			case err := <-channelErrCh:
				targetErrCh <- err
			default:
				targetErrCh <- nil
			}
		}()

		configPath := filepath.Join(tempDir, "config.yaml")
		configYAML := fmt.Sprintf(`routes:
- username: ide-user
  target:
    host: 127.0.0.1
    port: %d
    user: backend
    insecure: true
    auth:
      type: password
      password: backend-secret
  auth:
  - type: password
    password: client-secret
`, targetListener.Addr().(*net.TCPAddr).Port)
		err = os.WriteFile(configPath, []byte(configYAML), 0600)
		Expect(err).NotTo(HaveOccurred())

		configManager, err := config.NewConfigManager(configPath)
		Expect(err).NotTo(HaveOccurred())
		defer func() {
			_ = configManager.Close()
		}()

		proxy := New(configManager, "127.0.0.1", 0, proxyHostKeyPath)
		proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).NotTo(HaveOccurred())
		defer func() {
			_ = proxyListener.Close()
		}()

		proxyDone := make(chan error, 1)
		go func() {
			conn, err := proxyListener.Accept()
			if err != nil {
				proxyDone <- err
				return
			}
			proxy.handleConnection(conn)
			proxyDone <- nil
		}()

		clientConfig := &ssh.ClientConfig{
			User:            "ide-user",
			Auth:            []ssh.AuthMethod{ssh.Password("client-secret")},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         5 * time.Second,
		}

		client, err := ssh.Dial("tcp", proxyListener.Addr().String(), clientConfig)
		Expect(err).NotTo(HaveOccurred())
		defer func() {
			_ = client.Close()
		}()

		session, err := client.NewSession()
		Expect(err).NotTo(HaveOccurred())
		defer func() {
			_ = session.Close()
		}()
		Expect(session.Shell()).To(Succeed())

		dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		forwardedConn, err := client.DialContext(dialCtx, "tcp", echoListener.Addr().String())
		Expect(err).NotTo(HaveOccurred())
		defer func() {
			_ = forwardedConn.Close()
		}()

		message := []byte("concurrent-channel-ok")
		_, err = forwardedConn.Write(message)
		Expect(err).NotTo(HaveOccurred())

		buffer := make([]byte, len(message))
		_, err = io.ReadFull(forwardedConn, buffer)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(buffer)).To(Equal(string(message)))

		Expect(session.Close()).To(Succeed())
		Expect(client.Close()).To(Succeed())

		var proxyErr error
		Eventually(proxyDone, "5s", "100ms").Should(Receive(&proxyErr))
		Expect(proxyErr).NotTo(HaveOccurred())

		var targetErr error
		Eventually(targetErrCh, "5s", "100ms").Should(Receive(&targetErr))
		Expect(targetErr).NotTo(HaveOccurred())

		var echoErr error
		Eventually(echoErrCh, "5s", "100ms").Should(Receive(&echoErr))
		Expect(echoErr).NotTo(HaveOccurred())
	})
})

func writePrivateKeyFile(path string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return os.WriteFile(path, privateKeyPEM, 0600)
}

func generateSigner() (ssh.Signer, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return ssh.NewSignerFromKey(privateKey)
}
