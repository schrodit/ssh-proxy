package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"

	"github.com/schrodit/ssh-proxy/pkg/config"
	"github.com/schrodit/ssh-proxy/pkg/types"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type challengeCall struct {
	name        string
	instruction string
	questions   []string
	echos       []bool
}

type stubKeyboardInteractiveChallenger struct {
	answers [][]string
	calls   []challengeCall
}

func (s *stubKeyboardInteractiveChallenger) Challenge(name, instruction string, questions []string, echos []bool) ([]string, error) {
	s.calls = append(s.calls, challengeCall{
		name:        name,
		instruction: instruction,
		questions:   append([]string(nil), questions...),
		echos:       append([]bool(nil), echos...),
	})

	answer := s.answers[0]
	s.answers = s.answers[1:]
	return append([]string(nil), answer...), nil
}

var _ = Describe("Keyboard Interactive Authentication", func() {
	Describe("authenticateKeyboardInteractive", func() {
		It("authenticates after a successful challenge round", func() {
			sessionID := []byte{0xde, 0xad, 0xbe, 0xef}
			challenger := &stubKeyboardInteractiveChallenger{
				answers: [][]string{{"654321"}},
			}

			requests := make([]types.WebhookKeyboardInteractiveAuthRequest, 0, 2)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer r.Body.Close()

				var req types.WebhookKeyboardInteractiveAuthRequest
				err := json.NewDecoder(r.Body).Decode(&req)
				Expect(err).NotTo(HaveOccurred())
				requests = append(requests, req)

				switch len(requests) {
				case 1:
					w.WriteHeader(http.StatusAccepted)
					err = json.NewEncoder(w).Encode(types.WebhookKeyboardInteractiveResponse{
						Name:        "MFA",
						Instruction: "Enter your one-time code",
						Questions:   []string{"OTP"},
						Echos:       []bool{false},
					})
					Expect(err).NotTo(HaveOccurred())
				case 2:
					w.WriteHeader(http.StatusOK)
				default:
					Fail("unexpected request count")
				}
			}))
			defer server.Close()

			perms, err := authenticateKeyboardInteractive("alice", sessionID, &config.WebhookConfig{URL: server.URL}, challenger)
			Expect(err).NotTo(HaveOccurred())
			Expect(perms).NotTo(BeNil())
			Expect(perms.Extensions).To(HaveKeyWithValue("username", "alice"))

			Expect(challenger.calls).To(HaveLen(1))
			Expect(challenger.calls[0]).To(Equal(challengeCall{
				name:        "MFA",
				instruction: "Enter your one-time code",
				questions:   []string{"OTP"},
				echos:       []bool{false},
			}))

			Expect(requests).To(HaveLen(2))
			Expect(requests[0].Username).To(Equal("alice"))
			Expect(requests[0].AuthType).To(Equal("keyboard_interactive"))
			Expect(requests[0].SessionID).To(Equal("deadbeef"))
			Expect(requests[0].ChallengeRound).To(Equal(0))
			Expect(requests[0].Answers).To(BeEmpty())
			Expect(requests[1].ChallengeRound).To(Equal(1))
			Expect(requests[1].Answers).To(Equal([]string{"654321"}))
		})

		It("returns nil permissions when the webhook denies the authentication", func() {
			challenger := &stubKeyboardInteractiveChallenger{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			}))
			defer server.Close()

			perms, err := authenticateKeyboardInteractive("alice", []byte("session"), &config.WebhookConfig{URL: server.URL}, challenger)
			Expect(err).NotTo(HaveOccurred())
			Expect(perms).To(BeNil())
			Expect(challenger.calls).To(BeEmpty())
		})

		It("rejects challenge responses with invalid echo configuration", func() {
			challenger := &stubKeyboardInteractiveChallenger{
				answers: [][]string{{"654321"}},
			}

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusAccepted)
				err := json.NewEncoder(w).Encode(types.WebhookKeyboardInteractiveResponse{
					Questions: []string{"OTP", "Backup code"},
					Echos:     []bool{false},
				})
				Expect(err).NotTo(HaveOccurred())
			}))
			defer server.Close()

			perms, err := authenticateKeyboardInteractive("alice", []byte("session"), &config.WebhookConfig{URL: server.URL}, challenger)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("echo flags"))
			Expect(perms).To(BeNil())
			Expect(challenger.calls).To(BeEmpty())
		})
	})
})
