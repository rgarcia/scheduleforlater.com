package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/rgarcia/scheduleforlater.com/Godeps/_workspace/src/github.com/gorilla/schema"
	mailgun "github.com/rgarcia/scheduleforlater.com/Godeps/_workspace/src/github.com/mailgun/mailgun-go"
)

const MaxFormSize = 2 * 1024 * 1024

// MailgunRoutePayload is what Mailgun POSTs when a message is sent to the domain. See https://documentation.mailgun.com/user_manual.html#routes.
type MailgunRoutePayload struct {
	Recipient         string `schema:"recipient"`          // recipient of the message as reported by MAIL TO during SMTP chat.
	Sender            string `schema:"sender"`             // sender of the message as reported by MAIL FROM during SMTP chat. Note: this value may differ from From MIME header.
	From              string `schema:"from"`               // sender of the message as reported by From message header, for example “Bob Lee <blee@mailgun.net>”.
	Subject           string `schema:"subject"`            // subject string.
	BodyPlain         string `schema:"body-plain"`         // text version of the email. This field is always present. If the incoming message only has HTML body, Mailgun will create a text representation for you.
	StrippedText      string `schema:"stripped-text"`      // text version of the message without quoted parts and signature block (if found).
	StrippedSignature string `schema:"stripped-signature"` // the signature block stripped from the plain text message (if found).
	BodyHTML          string `schema:"body-html"`          // HTML version of the message, if message was multipart. Note that all parts of the message will be posted, not just text/html. For instance if a message arrives with “foo” part it will be posted as “body-foo”.
	StrippedHTML      string `schema:"stripped-html"`      // HTML version of the message, without quoted parts.
	Attachments       string `schema:"attachments"`        // contains a json list of metadata objects, one for each attachment, see below.
	MessageURL        string `schema:"message-url"`        // a URL that you can use to get and/or delete the message.
	Timestamp         int    `schema:"timestamp"`          // number of second passed since January 1, 1970 (see securing webhooks).
	Token             string `schema:"token"`              // randomly generated string with length 50 (see securing webhooks).
	Signature         string `schema:"signature"`          // string with hexadecimal digits generate by HMAC algorithm (see securing webhooks).
	MessageHeaders    string `schema:"message-headers"`    // list of all MIME headers dumped to a json string (order of headers preserved).
	ContentIDMap      string `schema:"content-id-map"`     // JSON-encoded dictionary which maps Content-ID (CID) of each attachment to the corresponding attachment-x parameter. This allows you to map posted attachments to tags like <img src='cid'> in the message body.
}

func main() {
	var port string
	if port = os.Getenv("PORT"); port == "" {
		log.Fatal("must set PORT")
	}

	var mailgunkey string
	if mailgunkey = os.Getenv("MAILGUN_KEY"); mailgunkey == "" {
		log.Fatal("must set MAILGUN_KEY")
	}

	var mailgunpublickey string
	if mailgunpublickey = os.Getenv("MAILGUN_PUBLIC_KEY"); mailgunpublickey == "" {
		log.Fatal("must set MAILGUN_PUBLIC_KEY")
	}

	var domain string
	if domain = os.Getenv("MAILGUN_DOMAIN"); domain == "" {
		log.Fatal("must set MAILGUN_DOMAIN")
	}

	mg := mailgun.NewMailgun(domain, mailgunkey, mailgunpublickey)

	payloadDecoder := schema.NewDecoder() // cache this globally per gorilla doc recommendation
	payloadDecoder.IgnoreUnknownKeys(true)
	http.HandleFunc("/mailgun", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.Header().Set("Allow", "POST")
			http.Error(w, "only POST method is allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			log.Printf("invalid form: %s", err)
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}

		// load it into a struct
		var payload MailgunRoutePayload
		if err := payloadDecoder.Decode(&payload, r.Form); err != nil {
			log.Printf("bad data: %s", err)
			http.Error(w, "bad data", http.StatusBadRequest)
			return
		}

		// verify that this came from mailgun
		if !verify(mailgunkey, fmt.Sprintf("%d", payload.Timestamp), payload.Token, payload.Signature) {
			http.Error(w, "bad signature", http.StatusForbidden)
			return
		}

		// parse the first line for what we need to do
		// TODO: actually do something
		directions := strings.SplitN(payload.StrippedText, "\n", 2)[0] // TODO: this is sloppy. needs nil/length check
		directions = strings.TrimSpace(directions)

		// reply to the message
		if mes, id, err := mg.Send(mailgun.NewMessage(
			payload.Recipient,                                 // from
			fmt.Sprintf("Re: %s", payload.Subject),            // subject
			fmt.Sprintf("Got your message: '%s'", directions), // text
			payload.From, // to
		)); err != nil {
			http.Error(w, "unable to send email", http.StatusInternalServerError)
			return
		} else {
			log.Printf("sent %s %s", mes, id)
		}

		fmt.Fprintf(w, "hello", html.EscapeString(r.URL.Path))
	})

	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func verify(key, timestamp, token, signature string) bool {
	h := hmac.New(sha256.New, []byte(key))
	io.WriteString(h, timestamp)
	io.WriteString(h, token)
	calcSig := h.Sum(nil)
	sig, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	if len(sig) != len(calcSig) {
		return false
	}

	return subtle.ConstantTimeCompare(sig, calcSig) == 1
}
