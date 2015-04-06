package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rgarcia/scheduleforlater.com/Godeps/_workspace/src/code.google.com/p/go-uuid/uuid"
	"github.com/rgarcia/scheduleforlater.com/Godeps/_workspace/src/github.com/gorilla/context"
	"github.com/rgarcia/scheduleforlater.com/Godeps/_workspace/src/github.com/gorilla/schema"
	"github.com/rgarcia/scheduleforlater.com/Godeps/_workspace/src/github.com/kidstuff/mongostore"
	mailgun "github.com/rgarcia/scheduleforlater.com/Godeps/_workspace/src/github.com/mailgun/mailgun-go"
	"github.com/rgarcia/scheduleforlater.com/Godeps/_workspace/src/gopkg.in/mgo.v2"
	"github.com/rgarcia/scheduleforlater.com/Godeps/_workspace/src/gopkg.in/mgo.v2/bson"
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

// User of the program has an email, calendar, and some preferences.
type User struct {
	ID        bson.ObjectId `bson:"_id"`
	FirstName string        `bson:"first_name"`
	LastName  string        `bson:"last_name"`
	Email     string        `bson:"email"`
	GCal      struct {
		AccessToken  string `bson:"access_token"`
		RefreshToken string `bson:"refresh_token"`
	} `bson:"gcal"`
	Prefs struct {
		StartTime *time.Time `bson:"start_time"`
		EndTime   *time.Time `bson:"end_time"`
	}
}

// Verification happens on first email to the service. Store the email sent--subject and directions--for processing later.
type Verification struct {
	ID         bson.ObjectId `bson:"_id"`
	Email      string        `bson:"email"`
	Subject    string        `bson:"subject"`
	Directions string        `bson:"directions"`
	Key        string        `bson:"key"`
	Timestamp  time.Time     `bson:"timestamp"`
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

	// host is where the server is running. It is used to create hyperlinks and for the cookie domain.
	var host string
	if host = os.Getenv("HOST"); host == "" {
		log.Fatal("must set HOST")
	}

	var cookiesecret string
	if cookiesecret = os.Getenv("COOKIE_SECRET"); cookiesecret == "" {
		log.Fatal("must set COOKIE_SECRET")
	}

	var sessionkey string
	if sessionkey = os.Getenv("SESSION_KEY"); sessionkey == "" {
		log.Fatal("must set SESSION_KEY")
	}

	var mongourl string
	if mongourl = os.Getenv("MONGO_URL"); mongourl == "" {
		log.Fatal("must set MONGO_URL")
	}

	mgosession, err := mgo.Dial(mongourl)
	if err != nil {
		log.Fatalf("could not connect to mongo: %s", err)
	}

	mg := mailgun.NewMailgun(domain, mailgunkey, mailgunpublickey)

	sessionstore := mongostore.NewMongoStore(mgosession.DB("").C("sessions"), 3600, true, []byte(cookiesecret))
	sessionstore.Options.Path = "/"

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
		directions := strings.SplitN(payload.StrippedText, "\n", 2)[0] // TODO: this is sloppy. needs nil/length check
		directions = strings.TrimSpace(directions)

		// load user info
		var user User
		if err := mgosession.DB("").C("users").Find(bson.M{"email": payload.Sender}).One(&user); err != nil {
			if err == mgo.ErrNotFound {
				// new user--initiate verification flow
				verification := Verification{
					ID:         bson.NewObjectId(),
					Email:      payload.Sender,
					Subject:    payload.Subject,
					Directions: directions,
					Key:        uuid.New(),
					Timestamp:  time.Now(),
				}
				if err := mgosession.DB("").C("verifications").Insert(verification); err != nil {
					// TODO: reply with error (please try again later)
					log.Printf("unable to insert: %s", err)
					http.Error(w, "unable to insert", http.StatusInternalServerError)
					return
				}
				if id, mes, err := mg.Send(mailgun.NewMessage(
					payload.Recipient,                      // from
					fmt.Sprintf("Re: %s", payload.Subject), // subject
					fmt.Sprintf("Thanks! Please verify this email address and connect it with Google "+
						"Calendar to get started: https://%s/verifications/%s. This link will expire in 24 hours.", host, verification.Key),
					payload.From, // to
				)); err != nil {
					log.Printf("unable to send welcome email: %s", err)
					http.Error(w, "unable to send welcome email", http.StatusInternalServerError)
					return
				} else {
					log.Printf("sent welcome email %s %s", mes, id)
					return
				}
			} else {
				// TODO: reply with error (please try again later)
				log.Printf("unable to search for user: %s", err)
				http.Error(w, "unable to search for user", http.StatusInternalServerError)
				return
			}
		}

		// pre-existing user: handle directiions
		// TODO

		fmt.Fprintf(w, "hello mailgun")
	})

	http.HandleFunc("/verifications/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.Header().Set("Allow", "GET")
			http.Error(w, "only GET method is allowed", http.StatusMethodNotAllowed)
			return
		}

		// store email, subject, directions in session
		session, _ := sessionstore.Get(r, sessionkey)
		verificationKey := strings.TrimPrefix(r.URL.Path, "/verifications/")
		var verification Verification
		if err := mgosession.DB("").C("verifications").Find(bson.M{"key": verificationKey}).
			One(&verification); err != nil {
			if err == mgo.ErrNotFound {
				log.Printf("verification link not found")
				http.Error(w, "verification link not found", http.StatusBadRequest)
				return
			} else {
				log.Printf("internal error finding verification: %s", err)
				http.Error(w, "internal error finding verification", http.StatusInternalServerError)
				return
			}
		}
		session.Values["email"] = verification.Email
		session.Values["subject"] = verification.Subject
		session.Values["directions"] = verification.Directions
		if err := session.Save(r, w); err != nil {
			log.Printf("error saving session: %s", err)
			http.Error(w, "internal error saving session", http.StatusInternalServerError)
			return
		}

		// delete verification from db
		if err := mgosession.DB("").C("verifications").RemoveId(verification.ID); err != nil {
			log.Printf("error removing verification: %s", err)
			http.Error(w, "internal error removing verification", http.StatusInternalServerError)
			return
		}

		// present google auth link
		// TODO
		fmt.Fprintf(w, "thanks")
	})

	http.HandleFunc("/dumpsession", func(w http.ResponseWriter, r *http.Request) {
		session, err := sessionstore.Get(r, sessionkey)
		if err != nil {
			log.Printf("error getting session: %s", err)
			http.Error(w, "internal error getting session", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "session data:\n%#v", session.Values)
	})

	// need ClearHandler when using gorilla sessions: http://www.gorillatoolkit.org/pkg/sessions
	log.Fatal(http.ListenAndServe(":"+port, context.ClearHandler(http.DefaultServeMux)))
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
