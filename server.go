package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rgarcia/scheduleforlater.com/Godeps/_workspace/src/code.google.com/p/go-uuid/uuid"
	"github.com/rgarcia/scheduleforlater.com/Godeps/_workspace/src/github.com/gorilla/context"
	"github.com/rgarcia/scheduleforlater.com/Godeps/_workspace/src/github.com/gorilla/schema"
	"github.com/rgarcia/scheduleforlater.com/Godeps/_workspace/src/github.com/kidstuff/mongostore"
	mailgun "github.com/rgarcia/scheduleforlater.com/Godeps/_workspace/src/github.com/mailgun/mailgun-go"
	"github.com/rgarcia/scheduleforlater.com/Godeps/_workspace/src/gopkg.in/mgo.v2"
	"github.com/rgarcia/scheduleforlater.com/Godeps/_workspace/src/gopkg.in/mgo.v2/bson"

	netcontext "github.com/rgarcia/scheduleforlater.com/Godeps/_workspace/src/golang.org/x/net/context"
	"github.com/rgarcia/scheduleforlater.com/Godeps/_workspace/src/golang.org/x/oauth2"
	"github.com/rgarcia/scheduleforlater.com/Godeps/_workspace/src/golang.org/x/oauth2/google"
	calendar "github.com/rgarcia/scheduleforlater.com/Godeps/_workspace/src/google.golang.org/api/calendar/v3"
	googlebasic "github.com/rgarcia/scheduleforlater.com/Godeps/_workspace/src/google.golang.org/api/oauth2/v2"
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
	MessageID         string `schema:"Message-Id"`
}

// User of the program has an email, calendar, and some preferences.
type User struct {
	ID        bson.ObjectId `bson:"_id"`
	FirstName string        `bson:"first_name"`
	LastName  string        `bson:"last_name"`
	Email     string        `bson:"email"`
	GCal      struct {
		Email        string `bson:"email"`
		AccessToken  string `bson:"access_token"`
		RefreshToken string `bson:"refresh_token"`
	} `bson:"gcal"`
	Prefs struct {
		StartTime time.Time `bson:"start_time"`
		EndTime   time.Time `bson:"end_time"`
	}
}

// Verification happens on first email to the service. Store the email sent--subject and directions--for processing later.
type Verification struct {
	ID         bson.ObjectId `bson:"_id"`
	Email      string        `bson:"email"`
	Subject    string        `bson:"subject"`
	MessageID  string        `bson:"message_id"`
	Directions string        `bson:"directions"`
	Key        string        `bson:"key"`
	Timestamp  time.Time     `bson:"timestamp"`
}

type interval struct {
	Start time.Time
	End   time.Time
}

// Scorer assigns utility to a meeting slot.
type Scorer interface {
	Score(slot interval) float64
}

// UserPreferencesScorer scores a meeting slot based on whether it fits a user's preferences.
type UserPreferencesScorer struct {
	User User
}

// Score is -1000 if it falls outside of their work day, 0 if it fits.
func (u UserPreferencesScorer) Score(slot interval) float64 {
	// if this slot falls outside of user's preference for start/end time of the day, -1000 points
	// Convert times to floats for easy comparison
	userPrefStart := float64(u.User.Prefs.StartTime.Hour()) + float64(u.User.Prefs.StartTime.Minute())/60.0
	userPrefEnd := float64(u.User.Prefs.EndTime.Hour()) + float64(u.User.Prefs.EndTime.Minute())/60.0
	slotStart := float64(slot.Start.Hour()) + float64(slot.Start.Minute())/60.0
	slotEnd := float64(slot.End.Hour()) + float64(slot.End.Minute())/60.0
	if userPrefEnd > userPrefStart {
		// userPrefs fall in the same UTC day
		if slotStart < slotEnd {
			// slot does not span
			if (slotStart >= userPrefStart) && (slotEnd <= userPrefEnd) {
				return 0.0
			} else {
				return -1000.0
			}
		} else {
			// slot spans--impossible to fit preferences
			return -1000.0
		}
	} else {
		// userPrefs span a UTC day
		if slotStart < slotEnd {
			// slot does not span, simple case
			if (userPrefStart <= slotStart) || (userPrefEnd >= slotEnd) {
				return 0.0
			} else {
				return -1000.0
			}
		} else {
			if (userPrefStart <= slotStart) && (userPrefEnd >= slotEnd) {
				return 0.0
			} else {
				return -1000.0
			}
		}
	}
}

type slotRank struct {
	Slot  interval
	Score float64
}

type byRank []slotRank

func (r byRank) Len() int           { return len(r) }
func (r byRank) Swap(i, j int)      { r[i], r[j] = r[j], r[i] }
func (r byRank) Less(i, j int) bool { return r[i].Score < r[j].Score }

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

	// sendandreceiveaddress is where users send emails and where we send emails from
	var sendandreceiveaddress string
	if sendandreceiveaddress = os.Getenv("SEND_AND_RECEIVE_ADDRESS"); sendandreceiveaddress == "" {
		log.Fatal("must set SEND_AND_RECEIVE_ADDRESS")
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

	var googleClientID string
	if googleClientID = os.Getenv("GOOGLE_CLIENT_ID"); googleClientID == "" {
		log.Fatal("must set GOOGLE_CLIENT_ID")
	}

	var googleClientSecret string
	if googleClientSecret = os.Getenv("GOOGLE_CLIENT_SECRET"); googleClientSecret == "" {
		log.Fatal("must set GOOGLE_CLIENT_SECRET")
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

	oauth2config := &oauth2.Config{
		ClientID:     googleClientID,
		ClientSecret: googleClientSecret,
		Endpoint:     google.Endpoint,
		RedirectURL:  fmt.Sprintf("https://%s/oauth2/google", host),
		Scopes:       []string{calendar.CalendarScope, googlebasic.UserinfoEmailScope, googlebasic.UserinfoProfileScope},
	}

	// required for some stuff. don't 100% understand
	ctx := netcontext.Background()

	scheduleForLater := func(from string, user User, subject string, directions string, messageID string) {
		sendEmail := func(text string) {
			if id, mes, err := mg.Send(mailgun.NewMessage(
				from, // from
				fmt.Sprintf("Re: %s", subject),
				text,
				user.Email,
			)); err != nil {
				log.Printf("error: unable to send user email: %s", err)
			} else {
				log.Printf("sent email %s %s", mes, id)
			}
		}

		// parse directions into number of minutes and interval within which to schedule
		var timeRangeForMtg interval
		var mtgDuration time.Duration
		func() {
			usage := "[n] minutes next [n] [hours|days]"
			directionparts := strings.Split(directions, " ")
			if len(directionparts) != 5 || directionparts[1] != "minutes" || directionparts[2] != "next" || !(directionparts[4] == "hours" || directionparts[4] == "days") {
				sendEmail(fmt.Sprintf("Could not parse directions. Directions must be of the form '%s'.", usage))
				return
			}
			nminutes, err := strconv.Atoi(directionparts[0])
			if err != nil {
				sendEmail(fmt.Sprintf("Could not parse directions. Directions must be of the form '%s'.", usage))
				return
			}
			mtgDuration = time.Duration(nminutes) * time.Minute
			nduration, err := strconv.Atoi(directionparts[3])
			if err != nil {
				sendEmail(fmt.Sprintf("Could not parse directions. Directions must be of the form '%s'.", usage))
				return
			}
			timeRangeForMtg.Start = time.Now()
			if directionparts[4] == "hours" {
				timeRangeForMtg.End = timeRangeForMtg.Start.Add(time.Duration(nduration) * time.Hour)
			} else if directionparts[4] == "days" {
				timeRangeForMtg.End = timeRangeForMtg.Start.Add(time.Duration(nduration) * 24 * time.Hour)
			}
			log.Printf("making a meeting sometime between %s and %s", timeRangeForMtg.Start, timeRangeForMtg.End)
		}()

		// enumerate all potential meeting slots starting on 15 minute marks
		mark := 15 * time.Minute
		var mtgSlots []interval
		func() {
			mtgSlotStart := timeRangeForMtg.Start.Add(mark).Round(mark) // round up to next starting time
			for {
				mtgSlotEnd := mtgSlotStart.Add(mtgDuration)
				if mtgSlotEnd.After(timeRangeForMtg.End) {
					break
				}
				mtgSlots = append(mtgSlots, interval{Start: mtgSlotStart, End: mtgSlotEnd})
				log.Print(mtgSlotStart, mtgSlotEnd)
				mtgSlotStart = mtgSlotStart.Add(mark)
			}
		}()

		// query for times when we're busy in the range
		var busySlots []interval
		client := oauth2config.Client(ctx, &oauth2.Token{
			AccessToken:  user.GCal.AccessToken,
			RefreshToken: user.GCal.RefreshToken,
			Expiry:       time.Now().Add(-time.Hour), // TODO: store expiry so that we don't have to assume always expired
		})
		svc, err := calendar.New(client)
		if err != nil {
			log.Printf("error initiating calendar service: %s", err)
			sendEmail("Error initiating calendar service. Please try again.")
			return
		}
		calapitimefmt := "2006-01-02T15:04:05-0700"
		func() {
			freebusy, err := calendar.NewFreebusyService(svc).Query(&calendar.FreeBusyRequest{
				Items: []*calendar.FreeBusyRequestItem{
					&calendar.FreeBusyRequestItem{Id: user.GCal.Email},
				},
				TimeMin: timeRangeForMtg.Start.Format(calapitimefmt),
				TimeMax: timeRangeForMtg.End.Format(calapitimefmt),
			}).Do()
			if err != nil {
				log.Printf("error getting free/busy from calendar: %s", err)
				sendEmail("Error getting free/busy from calendar. Please try again.")
				return
			}
			fbcalendar, ok := freebusy.Calendars[user.GCal.Email]
			if !ok {
				log.Printf("error: incorrectly assumed user had calendar named after email.")
				sendEmail(fmt.Sprintf("Oh no! The service currently only works if you have a calendar named '%s' that we can query for open slots and add events to.", user.GCal.Email))
				return
			}
			if len(fbcalendar.Errors) != 0 {
				for _, err := range fbcalendar.Errors {
					log.Printf("error: domain: %s reason: %s", err.Domain, err.Reason)
				}
				sendEmail("We ran into a problem retrieving free/busy data. Please try sending again.")
				return
			}
			log.Printf("free busy %#v", freebusy)
			for _, busy := range fbcalendar.Busy {
				var i interval
				i.Start, _ = time.Parse("2006-01-02T15:04:05Z", busy.Start)
				i.End, _ = time.Parse("2006-01-02T15:04:05Z", busy.End)
				busySlots = append(busySlots, i)
				log.Printf("busy from %s to %s", i.Start, i.End)
			}
		}()

		// rank feasible blocks of time based on the following criteria:
		// - not within user's preferences => -1000 points. In the future might be less of a penalty if close to preferences e.g. ok to have a mtg go a little bit past EOD
		// - distance to midpoint of [timeRangeForMtg.Start, timeRangeForMtg.End], where low distance == good
		//   i.e. if it's right at the midpoint, 1 point
		//        if it's right at the start or end, 0 points
		// - contiguous with other meetings. If a slot's end time matches with the start of another meeting or a slot's start time matches with the end of another meeting, +1 pt.
		// ... future other criteria
		var slotRanks []slotRank
		midpointScore := func(slot interval) float64 {
			// theory: if you say "next 48 hours" your ideal time is 24 hours from now
			// thus, give 0 points to things furthest from the midpoint, and 1 point to things closest
			midpoint := func(i interval) time.Time {
				return i.Start.Add(i.End.Sub(i.Start) / 2)
			}
			midpointOfRange := midpoint(timeRangeForMtg)
			rangeLength := float64(timeRangeForMtg.End.Sub(timeRangeForMtg.Start))
			midpointOfSlot := midpoint(slot)
			return 1.0 - 2*math.Abs(float64(midpointOfSlot.Sub(midpointOfRange)))/rangeLength
		}
		contiguousScore := func(slot interval) float64 {
			for _, busySlot := range busySlots {
				if slot.Start.Equal(busySlot.End) || slot.End.Equal(busySlot.Start) {
					return 1.0
				}
			}
			return 0.0
		}
		for _, mtgSlot := range mtgSlots {
			score := UserPreferencesScorer{User: user}.Score(mtgSlot) + midpointScore(mtgSlot) + contiguousScore(mtgSlot)
			slotRanks = append(slotRanks, slotRank{Slot: mtgSlot, Score: score})
		}
		sort.Sort(sort.Reverse(byRank(slotRanks)))
		for _, slotRank := range slotRanks {
			log.Printf("slot: %s %s score: %f", slotRank.Slot.Start, slotRank.Slot.End, slotRank.Score)
		}

		// schedule the mtg
		mtgStart := slotRanks[0].Slot.Start
		mtgEnd := slotRanks[0].Slot.End
		event, err := calendar.NewEventsService(svc).Insert(user.GCal.Email, &calendar.Event{
			Attendees: []*calendar.EventAttendee{
				&calendar.EventAttendee{Email: user.GCal.Email},
			},
			Description: fmt.Sprintf("https://mail.google.com/mail/?authuser=%s#search/%s",
				user.GCal.Email,
				url.QueryEscape(fmt.Sprintf("rfc822msgid:%s", messageID))), // link to email
			Start:   &calendar.EventDateTime{DateTime: mtgStart.Format(calapitimefmt)},
			End:     &calendar.EventDateTime{DateTime: mtgEnd.Format(calapitimefmt)},
			Summary: subject,
		}).SendNotifications(true).Do()
		if err != nil {
			log.Printf("error creating event: %s", err)
			sendEmail("Error creating calendar event. Please try again.")
			return
		}

		// event will have start time in their time zone
		eventStart, err := time.Parse("2006-01-02T15:04:05-07:00", event.Start.DateTime)
		if err != nil {
			log.Printf("error parsing event start time: %s", err)
			sendEmail("Created calendar event, but could not parse start time. Please report this error.")
			return
		}
		sendEmail(fmt.Sprintf("I scheduled you to handle this email at %s.", eventStart.Format("Monday, January 2 3:04pm -0700")))
	}

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
					MessageID:  payload.MessageID,
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
					sendandreceiveaddress,                  // from
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

		// pre-existing user: handle directions
		scheduleForLater(sendandreceiveaddress, user, payload.Subject, directions, payload.MessageID)

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
		session.Values["messageID"] = verification.MessageID
		session.Values["googleOAuth2State"] = uuid.New()
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
		fmt.Fprintf(w, "<html><body>Thanks! Please connect this email (%s) with the Google Calendar account you'd like to use by clicking <a href='%s'>here</a>.</body></html>",
			verification.Email, oauth2config.AuthCodeURL(session.Values["googleOAuth2State"].(string), oauth2.AccessTypeOffline, oauth2.ApprovalForce))
	})

	http.HandleFunc("/oauth2/google", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.Header().Set("Allow", "GET")
			http.Error(w, "only GET method is allowed", http.StatusMethodNotAllowed)
			return
		}

		// redeem code for access/refresh token, store in session
		session, _ := sessionstore.Get(r, sessionkey)
		if r.FormValue("state") != session.Values["googleOAuth2State"] {
			log.Printf("state mismatch")
			http.Error(w, "state mismatch, please try again", http.StatusInternalServerError)
			return
		}
		var code string
		if code = r.FormValue("code"); code == "" {
			log.Printf("no code: %#v", r)
			http.Error(w, "no code, please try again", http.StatusBadRequest)
			return
		}
		token, err := oauth2config.Exchange(ctx, code)
		if err != nil {
			log.Printf("error redeeming code for token: %s", err)
			http.Error(w, "error getting token, please try again", http.StatusInternalServerError)
			return
		}
		session.Values["access_token"] = token.AccessToken
		session.Values["refresh_token"] = token.RefreshToken
		if err := session.Save(r, w); err != nil {
			log.Printf("error saving session: %s", err)
			http.Error(w, "internal error saving session", http.StatusInternalServerError)
			return
		}

		// ask user to set preferences
		fmt.Fprintf(w, `<html><body>Almost there.
Please give us the earliest and latest time you'd like to schedule something.
<br/><br/>
<form name="userprefs" action="/setup" method="POST">
  Start time:
  <select name="start-time">
    <option value="12:00am">12:00am</option>
    <option value="12:30am">12:30am</option>
    <option value="1:00am">1:00am</option>
    <option value="1:30am">1:30am</option>
    <option value="2:00am">2:00am</option>
    <option value="2:30am">2:30am</option>
    <option value="3:00am">3:00am</option>
    <option value="3:30am">3:30am</option>
    <option value="4:00am">4:00am</option>
    <option value="4:30am">4:30am</option>
    <option value="5:00am">5:00am</option>
    <option value="5:30am">5:30am</option>
    <option value="6:00am">6:00am</option>
    <option value="6:30am">6:30am</option>
    <option value="7:00am">7:00am</option>
    <option value="7:30am">7:30am</option>
    <option value="8:00am">8:00am</option>
    <option value="8:30am">8:30am</option>
    <option value="9:00am" selected="selected">9:00am</option>
    <option value="9:30am">9:30am</option>
    <option value="10:00am">10:00am</option>
    <option value="10:30am">10:30am</option>
    <option value="11:00am">11:00am</option>
    <option value="11:30am">11:30am</option>
    <option value="12:00pm">12:00pm</option>
    <option value="12:30pm">12:30pm</option>
    <option value="1:00pm">1:00pm</option>
    <option value="1:30pm">1:30pm</option>
    <option value="2:00pm">2:00pm</option>
    <option value="2:30pm">2:30pm</option>
    <option value="3:00pm">3:00pm</option>
    <option value="3:30pm">3:30pm</option>
    <option value="4:00pm">4:00pm</option>
    <option value="4:30pm">4:30pm</option>
    <option value="5:00pm">5:00pm</option>
    <option value="5:30pm">5:30pm</option>
    <option value="6:00pm">6:00pm</option>
    <option value="6:30pm">6:30pm</option>
    <option value="7:00pm">7:00pm</option>
    <option value="7:30pm">7:30pm</option>
    <option value="8:00pm">8:00pm</option>
    <option value="8:30pm">8:30pm</option>
    <option value="9:00pm">9:00pm</option>
    <option value="9:30pm">9:30pm</option>
    <option value="10:00pm">10:00pm</option>
    <option value="10:30pm">10:30pm</option>
    <option value="11:00pm">11:00pm</option>
    <option value="11:30pm">11:30pm</option>
  </select>
  <br/><br/>
  End time:
  <select name="end-time">
    <option value="12:00am">12:00am</option>
    <option value="12:30am">12:30am</option>
    <option value="1:00am">1:00am</option>
    <option value="1:30am">1:30am</option>
    <option value="2:00am">2:00am</option>
    <option value="2:30am">2:30am</option>
    <option value="3:00am">3:00am</option>
    <option value="3:30am">3:30am</option>
    <option value="4:00am">4:00am</option>
    <option value="4:30am">4:30am</option>
    <option value="5:00am">5:00am</option>
    <option value="5:30am">5:30am</option>
    <option value="6:00am">6:00am</option>
    <option value="6:30am">6:30am</option>
    <option value="7:00am">7:00am</option>
    <option value="7:30am">7:30am</option>
    <option value="8:00am">8:00am</option>
    <option value="8:30am">8:30am</option>
    <option value="9:00am">9:00am</option>
    <option value="9:30am">9:30am</option>
    <option value="10:00am">10:00am</option>
    <option value="10:30am">10:30am</option>
    <option value="11:00am">11:00am</option>
    <option value="11:30am">11:30am</option>
    <option value="12:00pm">12:00pm</option>
    <option value="12:30pm">12:30pm</option>
    <option value="1:00pm">1:00pm</option>
    <option value="1:30pm">1:30pm</option>
    <option value="2:00pm">2:00pm</option>
    <option value="2:30pm">2:30pm</option>
    <option value="3:00pm">3:00pm</option>
    <option value="3:30pm">3:30pm</option>
    <option value="4:00pm">4:00pm</option>
    <option value="4:30pm">4:30pm</option>
    <option value="5:00pm" selected="selected">5:00pm</option>
    <option value="5:30pm">5:30pm</option>
    <option value="6:00pm">6:00pm</option>
    <option value="6:30pm">6:30pm</option>
    <option value="7:00pm">7:00pm</option>
    <option value="7:30pm">7:30pm</option>
    <option value="8:00pm">8:00pm</option>
    <option value="8:30pm">8:30pm</option>
    <option value="9:00pm">9:00pm</option>
    <option value="9:30pm">9:30pm</option>
    <option value="10:00pm">10:00pm</option>
    <option value="10:30pm">10:30pm</option>
    <option value="11:00pm">11:00pm</option>
    <option value="11:30pm">11:30pm</option>
  </select>
  <br/><br/>
  Time zone:
  <select name="time-zone">
    <option value="-1200">-1200</option>
    <option value="-1100">-1100</option>
    <option value="-1000">-1000</option>
    <option value="-0900">-0900</option>
    <option value="-0700" selected="selected">-0700</option>
    <option value="-0600">-0600</option>
    <option value="-0500">-0500</option>
    <option value="-0400">-0400</option>
    <option value="-0300">-0300</option>
    <option value="-0200">-0200</option>
    <option value="-0100">-0100</option>
    <option value="+0000">+0000</option>
    <option value="+0100">+0100</option>
    <option value="+0200">+0200</option>
    <option value="+0300">+0300</option>
    <option value="+0400">+0400</option>
    <option value="+0500">+0500</option>
    <option value="+0600">+0600</option>
    <option value="+0700">+0700</option>
    <option value="+0800">+0800</option>
    <option value="+0900">+0900</option>
    <option value="+1000">+1000</option>
    <option value="+1100">+1100</option>
    <option value="+1200">+1200</option>
  </select>
  <br/><br/>
  <input type="submit" value="Submit">
</form>
</body>
</html>
`)
	})

	http.HandleFunc("/setup", func(w http.ResponseWriter, r *http.Request) {
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

		// validate form data
		startTime := r.FormValue("start-time")
		endTime := r.FormValue("end-time")
		timeZone := r.FormValue("time-zone")
		if startTime == "" || endTime == "" || timeZone == "" {
			fmt.Fprintf(w, "Invalid submission. Hit back and try again.")
			return
		}
		start, err := time.Parse("3:00pm -0700", fmt.Sprintf("%s %s", startTime, timeZone))
		if err != nil {
			log.Printf("error parsing start time: %s", err)
			http.Error(w, "Internal error. Please go back and try again.", http.StatusInternalServerError)
			return
		}
		end, err := time.Parse("3:00pm -0700", fmt.Sprintf("%s %s", endTime, timeZone))
		if err != nil {
			log.Printf("error parsing end time: %s", err)
			http.Error(w, "Internal error. Please go back and try again.", http.StatusInternalServerError)
			return
		}
		if start.Equal(end) {
			http.Error(w, "Times must be different. Please go back and try again.", http.StatusBadRequest)
			return
		}
		if start.After(end) {
			http.Error(w, "Start time must come after end time. Please go back and try again.", http.StatusBadRequest)
			return
		}

		// create user
		session, _ := sessionstore.Get(r, sessionkey)
		client := oauth2config.Client(ctx, &oauth2.Token{AccessToken: session.Values["access_token"].(string)})
		svc, err := googlebasic.New(client)
		if err != nil {
			log.Printf("error initiating service: %s", err)
			http.Error(w, "Internal error. Please go back and try again.", http.StatusInternalServerError)
			return
		}
		userinfo, err := googlebasic.NewUserinfoV2Service(svc).Me.Get().Do()
		if err != nil {
			log.Printf("error calling userinfo service: %s", err)
			http.Error(w, "Internal error. Please go back and try again.", http.StatusInternalServerError)
			return
		}
		user := User{
			ID:        bson.NewObjectId(),
			FirstName: userinfo.Given_name,
			LastName:  userinfo.Family_name,
			Email:     session.Values["email"].(string),
		}
		user.GCal.Email = userinfo.Email
		user.GCal.AccessToken = session.Values["access_token"].(string)
		user.GCal.RefreshToken = session.Values["refresh_token"].(string)
		user.Prefs.StartTime = start
		user.Prefs.EndTime = end

		if user.Email == "" || user.GCal.Email == "" || user.GCal.AccessToken == "" || user.GCal.RefreshToken == "" {
			log.Printf("user invalid: %#v", user)
			http.Error(w, "Internal error. Please go back and try again.", http.StatusInternalServerError)
			return
		}
		log.Printf("creating new user: %#v", user)
		if err := mgosession.DB("").C("users").Insert(user); err != nil {
			log.Printf("unable to insert user: %s", err)
			http.Error(w, "Internal error. Please go back and try again.", http.StatusInternalServerError)
			return
		}

		// process pending email that triggered setup process
		scheduleForLater(sendandreceiveaddress, user, session.Values["subject"].(string), session.Values["directions"].(string), session.Values["messageID"].(string))

		fmt.Fprintf(w, "Thanks! You're all set.")
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
