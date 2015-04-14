package main

import (
	"testing"
	"time"
)

type UserPreferencesScoreTest struct {
	Pref  interval
	Slot  interval
	Score float64
}

func mustTimeParse(format string, t string) time.Time {
	tm, err := time.Parse(format, t)
	if err != nil {
		panic(err)
	}
	return tm
}

func TestUserPreferencesScore(t *testing.T) {
	tfmt := "2006-01-02T15:04:05Z"
	tests := []UserPreferencesScoreTest{
		// user preferences don't span a UTC day
		// slot doesn't span
		UserPreferencesScoreTest{
			Pref: interval{
				Start: mustTimeParse(tfmt, "0000-01-01T09:00:00Z"),
				End:   mustTimeParse(tfmt, "0000-01-01T17:00:00Z"),
			},
			Slot: interval{
				Start: mustTimeParse(tfmt, "2015-04-08T16:30:00Z"),
				End:   mustTimeParse(tfmt, "2015-04-08T17:00:00Z"),
			},
			Score: 0.0,
		},
		UserPreferencesScoreTest{
			Pref: interval{
				Start: mustTimeParse(tfmt, "0000-01-01T09:00:00Z"),
				End:   mustTimeParse(tfmt, "0000-01-01T17:00:00Z"),
			},
			Slot: interval{
				Start: mustTimeParse(tfmt, "2015-04-08T17:00:00Z"),
				End:   mustTimeParse(tfmt, "2015-04-08T17:30:00Z"),
			},
			Score: -1000.0,
		},

		// user preferences don't span a UTC day
		// slot does span
		UserPreferencesScoreTest{
			Pref: interval{
				Start: mustTimeParse(tfmt, "0000-01-01T09:00:00Z"),
				End:   mustTimeParse(tfmt, "0000-01-01T17:00:00Z"),
			},
			Slot: interval{
				Start: mustTimeParse(tfmt, "2015-04-08T23:30:00Z"),
				End:   mustTimeParse(tfmt, "2015-04-09T00:00:00Z"),
			},
			Score: -1000.0,
		},

		// user preferences span a UTC day
		// slot does not span
		UserPreferencesScoreTest{
			Pref: interval{
				Start: mustTimeParse(tfmt, "0000-01-01T20:00:00Z"),
				End:   mustTimeParse(tfmt, "0000-01-02T04:00:00Z"),
			},
			Slot: interval{
				Start: mustTimeParse(tfmt, "2015-04-08T03:30:00Z"),
				End:   mustTimeParse(tfmt, "2015-04-08T04:00:00Z"),
			},
			Score: 0.0,
		},
		UserPreferencesScoreTest{
			Pref: interval{
				Start: mustTimeParse(tfmt, "0000-01-01T20:00:00Z"),
				End:   mustTimeParse(tfmt, "0000-01-02T04:00:00Z"),
			},
			Slot: interval{
				Start: mustTimeParse(tfmt, "2015-04-08T04:00:00Z"),
				End:   mustTimeParse(tfmt, "2015-04-08T04:30:00Z"),
			},
			Score: -1000.0,
		},

		// user preferences span a UTC day
		// slot does span
		UserPreferencesScoreTest{
			Pref: interval{
				Start: mustTimeParse(tfmt, "0000-01-01T20:00:00Z"),
				End:   mustTimeParse(tfmt, "0000-01-02T04:00:00Z"),
			},
			Slot: interval{
				Start: mustTimeParse(tfmt, "2015-04-08T23:30:00Z"),
				End:   mustTimeParse(tfmt, "2015-04-09T00:00:00Z"),
			},
			Score: 0.0,
		},
		UserPreferencesScoreTest{
			Pref: interval{
				Start: mustTimeParse(tfmt, "0000-01-01T20:00:00Z"),
				End:   mustTimeParse(tfmt, "0000-01-02T00:15:00Z"),
			},
			Slot: interval{
				Start: mustTimeParse(tfmt, "2015-04-08T23:45:00Z"),
				End:   mustTimeParse(tfmt, "2015-04-08T00:30:00Z"),
			},
			Score: -1000.0,
		},

		// times sent to scorer do not have a uniform time zone
		UserPreferencesScoreTest{
			Pref: interval{
				Start: mustTimeParse("2006-01-02T15:04:05 -0700", "0000-01-01T09:00:00 -0700"),
				End:   mustTimeParse("2006-01-02T15:04:05 -0700", "0000-01-01T17:00:00 -0700"),
			},
			Slot: interval{
				Start: mustTimeParse(tfmt, "2015-04-15T15:30:00Z"),
				End:   mustTimeParse(tfmt, "2015-04-15T16:00:00Z"),
			},
			Score: -1000.0,
		},
	}
	for _, test := range tests {
		user := User{}
		user.Prefs.StartTime = test.Pref.Start
		user.Prefs.EndTime = test.Pref.End
		if got := (UserPreferencesScorer{User: user}).Score(test.Slot); got != test.Score {
			t.Errorf("got %f, expected %f. test case: %v", got, test.Score, test)
		}
	}
}
