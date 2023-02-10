package cache

import (
	"context"
	"crypto/sha1"
	b64 "encoding/base64"
	"fmt"
	"hash"
	"math/rand"
	"strings"
	"time"

	goCache "github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
)

type goStore struct {
	authExpiration    time.Duration
	aclExpiration     time.Duration
	authJitter        time.Duration
	aclJitter         time.Duration
	refreshExpiration bool
	client            *goCache.Cache
	h                 hash.Hash
}

const (
	defaultExpiration = 30
)

type Store interface {
	SetAuthRecord(ctx context.Context, username, password, granted string) error
	CheckAuthRecord(ctx context.Context, username, password string) (bool, bool)
	SetACLRecord(ctx context.Context, username, topic, clientid string, acc int, granted string) error
	CheckACLRecord(ctx context.Context, username, topic, clientid string, acc int) (bool, bool)
	SetTokenRecord(ctx context.Context, token string, username string) error
	GetTokenRecord(ctx context.Context, token string) (string, bool)
	SetAclArrayRecord(ctx context.Context, username string, acc string, aclArray []string) error
	GetAclArrayRecord(ctx context.Context, username string, acc string) ([]string, bool)
	Connect(ctx context.Context, reset bool) bool
	Close()
}

// NewGoStore initializes a cache using go-cache as the store.
func NewGoStore(authExpiration, aclExpiration, authJitter, aclJitter time.Duration, refreshExpiration bool) *goStore {
	// TODO: support hydrating the cache to retain previous values.

	return &goStore{
		authExpiration:    authExpiration,
		aclExpiration:     aclExpiration,
		authJitter:        authJitter,
		aclJitter:         aclJitter,
		refreshExpiration: refreshExpiration,
		client:            goCache.New(time.Second*defaultExpiration, time.Second*(defaultExpiration*2)),
		h:                 sha1.New(),
	}
}

func toAuthRecord(username, password string, h hash.Hash) string {
	sum := h.Sum([]byte(fmt.Sprintf("auth-%s-%s", username, password)))
	log.Debugf("to auth record: %v\n", sum)
	return b64.StdEncoding.EncodeToString(sum)
}

func toACLRecord(username, topic, clientid string, acc int, h hash.Hash) string {
	sum := h.Sum([]byte(fmt.Sprintf("acl-%s-%s-%s-%d", username, topic, clientid, acc)))
	log.Debugf("to auth record: %v\n", sum)
	return b64.StdEncoding.EncodeToString(sum)
}

// Return an expiration duration with a jitter added, i.e the actual expiration is in the range [expiration - jitter, expiration + jitter].
// If no expiration was set or jitter > expiration, then any negative value will yield 0 instead.
func expirationWithJitter(expiration, jitter time.Duration) time.Duration {
	if jitter == 0 {
		return expiration
	}

	result := expiration + time.Duration(rand.Int63n(int64(jitter)*2)-int64(jitter))
	if result < 0 {
		return 0
	}

	return result
}

// Connect flushes the cache if reset is set.
func (s *goStore) Connect(ctx context.Context, reset bool) bool {
	log.Infoln("started go-cache")
	if reset {
		s.client.Flush()
		log.Infoln("flushed go-cache")
	}
	return true
}

func (s *goStore) Close() {
	//TODO: support serializing cache for re hydration.
}

// CheckAuthRecord checks if the username/password pair is present in the cache. Return if it's present and, if so, if it was granted privileges
func (s *goStore) CheckAuthRecord(ctx context.Context, username, password string) (bool, bool) {
	record := toAuthRecord(username, password, s.h)
	return s.checkRecord(ctx, record, expirationWithJitter(s.authExpiration, s.authJitter))
}

// CheckAclCache checks if the username/topic/clientid/acc mix is present in the cache. Return if it's present and, if so, if it was granted privileges.
func (s *goStore) CheckACLRecord(ctx context.Context, username, topic, clientid string, acc int) (bool, bool) {
	record := toACLRecord(username, topic, clientid, acc, s.h)
	return s.checkRecord(ctx, record, expirationWithJitter(s.aclExpiration, s.aclJitter))
}

func (s *goStore) checkRecord(ctx context.Context, record string, expirationTime time.Duration) (bool, bool) {
	granted := false
	v, present := s.client.Get(record)

	if present {
		value, ok := v.(string)
		if ok && value == "true" {
			granted = true
		}

		if s.refreshExpiration {
			s.client.Set(record, value, expirationTime)
		}
	}
	return present, granted
}

// SetAuthRecord sets a pair, granted option and expiration time.
func (s *goStore) SetAuthRecord(ctx context.Context, username, password string, granted string) error {
	record := toAuthRecord(username, password, s.h)
	s.client.Set(record, granted, expirationWithJitter(s.authExpiration, s.authJitter))

	return nil
}

// SetAclCache sets a mix, granted option and expiration time.
func (s *goStore) SetACLRecord(ctx context.Context, username, topic, clientid string, acc int, granted string) error {
	record := toACLRecord(username, topic, clientid, acc, s.h)
	s.client.Set(record, granted, expirationWithJitter(s.aclExpiration, s.aclJitter))

	return nil
}

// SetTokenRecord sets a token as key, username as value
func (s *goStore) SetTokenRecord(ctx context.Context, token string, username string) error {
	record := toAuthRecord(token, "", s.h)
	// log.Errorf("SetTokenRecord: %s\n", token)
	// log.Errorf("SetTokenRecord: %s\n", username)
	s.client.Set(record, username, expirationWithJitter(s.aclExpiration, s.aclJitter))
	return nil
}

// CheckAuthRecord get the username from the token
func (s *goStore) GetTokenRecord(ctx context.Context, token string) (string, bool) {
	record := toAuthRecord(token, "", s.h)

	v, present := s.client.Get(record)
	if present {
		value, ok := v.(string)
		// log.Errorf("GetTokenRecord: %s\n", token)
		// log.Errorf("GetTokenRecord: %s\n", value)
		if ok {
			return value, true
		}

		if s.refreshExpiration {
			s.client.Set(record, value, expirationWithJitter(s.authExpiration, s.authJitter))
		}
	}

	return "", false
}

// SetAclListRecord sets a token as key, Acl list as value
func (s *goStore) SetAclArrayRecord(ctx context.Context, username string, acc string, aclArray []string) error {
	record := toAuthRecord(username, acc, s.h)
	aclString := strings.Join(aclArray, " ")
	// log.Errorf("SetAclArrayRecord: %s\n", username)
	// log.Errorf("SetAclArrayRecord: %s\n", aclString)
	s.client.Set(record, aclString, expirationWithJitter(s.aclExpiration, s.aclJitter))
	return nil
}

// CheckAuthRecord get the username from the token
func (s *goStore) GetAclArrayRecord(ctx context.Context, username string, acc string) ([]string, bool) {
	record := toAuthRecord(username, acc, s.h)

	v, present := s.client.Get(record)
	if present {
		value, ok := v.(string)
		// log.Errorf("GetAclArrayRecord: %s\n", username)
		// log.Errorf("GetAclArrayRecord: %s\n", value)
		if ok {
			aclArray := strings.Split(value, " ")
			return aclArray, true
		}

		if s.refreshExpiration {
			s.client.Set(record, value, expirationWithJitter(s.authExpiration, s.authJitter))
		}
	}

	return nil, false
}
