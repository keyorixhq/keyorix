// query.go — URL query string builder used by remote list operations.
//
// Used internally by remote_secrets.go, remote_users.go, and remote_audit.go
// to build filter query strings without duplicating the join/format logic.
// Not exported; stays close to where it is used (same package).
package store

import (
	"fmt"
	"strings"
	"time"
)

// queryBuilder accumulates URL query parameters.
type queryBuilder struct {
	params []string
}

func newQueryBuilder() *queryBuilder {
	return &queryBuilder{}
}

func (q *queryBuilder) add(key, value string) {
	q.params = append(q.params, key+"="+value)
}

func (q *queryBuilder) addUint(key string, v *uint) {
	if v != nil {
		q.add(key, fmt.Sprintf("%d", *v))
	}
}

func (q *queryBuilder) addString(key string, v *string) {
	if v != nil && *v != "" {
		q.add(key, *v)
	}
}

func (q *queryBuilder) addBool(key string, v *bool) {
	if v != nil {
		q.add(key, fmt.Sprintf("%t", *v))
	}
}

func (q *queryBuilder) addTime(key string, v *time.Time) {
	if v != nil {
		q.add(key, v.Format("2006-01-02T15:04:05Z"))
	}
}

func (q *queryBuilder) addTags(key string, tags []string) {
	for _, tag := range tags {
		q.add(key, tag)
	}
}

func (q *queryBuilder) addPage(page, pageSize int) {
	if page > 0 {
		q.add("page", fmt.Sprintf("%d", page))
	}
	if pageSize > 0 {
		q.add("page_size", fmt.Sprintf("%d", pageSize))
	}
}

// String returns "?k=v&k=v" or "" if no params were added.
func (q *queryBuilder) String() string {
	if len(q.params) == 0 {
		return ""
	}
	return "?" + strings.Join(q.params, "&")
}
