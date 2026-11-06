package handlers

// policy_families_not_found_typed_test.go — STORAGE-ERR-CLASS-5 item 4.
//
// The alert-escalation, notification-channel and rotation-policy handlers answered 404 for
// any error whose TEXT contained "not found", so a storage read fault with those words in
// the driver message read as a missing target. Each now classifies by the typed storage
// not-found: 404 only for a row that is not there, 503 storage_unavailable for a fault.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyFamilies_ReadFaultIs503NotFoundStays404(t *testing.T) {
	fw := newFoldWorld(t)
	esc := NewAlertEscalationHandler(fw.cs)
	ch := NewNotificationChannelHandler(fw.cs)
	rot := NewRotationPolicyHandler(fw.cs)

	const (
		escBody = `{"name":"renamed"}`
		chBody  = `{"events":"secret.rotated"}`
		rotBody = `{"name":"renamed","interval_days":30,"alert_days_before":5,"is_active":true}`
	)
	cases := []struct {
		name, fault, body string
		call              func(w http.ResponseWriter, r *http.Request)
	}{
		{"alert escalation Get", "GetAlertEscalationPolicy", "", esc.Get},
		{"alert escalation Update", "GetAlertEscalationPolicy", escBody, esc.Update},
		{"notification channel Get", "GetNotificationChannel", "", ch.Get},
		{"notification channel Update", "GetNotificationChannel", chBody, ch.Update},
		{"notification channel Delete", "GetNotificationChannel", "", ch.Delete},
		{"notification channel GetRetryPolicy", "GetNotificationChannel", "", ch.GetRetryPolicy},
		{"rotation policy Get", "GetRotationPolicy", "", rot.Get},
		{"rotation policy Update", "GetRotationPolicy", rotBody, rot.Update},
		{"rotation policy Delete", "GetRotationPolicy", "", rot.Delete},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			method := http.MethodGet
			if tc.body != "" {
				method = http.MethodPut
			}
			fw.armFault(tc.fault, 1, errFoldDriver)
			w := httptest.NewRecorder()
			tc.call(w, suReq(method, tc.body, map[string]string{"id": "1"}))
			require.True(t, fw.faulty.Fired(), "the read fault must be reached")
			requireNot404Fault(t, w, true, tc.name)
			fw.faulty.Arm(nil)

			w = httptest.NewRecorder()
			tc.call(w, suReq(method, tc.body, map[string]string{"id": "9999999"}))
			assert.Equal(t, http.StatusNotFound, w.Code, "%s: a true not-found stays 404: %s", tc.name, w.Body.String())
			assert.Empty(t, w.Header().Get("Retry-After"))
		})
	}
}
