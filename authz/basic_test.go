package authz

import (
	"io/ioutil"
	"testing"

	"github.com/docker/docker/pkg/authorization"
	"github.com/stretchr/testify/assert"
)

func TestAuditRequestStdout(t *testing.T) {
	auditor := NewBasicAuditor(&BasicAuditorSettings{LogHook: AuditHookStdout})
	assert.NoError(t, auditor.AuditRequest(&authorization.Request{User: "user"}, &authorization.Response{Allow: true}))
	assert.Error(t, auditor.AuditRequest(&authorization.Request{User: "user"}, nil), "Missing request")
	assert.Error(t, auditor.AuditRequest(nil, &authorization.Response{Err: "err"}), "Missing plugin response")
}

func TestAuditRequestSyslog(t *testing.T) {
	auditor := NewBasicAuditor(&BasicAuditorSettings{LogHook: AuditHookSyslog})
	assert.NoError(t, auditor.AuditRequest(&authorization.Request{User: "user"}, &authorization.Response{Allow: true}))
}

func TestAuditRequestFile(t *testing.T) {
	logPath := "/tmp/auth-plugin-stub.log"
	auditor := NewBasicAuditor(&BasicAuditorSettings{LogHook: AuditHookFile, LogPath: logPath})
	assert.NoError(t, auditor.AuditRequest(&authorization.Request{User: "user"}, &authorization.Response{Allow: true}))
	log, err := ioutil.ReadFile(logPath)
	assert.NoError(t, err)
	assert.Contains(t, string(log), "allow", "Log doesn't container authorization data")
}
