package core

import "github.com/docker/docker/pkg/authorization"

// Authorizer handles the authorization of docker requests and responses
type Authorizer interface {
	Init() error                                                 // Initialize the handler
	AuthZReq(req *authorization.Request) *authorization.Response // Handle request from client to daemon
	AuthZRes(req *authorization.Request) *authorization.Response // Handle response from daemon to client
}

// Auditor audits the requests and responses sent from/to docker daemon
type Auditor interface {
	// AuditRequest audit the request sent from docker client and the associated authorization response
	// Docker client -> authorization -> audit -> Docker daemon
	AuditRequest(req *authorization.Request, pluginRes *authorization.Response) error

	// AuditRequest audit the response sent from docker daemon and the associated authorization response
	// Docker daemon -> authorization  -> audit -> Docker client
	AuditResponse(req *authorization.Request, pluginRes *authorization.Response) error
}
