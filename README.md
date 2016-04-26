# Auth Plugin Stub

## Build the plugin
1. Install [glide](https://github.com/Masterminds/glide)
1. `glide install`
1. `go install`

## Running as a stand-alone service

1. Run the plugin
1. Update Docker daemon to run with authorization enabled.
Example:
```bash
   /usr/bin/docker daemon -H fd:// --authorization-plugin=auth-plugin-stub
``` 
  
## Extending the authorization plugin

The framework consists of two extendable interfaces: the Authorizer, 
which handles the authorization flow; and the Auditor, which audits the request and response in the authorization flow.

```go
// Authorizer handles the authorization of docker requests and responses
type Authorizer interface {
	Init() error                                                 // Init initialize the handler
	AuthZReq(req *authorization.Request) *authorization.Response // AuthZReq handles the request from docker client
	// to docker daemon
	AuthZRes(req *authorization.Request) *authorization.Response // AuthZRes handles the response from docker deamon to docker client
}
```

```go
// Auditor audits the request and response sent from/to docker daemon
type Auditor interface {
	// AuditRequest audit the request sent from docker client and the associated authorization response
	// Docker client -> authorization -> audit -> Docker daemon
	AuditRequest(req *authorization.Request, pluginRes *authorization.Response)
	// AuditRequest audit the response sent from docker daemon and the associated authorization response
	// Docker daemon -> authorization  -> audit -> Docker client
	AuditResponse(req *authorization.Request, pluginRes *authorization.Response)
}
```
