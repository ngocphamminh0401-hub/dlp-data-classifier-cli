# IPC Protocol: Agent <-> Scanner (Unix + Protobuf)

This IPC channel is optimized for local throughput and long-term wire compatibility.

## Transport
- Unix domain socket: `net.Listen("unix", "/var/run/dlp-scanner.sock")`
- One goroutine per accepted connection.
- Frame format: 4-byte big-endian length prefix + protobuf binary payload.

## Serialization
- Protobuf binary wire format.
- Manual stable field numbering is implemented in `internal/ipc/protocol.go` using `protowire`.
- Benefit: compact payload and stable forward/backward evolution compared with gob.

## Envelope
```go
type Envelope struct {
    Type     string   // scan | result | ping | pong
    Request  *Request
    Response *Response
}
```

## Request schema
```go
type Request struct {
    JobID    string
    FilePath string
    Options  ScanOptions
}
```

## Response schema
```go
type Response struct {
    JobID      string
    Level      int
    Matches    []Match
    DurationMs int64
    Err        string
}
```

## Heartbeat
- Dedicated heartbeat goroutine per connection.
- Every 5s, server writes `Envelope{Type:"ping"}`.
- Write timeout: 500ms.
- Client replies `Envelope{Type:"pong"}`.

## Graceful shutdown
- `context.WithCancel` coordinates server stop.
- Signal handlers:
  - Unix: `SIGTERM`, `SIGINT`, `os.Interrupt`
  - Windows: `os.Interrupt`
- Listener close unblocks accept loop and lets active connection goroutines exit.

## Integration test
- `internal/ipc/ipc_integration_test.go`
- Verifies end-to-end scanner call through Unix protobuf IPC.
