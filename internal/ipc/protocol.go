package ipc

import (
	"fmt"
	"math"

	"google.golang.org/protobuf/encoding/protowire"
)

const (
	TypeScan   = "scan"
	TypeResult = "result"
	TypePing   = "ping"
	TypePong   = "pong"
)

type ScanOptions struct {
	MinConfidence float64
	RulesDir      string
	MaxFileSizeMB int64
}

type Request struct {
	JobID    string
	FilePath string
	Options  ScanOptions
}

type Match struct {
	RuleID     string
	RuleName   string
	Category   string
	Offset     int64
	Length     int
	Confidence float64
}

type Response struct {
	JobID      string
	Level      int
	Matches    []Match
	DurationMs int64
	Err        string
}

// Envelope is a protobuf binary frame over Unix socket.
// Field numbers are stable for backward compatible wire evolution.
type Envelope struct {
	Type     string
	Request  *Request
	Response *Response
}

func MarshalEnvelope(e Envelope) ([]byte, error) {
	b := make([]byte, 0, 256)
	if e.Type != "" {
		b = protowire.AppendTag(b, 1, protowire.BytesType)
		b = protowire.AppendString(b, e.Type)
	}
	if e.Request != nil {
		rb, err := marshalRequest(*e.Request)
		if err != nil {
			return nil, err
		}
		b = protowire.AppendTag(b, 2, protowire.BytesType)
		b = protowire.AppendBytes(b, rb)
	}
	if e.Response != nil {
		rb, err := marshalResponse(*e.Response)
		if err != nil {
			return nil, err
		}
		b = protowire.AppendTag(b, 3, protowire.BytesType)
		b = protowire.AppendBytes(b, rb)
	}
	return b, nil
}

func UnmarshalEnvelope(b []byte) (Envelope, error) {
	var out Envelope
	for len(b) > 0 {
		num, wt, n := protowire.ConsumeTag(b)
		if n < 0 {
			return out, fmt.Errorf("consume tag: %v", protowire.ParseError(n))
		}
		b = b[n:]
		switch num {
		case 1:
			if wt != protowire.BytesType {
				return out, fmt.Errorf("type field wire type mismatch")
			}
			s, m := protowire.ConsumeString(b)
			if m < 0 {
				return out, fmt.Errorf("consume type: %v", protowire.ParseError(m))
			}
			out.Type = s
			b = b[m:]
		case 2:
			if wt != protowire.BytesType {
				return out, fmt.Errorf("request field wire type mismatch")
			}
			raw, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return out, fmt.Errorf("consume request: %v", protowire.ParseError(m))
			}
			req, err := unmarshalRequest(raw)
			if err != nil {
				return out, err
			}
			out.Request = &req
			b = b[m:]
		case 3:
			if wt != protowire.BytesType {
				return out, fmt.Errorf("response field wire type mismatch")
			}
			raw, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return out, fmt.Errorf("consume response: %v", protowire.ParseError(m))
			}
			resp, err := unmarshalResponse(raw)
			if err != nil {
				return out, err
			}
			out.Response = &resp
			b = b[m:]
		default:
			m := protowire.ConsumeFieldValue(num, wt, b)
			if m < 0 {
				return out, fmt.Errorf("consume unknown field: %v", protowire.ParseError(m))
			}
			b = b[m:]
		}
	}
	return out, nil
}

func marshalRequest(r Request) ([]byte, error) {
	b := make([]byte, 0, 128)
	if r.JobID != "" {
		b = protowire.AppendTag(b, 1, protowire.BytesType)
		b = protowire.AppendString(b, r.JobID)
	}
	if r.FilePath != "" {
		b = protowire.AppendTag(b, 2, protowire.BytesType)
		b = protowire.AppendString(b, r.FilePath)
	}
	if r.Options.MinConfidence != 0 || r.Options.RulesDir != "" || r.Options.MaxFileSizeMB != 0 {
		ob := marshalOptions(r.Options)
		b = protowire.AppendTag(b, 3, protowire.BytesType)
		b = protowire.AppendBytes(b, ob)
	}
	return b, nil
}

func unmarshalRequest(b []byte) (Request, error) {
	var out Request
	for len(b) > 0 {
		num, wt, n := protowire.ConsumeTag(b)
		if n < 0 {
			return out, fmt.Errorf("request tag: %v", protowire.ParseError(n))
		}
		b = b[n:]
		switch num {
		case 1:
			s, m := protowire.ConsumeString(b)
			if m < 0 {
				return out, fmt.Errorf("request job id: %v", protowire.ParseError(m))
			}
			out.JobID = s
			b = b[m:]
		case 2:
			s, m := protowire.ConsumeString(b)
			if m < 0 {
				return out, fmt.Errorf("request path: %v", protowire.ParseError(m))
			}
			out.FilePath = s
			b = b[m:]
		case 3:
			raw, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return out, fmt.Errorf("request options: %v", protowire.ParseError(m))
			}
			out.Options = unmarshalOptions(raw)
			b = b[m:]
		default:
			m := protowire.ConsumeFieldValue(num, wt, b)
			if m < 0 {
				return out, fmt.Errorf("request unknown: %v", protowire.ParseError(m))
			}
			b = b[m:]
		}
	}
	return out, nil
}

func marshalOptions(o ScanOptions) []byte {
	b := make([]byte, 0, 48)
	if o.MinConfidence != 0 {
		b = protowire.AppendTag(b, 1, protowire.Fixed64Type)
		b = protowire.AppendFixed64(b, math.Float64bits(o.MinConfidence))
	}
	if o.RulesDir != "" {
		b = protowire.AppendTag(b, 2, protowire.BytesType)
		b = protowire.AppendString(b, o.RulesDir)
	}
	if o.MaxFileSizeMB != 0 {
		b = protowire.AppendTag(b, 3, protowire.VarintType)
		b = protowire.AppendVarint(b, uint64(o.MaxFileSizeMB))
	}
	return b
}

func unmarshalOptions(b []byte) ScanOptions {
	var out ScanOptions
	for len(b) > 0 {
		num, wt, n := protowire.ConsumeTag(b)
		if n < 0 {
			break
		}
		b = b[n:]
		switch num {
		case 1:
			if wt != protowire.Fixed64Type {
				return out
			}
			v, m := protowire.ConsumeFixed64(b)
			if m < 0 {
				return out
			}
			out.MinConfidence = math.Float64frombits(v)
			b = b[m:]
		case 2:
			s, m := protowire.ConsumeString(b)
			if m < 0 {
				return out
			}
			out.RulesDir = s
			b = b[m:]
		case 3:
			v, m := protowire.ConsumeVarint(b)
			if m < 0 {
				return out
			}
			out.MaxFileSizeMB = int64(v)
			b = b[m:]
		default:
			m := protowire.ConsumeFieldValue(num, wt, b)
			if m < 0 {
				return out
			}
			b = b[m:]
		}
	}
	return out
}

func marshalResponse(r Response) ([]byte, error) {
	b := make([]byte, 0, 128)
	if r.JobID != "" {
		b = protowire.AppendTag(b, 1, protowire.BytesType)
		b = protowire.AppendString(b, r.JobID)
	}
	b = protowire.AppendTag(b, 2, protowire.VarintType)
	b = protowire.AppendVarint(b, uint64(r.Level))
	if len(r.Matches) > 0 {
		for _, m := range r.Matches {
			mb, err := marshalMatch(m)
			if err != nil {
				return nil, err
			}
			b = protowire.AppendTag(b, 3, protowire.BytesType)
			b = protowire.AppendBytes(b, mb)
		}
	}
	if r.DurationMs != 0 {
		b = protowire.AppendTag(b, 4, protowire.VarintType)
		b = protowire.AppendVarint(b, uint64(r.DurationMs))
	}
	if r.Err != "" {
		b = protowire.AppendTag(b, 5, protowire.BytesType)
		b = protowire.AppendString(b, r.Err)
	}
	return b, nil
}

func unmarshalResponse(b []byte) (Response, error) {
	var out Response
	for len(b) > 0 {
		num, wt, n := protowire.ConsumeTag(b)
		if n < 0 {
			return out, fmt.Errorf("response tag: %v", protowire.ParseError(n))
		}
		b = b[n:]
		switch num {
		case 1:
			s, m := protowire.ConsumeString(b)
			if m < 0 {
				return out, fmt.Errorf("response job id: %v", protowire.ParseError(m))
			}
			out.JobID = s
			b = b[m:]
		case 2:
			v, m := protowire.ConsumeVarint(b)
			if m < 0 {
				return out, fmt.Errorf("response level: %v", protowire.ParseError(m))
			}
			out.Level = int(v)
			b = b[m:]
		case 3:
			raw, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return out, fmt.Errorf("response match: %v", protowire.ParseError(m))
			}
			match, err := unmarshalMatch(raw)
			if err != nil {
				return out, err
			}
			out.Matches = append(out.Matches, match)
			b = b[m:]
		case 4:
			v, m := protowire.ConsumeVarint(b)
			if m < 0 {
				return out, fmt.Errorf("response duration: %v", protowire.ParseError(m))
			}
			out.DurationMs = int64(v)
			b = b[m:]
		case 5:
			s, m := protowire.ConsumeString(b)
			if m < 0 {
				return out, fmt.Errorf("response err: %v", protowire.ParseError(m))
			}
			out.Err = s
			b = b[m:]
		default:
			m := protowire.ConsumeFieldValue(num, wt, b)
			if m < 0 {
				return out, fmt.Errorf("response unknown: %v", protowire.ParseError(m))
			}
			b = b[m:]
		}
	}
	return out, nil
}

func marshalMatch(m Match) ([]byte, error) {
	b := make([]byte, 0, 64)
	if m.RuleID != "" {
		b = protowire.AppendTag(b, 1, protowire.BytesType)
		b = protowire.AppendString(b, m.RuleID)
	}
	if m.RuleName != "" {
		b = protowire.AppendTag(b, 2, protowire.BytesType)
		b = protowire.AppendString(b, m.RuleName)
	}
	if m.Category != "" {
		b = protowire.AppendTag(b, 3, protowire.BytesType)
		b = protowire.AppendString(b, m.Category)
	}
	if m.Offset != 0 {
		b = protowire.AppendTag(b, 4, protowire.VarintType)
		b = protowire.AppendVarint(b, uint64(m.Offset))
	}
	if m.Length != 0 {
		b = protowire.AppendTag(b, 5, protowire.VarintType)
		b = protowire.AppendVarint(b, uint64(m.Length))
	}
	if m.Confidence != 0 {
		b = protowire.AppendTag(b, 6, protowire.Fixed64Type)
		b = protowire.AppendFixed64(b, math.Float64bits(m.Confidence))
	}
	return b, nil
}

func unmarshalMatch(b []byte) (Match, error) {
	var out Match
	for len(b) > 0 {
		num, wt, n := protowire.ConsumeTag(b)
		if n < 0 {
			return out, fmt.Errorf("match tag: %v", protowire.ParseError(n))
		}
		b = b[n:]
		switch num {
		case 1:
			s, m := protowire.ConsumeString(b)
			if m < 0 {
				return out, fmt.Errorf("match rule id: %v", protowire.ParseError(m))
			}
			out.RuleID = s
			b = b[m:]
		case 2:
			s, m := protowire.ConsumeString(b)
			if m < 0 {
				return out, fmt.Errorf("match rule name: %v", protowire.ParseError(m))
			}
			out.RuleName = s
			b = b[m:]
		case 3:
			s, m := protowire.ConsumeString(b)
			if m < 0 {
				return out, fmt.Errorf("match category: %v", protowire.ParseError(m))
			}
			out.Category = s
			b = b[m:]
		case 4:
			v, m := protowire.ConsumeVarint(b)
			if m < 0 {
				return out, fmt.Errorf("match offset: %v", protowire.ParseError(m))
			}
			out.Offset = int64(v)
			b = b[m:]
		case 5:
			v, m := protowire.ConsumeVarint(b)
			if m < 0 {
				return out, fmt.Errorf("match length: %v", protowire.ParseError(m))
			}
			out.Length = int(v)
			b = b[m:]
		case 6:
			v, m := protowire.ConsumeFixed64(b)
			if m < 0 {
				return out, fmt.Errorf("match confidence: %v", protowire.ParseError(m))
			}
			out.Confidence = math.Float64frombits(v)
			b = b[m:]
		default:
			m := protowire.ConsumeFieldValue(num, wt, b)
			if m < 0 {
				return out, fmt.Errorf("match unknown: %v", protowire.ParseError(m))
			}
			b = b[m:]
		}
	}
	return out, nil
}
