package ipc

import "github.com/vnpt/dlp-classifier/internal/scanner"

func toResponse(jobID string, r scanner.ScanResult, err error) Response {
	resp := Response{JobID: jobID}
	if err != nil {
		resp.Err = err.Error()
		return resp
	}
	resp.Level = int(r.Level)
	resp.DurationMs = r.Duration.Milliseconds()
	if r.Error != "" {
		resp.Err = r.Error
	}
	for _, m := range r.Matches {
		resp.Matches = append(resp.Matches, Match{
			RuleID:     m.RuleID,
			Offset:     m.Offset,
			Length:     m.Length,
			Confidence: m.Confidence,
		})
	}
	return resp
}
