# Context Window technique for DLP

## Why context matters
Regex finds the shape of data, but context confirms the meaning. A 16-digit string is not always a credit card. The Context Window reduces false positives by requiring nearby keywords to boost confidence.

## Core idea
When a regex match is found, scan a fixed window before and after the match for keywords. The closer the keyword, the higher the score.

## Confidence scoring
- Base score: regex match adds a base score (example: 0.60).
- Distance boost: keywords within a radius add extra points.
  - Within 20 characters: +0.30
  - Within 50 characters: +0.20
  - Outside window: +0.00
- Threshold: accept only if final score >= 0.80.

## Distance-weighted window
Example for credit card:
- Match: "4111 1111 1111 1111"
- Keywords: "Visa", "CVV", "payment"

Closer keywords produce higher confidence.

## Zero-copy implementation (Go)
Use slicing on the existing byte buffer to avoid extra allocations.

```go
windowSize := 50

start := matchIndex[0] - windowSize
if start < 0 {
    start = 0
}

end := matchIndex[1] + windowSize
if end > len(data) {
    end = len(data)
}

context := data[start:end]

// Scan keywords with bytes.Contains or Aho-Corasick
```

## Practical tuning tips
- Keep window small enough for performance (20-100 chars).
- Use primary keywords (e.g., "Visa", "CVV") for higher boosts.
- Apply checksum validation (Luhn) before context scoring when possible.
