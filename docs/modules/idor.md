# IDOR Detection

**Module ID:** `idor` | **Category:** Scanner | **Type:** Built-in
**Source:** `src/scanner/idor.rs`

## What It Does

Detects Insecure Direct Object Reference (IDOR) vulnerabilities by manipulating numeric identifiers in URL parameters and path segments. It generates adjacent ID values, requests the modified URLs, and compares the responses using a similarity metric to determine whether different objects are being returned without authorization checks.

## Checks Performed

### ID Detection Heuristics

**Parameter names** containing: `id`, `uid`, `user_id`, `userid`, `account`, `profile`, `doc`, `file`, `order`, `item`, `record`, `num`, `no`

**Parameter values** that are purely numeric, non-empty, and at most 10 digits long.

**Path segments** that are purely numeric and at most 10 digits (UUIDs and hashes are skipped).

### Adjacent ID Generation

For a given numeric ID `N`, the following values are tested:

| Test Value | Rationale |
|------------|-----------|
| `N + 1` | Next sequential record |
| `N - 1` (min 0) | Previous sequential record |
| `N + 100` | Distant record (different page/batch) |

### Similarity Analysis

Responses are compared using a character-level positional similarity metric. A finding is emitted when:

- Both responses return HTTP 200 (success)
- The response bodies are different
- The response body is at least 100 bytes
- Similarity is between 30% and 95% (same template, different data)

## Findings

| Finding | Severity | CWE | Trigger |
|---------|----------|-----|---------|
| Possible IDOR (parameter) | High | 639 | Adjacent ID in query param returns different content with 30-95% similarity |
| Possible IDOR in Path | High | 639 | Adjacent ID in URL path segment returns different content with 30-95% similarity |

## OWASP Coverage

**A01:2021 -- Broken Access Control.** IDOR is a primary example of broken access control where sequential or guessable identifiers allow unauthorized access to other users' resources.

## How It Works

1. **URL parameter testing:** Query parameters are extracted and each is checked against the ID name/value heuristics. For qualifying parameters, a baseline response is captured and then up to 3 adjacent IDs are tested.
2. **Path segment testing:** URL path segments are split and each purely numeric segment (up to 10 digits) is tested with adjacent IDs.
3. **Similarity scoring:** The `calculate_similarity` function counts character-by-character positional matches between two response bodies and divides by the maximum length. Values between 0.3 and 0.95 indicate the same page template rendering different data -- the hallmark of an IDOR.
4. **Early termination:** Testing stops at the first confirmed finding per parameter or path to avoid excessive requests.

## Example Output

```
[High] Possible IDOR: user_id
  Changing 'user_id' from '42' to '43' returns different content (72% similar).
  This may expose another user's data.
  Evidence: Parameter: user_id | Original: 42 | Test: 43 | Similarity: 72%
  Remediation: Implement proper authorization checks. Verify the requesting user owns the requested resource.
  OWASP: A01:2021 Broken Access Control | CWE-639
```
