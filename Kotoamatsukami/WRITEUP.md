# Kotoamatsukami Writeup

## Vulnerability Analysis
The application has a two-stage process for executing directives:
1. **Verification Gateway (`/api/seal`)**: Validates that the input payload's `action` is `"request_access"`, `subject` is `"guest"`, and `level` is `"public"`. If valid, it signs the JSON string using HMAC-SHA256 and returns a signed token.
2. **Decision Engine (`/api/execute`)**: Validates the signature and then carries out the action described in the token's payload.

The vulnerability stems from a **JSON Parser Discrepancy (Duplicate Key Collision)** between the Verification Gateway and the Decision Engine:
- The **Verification Gateway** parses the JSON payload and resolves duplicate keys by keeping the **first** occurrence (e.g., `"level": "public"`).
- The **Decision Engine** parses the JSON payload and resolves duplicate keys by keeping the **last** occurrence (e.g., `"level": "level-5"`).

By providing duplicate keys in the directive JSON, we can construct a payload that appears benign to the Verification Gateway but executes with elevated privileges in the Decision Engine.

## Exploit
1. We construct a payload requesting access, using duplicate keys to confuse the two parsers:
   ```json
   {
     "action": "request_access", 
     "action": "grant_access", 
     "subject": "guest", 
     "level": "public", 
     "level": "level-5"
   }
   ```
2. The Verification Gateway validates this as:
   - `action`: `"request_access"` (First key wins)
   - `subject`: `"guest"`
   - `level`: `"public"` (First key wins)
   Since these are all permitted values, the Gateway successfully signs the payload and returns the token:
   `eyJhY3Rpb24iOiAicmVxdWVzdF9hY2Nlc3MiLCAic3ViamVjdCI6ICJndWVzdCIsICJsZXZlbCI6ICJwdWJsaWMiLCAiYWN0aW9uIjogImdyYW50X2FjY2VzcyIsICJsZXZlbCI6ICJsZXZlbC01In0.qtczgMQMtozo_cX-_sq0kXYHovFl8JCWCa1T2YdQRT4`

3. We send this token to `/api/execute`. The Decision Engine validates the signature (which is valid), and then parses the payload as:
   - `action`: `"grant_access"` (Last key wins)
   - `subject`: `"guest"`
   - `level`: `"level-5"` (Last key wins)
   The engine carries this out, elevating the guest session's authority and returning a cookie named `decision_session` set to the elevated session state.

4. Using the returned `decision_session` cookie, we query the `/api/archive` endpoint, which unlocks the Restricted Archive and gives us the flag.

## Flag
`ICS{7h3_d3c1510n_w45_n3v3r_y0ur5}`
