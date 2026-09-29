# TunnelTwin — Bug Discovery & Resolution Log (BUG.md)

> **Bug Traces**: Every issue, failure, or unexpected behavior encountered during development is tracked here from discovery to resolution: how it was found, what was tried, what worked, what didn't, and how it was verified.

---

## Bug Index

| Bug ID | Title | Severity | Status | Discovered In | Resolved In |
|---|---|---|---|---|---|
| **BUG-001** | strongSwan.conf filelog syntax error on raw path | Low | Closed | Phase 0 | Phase 0 |
| **BUG-002** | /var/run/charon.pid collision across network namespaces | High | Closed | Phase 0 | Phase 0 |
| **BUG-003** | Python subprocess.run hang due to unclosed child pipes | Medium | Closed | Phase 0 | Phase 0 |
| **BUG-004** | Mypy loop variable reuse type inference conflict in result.py | Low | Closed | Phase 1 | Phase 1 |
| **BUG-005** | Windows monotonic clock resolution causing timer test flaky failure | Low | Closed | Phase 1 | Phase 1 |

---

## BUG-001: strongswan.conf filelog syntax error on raw filesystem path

### 1. Discovery & Symptoms
- **How discovered**: Running `start_charon.sh` failed during daemon initialization.
- **Observed error**:
  ```text
  00[CFG] /var/run/tunneltwin/ns-left/strongswan.conf:3: syntax error, unexpected ., expecting : or '{' or '='
  00[CFG] invalid config file '/var/run/tunneltwin/ns-left/strongswan.conf'
  ```
- **Expected behavior**: Daemon should parse logging section and write logs to the specified file.

### 2. Diagnosis & Root Cause
- strongSwan configuration parser does not allow filesystem paths with dots and slashes directly as subsection names in `charon.filelog`.

### 3. Attempted Fixes
- *Attempt 1 (Success)*: Used named subsection `daemon_log` with explicit `path = ${RUN_DIR}/charon.log` setting as documented in `strongswan.conf(5)`.

### 4. Verification Proof
- `start_charon.sh` parsed the filelog section cleanly and created `/tmp/tunneltwin/ns-left/charon.log`.

---

## BUG-002: /var/run/charon.pid collision across network namespaces

### 1. Discovery & Symptoms
- **How discovered**: `ns-left` started successfully, but `ns-right` charon exited immediately with `Connection refused` on its VICI socket.
- **Observed error in log**:
  ```text
  Sep 24 10:52:21 00[DMN] charon already running ('/var/run/charon.pid' exists)
  ```
- **Expected behavior**: Independent charon daemons should run in parallel without interfering with one another.

### 2. Diagnosis & Root Cause
- strongSwan's charon binary checks `/var/run/charon.pid` by default. While network stacks were isolated by `ip netns`, `/var/run` remained shared across namespaces from the host root filesystem.

### 3. Attempted Fixes
- *Attempt 1 (Failed)*: Overriding `piddir` in strongswan.conf did not alter the hardcoded startup check in the Ubuntu charon binary.
- *Attempt 2 (Success)*: Combined `ip netns exec` with `unshare -m` (private mount namespace) and mounted an isolated `tmpfs` over `/var/run`:
  `ip netns exec "${NS}" unshare -m sh -c "mount -t tmpfs tmpfs /var/run && exec ..."`
  Sockets were routed to `/tmp/tunneltwin/${NS}/` (visible outside the mount namespace).

### 4. Verification Proof
- Both daemons ran simultaneously with unique PIDs and responded to `swanctl --stats` independently.

---

## BUG-003: Python subprocess.run hang due to unclosed child pipes

### 1. Discovery & Symptoms
- **How discovered**: `pytest tests/test_phase0_matrix.py` hung indefinitely despite `run_matrix.sh` completing in background.
- **Observed behavior**: `ps aux` showed `[bash] <defunct>` with charon processes (PID 453, 477) still holding inherited stdout/stderr file descriptors.

### 2. Diagnosis & Root Cause
- `subprocess.run(capture_output=True)` waits for all pipe writers to close before returning EOF. Because charon was backgrounded without output redirection, it inherited the bash script's stdout/stderr pipes, keeping them open indefinitely.

### 3. Attempted Fixes
- *Attempt 1 (Success)*: Redirected background charon output to `/dev/null 2>&1` in `start_charon.sh`:
  `... /usr/lib/ipsec/charon >/dev/null 2>&1 &`
  (Charon's internal logging was already writing to `/tmp/tunneltwin/${NS}/charon.log`).

### 4. Verification Proof
- Pytest completed in 12.52 seconds with all 7 tests passing.

---

## BUG-004: Mypy loop variable reuse type inference conflict in result.py

### 1. Discovery & Symptoms
- **How discovered**: Running `mypy tunneltwin --ignore-missing-imports` during Phase 1 verification.
- **Observed error**:
  ```text
  tunneltwin/probe/result.py:205: error: Incompatible types in assignment (expression has type "IKEv1AcceptedTransform", variable has type "AcceptedTransform")  [assignment]
  ```
- **Expected behavior**: Static type checker cleanly accepts iterations over two independent collections.

### 2. Diagnosis & Root Cause
- In `result.py`, loop variable `t` was used first to iterate over `self.accepted_transforms` (`list[AcceptedTransform]`) and then subsequently over `self.ikev1_accepted` (`list[IKEv1AcceptedTransform]`). Mypy retains the type narrowing of `t` from the first loop within the same method scope, flagging the second loop assignment as an incompatible type assignment.

### 3. Attempted Fixes
- *Attempt 1 (Success)*: Renamed the secondary loop variable to `v1t` (`for v1t in self.ikev1_accepted:`), completely isolating the variable scope and type annotations.

### 4. Verification Proof
- `mypy tunneltwin --ignore-missing-imports` passed with zero errors across all 19 source files.

---

## BUG-005: Windows monotonic clock resolution causing timer test flaky failure

### 1. Discovery & Symptoms
- **How discovered**: Running `pytest -v tests/test_probe_scanner.py` on host Windows.
- **Observed error**:
  ```text
  AssertionError: assert 0.0 > 0.0
  start_time = 861532.265, end_time = 861532.265, duration_ms = 0.0
  ```
- **Expected behavior**: Timer tracking measures elapsed scan duration > 0 ms.

### 2. Diagnosis & Root Cause
- On Windows, the system timer interrupt granularity for `time.monotonic()` can be ~15.6ms. A fast unit test sleeping for only 10ms (`time.sleep(0.01)`) frequently completed within the same timer tick window, resulting in `end_time == start_time` and `duration_ms == 0.0`.

### 3. Attempted Fixes
- *Attempt 1 (Success)*: Increased test sleep to 50ms (`time.sleep(0.05)`) and asserted `duration_ms >= 1.0` to safely exceed the 15.6ms timer resolution on Windows.

### 4. Verification Proof
- `pytest -v tests/test_probe_scanner.py` passed consistently across runs with `duration_ms` measuring ~50.2ms.
