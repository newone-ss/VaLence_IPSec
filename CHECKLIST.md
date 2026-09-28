# TunnelTwin — Test Checklist & Verification

> **Note**: The canonical verification protocol is maintained in [VERIFICATION.md](file:///c:/Users/piyus/OneDrive/Desktop/project/Shield/VERIFICATION.md).
> This file provides the fast-reference checklist.

---

## Fast Verification Checklist ("No Vibe Checks")

Before any change is counted as "done", run and verify the following commands:

- [ ] **1. Ruff Lint**:
  ```bash
  ruff check .
  ```
  *Expected Output*: `All checks passed!` (Exit code 0)

- [ ] **2. Ruff Format**:
  ```bash
  ruff format --check .
  ```
  *Expected Output*: `X files already formatted` (Exit code 0)

- [ ] **3. Strict Type Check**:
  ```bash
  mypy tunneltwin --ignore-missing-imports
  ```
  *Expected Output*: `Success: no issues found in X source files` (Exit code 0)

- [ ] **4. In-Memory Unit Tests**:
  ```bash
  pytest -v tests/ -k "not phase0"
  ```
  *Expected Output*: `82 passed, 2 skipped, 1 deselected in ...s` (Exit code 0)

- [ ] **5. Lab Network Namespace Matrix (If lab/netns modified)**:
  ```bash
  sudo bash lab/run_matrix.sh
  ```
  *Expected Output*: `PHASE 0 EXIT CRITERIA MET: 4/4 PROFILES VERIFIED ESTABLISHED!` (Exit code 0)

- [ ] **6. One-Line Pre-Commit Verification**:
  ```bash
  ruff check . && ruff format --check . && mypy tunneltwin --ignore-missing-imports && pytest -v tests/ -k "not phase0"
  ```

---

For full details, expected stdout/stderr snippets, negative invariant rules, and phase exit gates, see [VERIFICATION.md](file:///c:/Users/piyus/OneDrive/Desktop/project/Shield/VERIFICATION.md).  
For the undo/revert safety net, see [ROLLBACK.md](file:///c:/Users/piyus/OneDrive/Desktop/project/Shield/ROLLBACK.md).
