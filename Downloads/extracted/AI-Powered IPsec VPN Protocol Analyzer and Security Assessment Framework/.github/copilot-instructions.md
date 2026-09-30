# Project guidance

- Keep the interface operational and evidence-led; do not add sample security records, fabricated counts, findings, activity, compliance results, or successful states.
- The workspace currently contains no backend API specification. Do not invent endpoints, request/response schemas, authentication flows, or role permissions. Add integrations only from an approved backend contract.
- Keep transport and event-stream code in `src/services`; keep pages, reusable UI, and shared types separated.
- If backend data is unavailable, state that plainly and preserve the distinction between unavailable data and an empty/healthy result.
- Use semantic HTML, keyboard-accessible controls, visible focus, compact rectangular buttons, and the dark neutral design tokens in `src/styles.css`.
- Browser-exposed `VITE_*` values are configuration, never secrets. Avoid introducing third-party network requests without an explicit requirement.
