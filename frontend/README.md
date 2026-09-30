# React + TypeScript + Vite

This template provides a minimal setup to get React working in Vite with HMR and some ESLint rules.

Currently, two official plugins are available:

- [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react) uses [Oxc](https://oxc.rs)
- [@vitejs/plugin-react-swc](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react-swc) uses [SWC](https://swc.rs/)

## React Compiler

The React Compiler is not enabled on this template because of its impact on dev & build performances. To add it, see [this documentation](https://react.dev/learn/react-compiler/installation).

## Expanding the ESLint configuration

If you are developing a production application, we recommend updating the configuration to enable type-aware lint rules:

```js
export default defineConfig([
  # IPsec Security Assessment Console

  A React + TypeScript operations console for IPsec VPN fleet assessment, IKE probing, PCAP analysis, investigations, verification, compliance evidence, and reports.

  ## Current integration boundary

  No backend API specification, identity contract, event schema, or backend URL was present in the project when the frontend was created. The application therefore renders explicit unavailable states and does not seed demo records or call assumed endpoints. Probe and analysis submission are disabled until the backend contract is implemented. The transport and Server-Sent Events boundaries are in `src/services/`.

  ## Requirements and local development

  - Node.js 20.19+ or 22.12+
  - npm

  Install dependencies with `npm install`, then use `npm run dev` for local development. Run `npm run lint` and `npm run build` before deployment. `npm run preview` serves the production build locally.

  Copy `.env.example` to `.env.local` and supply deployment configuration as applicable:

  - `VITE_API_BASE_URL`: absolute API base URL.
  - `VITE_SSE_URL`: absolute Server-Sent Events URL, if the service supports it.
  - `VITE_AUTH_ISSUER` and `VITE_AUTH_CLIENT_ID`: public identity-provider configuration. An authentication flow is not implemented without the backend identity contract.
  - `VITE_ENVIRONMENT`: display label for the deployment environment.

  Vite embeds `VITE_*` values into client assets. Never place secrets, private keys, tokens, or credentials in these values.

  ## Backend integration

  Use the backend's approved API schema to add service functions, domain types, auth behavior, role claims, and event handlers. `apiRequest<T>()` intentionally accepts only a contract-defined relative path; it defines no endpoint names or response fields. Do not enable operational actions based on URL configuration alone. Confirm CORS, authorization, auditability, pagination, and error semantics against the service contract.

  ## Dashboard perspectives and companion interfaces

  The shared web dashboard provides CISO, Auditor, and Admin information perspectives. The selector is a display preference only; it does not identify a user, grant access, or enforce role permissions. Connect it to authoritative identity claims and backend authorization before using it as a security boundary. The CLI and reports/attestation outputs are separate architecture interfaces; CLI command details and output formats were not supplied and are not assumed by this web application.

  ## Deployment and custom domain

  Build static assets using the environment settings for the target deployment, then host the `dist/` directory on the selected domain. Configure the web host to serve `index.html` for application routes, serve static assets with appropriate cache headers, and apply HTTPS, a restrictive Content Security Policy, and any required security headers. Configure the backend and event-stream URLs for that environment; do not hard-code a localhost service address in application code. The Vite production build is domain-independent and requires no vendor-specific domain binding.

  ## Legal pages

  Privacy and Terms currently show explicit placeholder notices. Replace them with approved legal text before a public or production deployment.
  globalIgnores(['dist']),
