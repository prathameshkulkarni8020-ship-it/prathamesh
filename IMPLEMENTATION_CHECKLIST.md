# Implementation checklist

## Implemented in this local build

- [x] Next.js App Router + TypeScript project scaffold and supplied logo.
- [x] Responsive homepage with honest empty states and no fabricated profiles or testimonials.
- [x] Supabase SSR auth flows: sign-up with an 18+ check, sign-in, email callback, password recovery/reset, and sign-out.
- [x] Supabase profile creation/edit schema; private-by-default visibility and an age-only discoverable view.
- [x] Combined partner-search filters, server-side validation, paging API, and no-store responses.
- [x] One-time, server-timestamped seven-day trial RPC; no second trial after any prior claim or active/previous paid membership.
- [x] Central role/permission checks in server code and PostgreSQL; Owner not granted through public signup.
- [x] Owner dashboard backed by database summary RPC; unavailable values are not rendered as zero.
- [x] Owner plan create/edit/enable controls, currency-aware integer minor units, price review confirmation, and append-only price history.
- [x] Member harassment reports; confidential staff queue, claim/assignment, review decisions, suspensions, bans, restoration RPC, and audit entries.
- [x] Account deletion review request only; no automatic deletion or retention-policy assumption.
- [x] Owner administrator role/permission controls for existing accounts; Developer technical dashboard.
- [x] Contact-message validation, database-backed throttling, and audit-history page.
- [x] `.env.example`, draft legal pages, and setup guide.

## Not implemented or not verified

- [ ] Apply migration to a configured Supabase project and run live RLS/API integration tests.
- [ ] Implement and verify account invitations, appeals and affected-party notifications.
- [ ] Define data retention and complete irreversible account deletion/export workflow.
- [ ] Confirm plan currency, prices, renewal behavior, cancellation, refunds, and legally required price-change notice/consent.
- [ ] Connect a payment provider and test signed webhook verification/idempotency with provider sandbox credentials.
- [ ] Configure production email sender, reminders, unsubscribe handling, retries, and scheduled jobs.
- [ ] Add durable distributed rate limiting (current application limiter is process-local; database report/contact guards provide additional controls).
- [ ] Add privacy-reviewed photo uploads, profile preferences UI, review submission/moderation UI, and advertisement management.
- [ ] Add privacy/legal owner and counsel approval, final business identity, support contact, and production retention schedule.
- [ ] Add live API error-rate/log aggregation and deployment/build status integration.
- [ ] Configure hosting and domain; run production build and deployment verification with approved credentials.
