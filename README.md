# BandhPremache

A Next.js application for a privacy-conscious matrimony service. This local project includes the responsive public site, authentication and profile flows, privacy-projected member search, trial controls, moderation/report foundations, an Owner/Developer/Moderator administration area, and a Supabase migration.

## Run locally

Requirements: Node.js 20.9 or newer and npm.

```powershell
npm install
npm run dev
```

Open `http://localhost:3000`. Without Supabase credentials, account, search, moderation, and admin data endpoints deliberately report that live services are unavailable. The marketing site does not invent members, reviews, prices, company credentials, or successful payments.

## Configure Supabase

1. Create a new Supabase project and configure its authentication email provider.
2. Copy `.env.example` to `.env.local`; set `NEXT_PUBLIC_SUPABASE_URL`, `NEXT_PUBLIC_SUPABASE_ANON_KEY`, and `NEXT_PUBLIC_SITE_URL`. The anon key is intended for browser use; never add a service-role key to a `NEXT_PUBLIC_` variable.
3. Review `supabase/migrations/20261015000000_initial_schema.sql` with the project owner and apply it only to a new, empty Supabase project. It has not been run against production.
4. In Supabase Auth, create and verify the intended Owner account. Find that user's UUID in the Auth dashboard, inspect it carefully, then run the commented one-time `INSERT` at the end of the migration in the SQL Editor. Public registration always creates `MEMBER`; there is no automatic Owner.
5. Add `http://localhost:3000/auth/confirm` and the approved production callback URL to the Supabase Auth redirect allow-list. Configure email templates to redirect through `/auth/confirm`.
6. Review the draft Privacy and Terms pages with the business owner and qualified counsel before launch.

The migration uses RLS, server-side `has_permission` checks, a safe `discoverable_profiles` view that exposes age instead of date of birth, integer minor-unit plan prices, audit rows that are append-only to application roles, one-time seven-day trial claims, report throttling/duplicate protection, and staff-only moderation evidence. Apply changes through reviewed migrations; do not edit production data manually except for the documented initial Owner provisioning.

## Roles

- `OWNER`: business administration.
- `DEVELOPER`: technical diagnostics only by default.
- `MODERATOR`: Trust & Safety functions by default.
- `MEMBER`: normal account and profile access.

The Owner can set Developer/Moderator/Member roles and grant explicit additional permissions to existing, verified Supabase accounts in `/admin/administrators`. That screen does **not** send invitation emails. Owner assignment itself is excluded from the screen and remains a manually reviewed provisioning operation. Administrative roles are separately revocable; disabling a role blocks its permissions.

## Tests and checks

```powershell
npm test
npm run lint
npm run typecheck
npm run build
```

The included Vitest tests are local unit tests for permission boundaries, input validation, age calculations, currency precision, and in-process throttling. They do not connect to Supabase, a payment provider, or an email provider. Supabase integration/RLS tests require a configured Supabase project and have not been run here.

## Integrations not enabled

- **Payments:** no checkout or webhook is active; there are no provider credentials. Plan changes are intended for new memberships only. Membership and payment records keep price snapshots. No automatic renewal charge is made.
- **Email:** Supabase auth email templates require configuration. No email sender, reminder sequence, retry worker, or unsubscribe service is connected.
- **Scheduled work:** no background scheduler is deployed. Membership expiry is interpreted from timestamps in the dashboard/trial paths; reminders and periodic review jobs require a scheduler.
- **Deployment:** no hosting account, domain, or production secrets were supplied. The local production build must pass before deployment; no public deployment or paid resources were created.
- **Business policy:** currency, paid prices, renewal/price-change notice and consent, refund/cancellation terms, report appeals, data retention, and legal/business identity require owner confirmation.

See [`IMPLEMENTATION_CHECKLIST.md`](./IMPLEMENTATION_CHECKLIST.md) for current implementation status.
