# WebVault secure customer intake setup

This folder establishes the private Supabase backend. It does **not** make the public GitHub Pages site private; the website stays public while customer records and uploaded files remain private.

## Security model

- Customer rows and file metadata have Row Level Security enabled.
- There are no anonymous or authenticated insert policies on customer tables.
- Public form submissions must go through the `submit-request` Edge Function.
- The Edge Function uses the Supabase service-role key only on the server.
- Uploaded files go into a private bucket (not public URLs).
- Uploads are limited to five files, 25 MB each, with an allowlist of image/video MIME types.
- Basic IP-hash rate limiting allows five submissions per IP hash per hour.
- Admin access is granted by explicitly inserting your authenticated user UUID into `webvault_admins`.

## Setup steps

1. Create a Supabase project at https://supabase.com and keep its database password private.
2. In Supabase SQL Editor, run `migrations/202611060001_webvault_private_intake.sql`.
3. In Supabase Authentication settings, disable public sign-ups after creating your own owner account. Use a strong unique password and enable MFA if available.
4. Deploy the Edge Function in `functions/submit-request/index.ts` as `submit-request`. Set `verify_jwt=false` because customer visitors are not logged in; the function performs its own validation and rate limiting. Supabase provides `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` to deployed functions. Add a random `RATE_LIMIT_SALT` secret.
5. Create your owner account in Supabase Auth, then copy its user UUID from Authentication > Users. In SQL Editor run:
   `insert into public.webvault_admins(user_id) values ('YOUR_AUTH_USER_UUID');`
6. Keep the project URL and anon/publishable key for the public website configuration only. **Never put the service-role key, database password, or any secret key in GitHub Pages code.**
7. Configure the website form to POST multipart form data to the Edge Function URL. The optional file field name is `files`; text field names are `name`, `reach`, `biz`, `msg`, and honeypot `website`.

## Important remaining work

The current public website form still uses `mailto:`. It has not yet been switched to this backend, and no live database exists until you create the Supabase project and deploy these files. The private owner dashboard, authenticated file preview/download, and automated 90-day deletion workflow must be completed and tested before accepting real customer uploads.

## 90-day retention

Do not enable uploads for real customer data until a scheduled server-side cleanup task has been configured and tested to delete both old storage objects and their database records after 90 days. Deleting only database rows does not remove files from Storage.
