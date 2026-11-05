# Skytech CRM — Cloudflare version

Runs entirely on Cloudflare (Workers + D1 database). No Netlify needed.

## Deploy (about 5 minutes)

The Cloudflare dashboard drag-and-drop box cannot deploy this, because the app has a backend and a database.
Use the one-line deploy command instead. You need Node.js (https://nodejs.org) installed.

1. Unzip this folder and open a terminal inside it.
2. Log in to Cloudflare:      npx wrangler@latest login
3. Deploy:                    npx wrangler@latest deploy

Wrangler creates the D1 database (named "skytech-crm") automatically on first deploy.
If your Wrangler asks for a database id instead, run:
    npx wrangler d1 create skytech-crm
then paste the printed database_id into wrangler.jsonc as  "database_id": "..."  and deploy again.

The tables and the login secret are created automatically on the first visit.

## First use

Open your site and choose "Create an account". The FIRST account becomes the workspace owner.
After that, sign-ups close (clients are added with "Client calendar access" inside the app).
To allow more owner accounts, add the variable ALLOW_SIGNUP = true in the Worker settings.

## Client invitations and emails (optional)

Without email set up, "Grant access & email client" shows you a setup link to send to the client yourself.
To send emails automatically, create a free Resend account (resend.com), verify your sender, then add:
    npx wrangler secret put RESEND_API_KEY
and a variable MAIL_FROM, for example  Skytech <hello@yourdomain.com>  (Worker settings > Variables).
Password-reset emails also need this.

## Locked out?
If the owner password is lost and email is not set up, run:
    npx wrangler d1 execute skytech-crm --remote --command "DELETE FROM users WHERE is_admin=1"
then create the account again with the same email — your data is kept (it is tied to the email).
