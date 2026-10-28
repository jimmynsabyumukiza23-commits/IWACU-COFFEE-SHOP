# Iwacu Coffee Shop

## Run locally

Install Node.js 22.5 or newer, open PowerShell in this folder, and run:

```powershell
node server.js
```

Open <http://127.0.0.1:3000>. Do not open the HTML files directly with `file://`; the account and order forms need the local server.

The homepage is `UR.JI.html` and is served at `/`. The server also publishes `robots.txt` and a sitemap at `/sitemap.xml`.

Customers can create an account with their name, email, phone number, and a password of at least 10 characters. Passwords are stored as salted scrypt hashes. After signing in, customers can submit orders that are saved in `data/iwacu.sqlite`.

The homepage's Our Story section has a public comment board. Anyone can read and post comments; posted display names and comments are visible to everyone. Comments are limited to 500 characters, and posting is rate-limited.

Customers who forget their password can request an 8-digit verification code by email. Codes expire after 10 minutes, can be attempted five times, and are usable only once. Password reset email uses the Resend API. Configure `RESEND_API_KEY` and `EMAIL_FROM` as environment variables; verify the sender address or domain in Resend before sending email. Keep the API key secret and never commit it. The reset form reports when email delivery is not configured.

The SQLite database is private application data and is not served as a website file. Keep the `data` folder private and make secure backups if you need to preserve customer records. Do not commit or share the database.

When run locally, this server binds to the local computer only and is not publicly available. For a public launch, deploy using the included `render.yaml` configuration or another hosting provider with HTTPS, persistent storage, backups, privacy protections, and production monitoring; never expose the local server directly to the internet.

On Render, add the `RESEND_API_KEY` and `EMAIL_FROM` environment variables in the service settings. `render.yaml` intentionally leaves these values unsynchronized so secrets are not stored in the repository. Use a sender address verified by your Resend account.

## Public launch checklist

Complete and verify each item before sharing the public site:

- [ ] Commit and push the latest website changes to the GitHub repository connected to Render. Check `git status` first so private files such as `.env` and `data/iwacu.sqlite` are not committed.
- [ ] Confirm the Render Web Service is connected to the correct repository and branch and uses the included Blueprint settings: Node runtime, `node server.js`, `/api/health`, and the persistent disk mounted at `/var/data`.
- [ ] In Render, set `RESEND_API_KEY` and `EMAIL_FROM` as secret/service environment variables. Do not put secret values in GitHub, this README, or chat.
- [ ] Wait for a successful Render deployment and open the service's actual `https://...onrender.com` URL in a browser. Confirm `/api/health` returns `{"status":"ok"}`.
- [ ] On the public URL, test the homepage and menu, customer registration and sign-in, a test order, and the public comment board.
- [ ] Test password reset using an email address you control. Confirm the verified Resend sender delivers the code, the code expires, and a successful reset allows sign-in with the new password.
- [ ] Confirm customer and order data survives a service restart by checking the configured persistent disk; keep database backups private and protected.
- [ ] After launch, check `https://your-public-url/robots.txt` and `https://your-public-url/sitemap.xml`. Search-engine indexing can take time and is not guaranteed.

The local website being available at `http://127.0.0.1:3000` does not confirm that GitHub has the latest changes or that Render is live. Only share the public URL after completing the checks above.
