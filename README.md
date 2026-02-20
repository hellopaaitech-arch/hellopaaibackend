# Hello Paai Backend

## Run

1) Copy env file

- Create `.env` from `.env.example`

2) Install and start

```bash
npm i
npm run dev
```

API base: `http://localhost:5000`

## Super admin

Set `SUPER_ADMIN_EMAIL` and `SUPER_ADMIN_PASSWORD` in `.env`. Super admin is auto-created on first startup. No register page.

Login:

- `POST /api/auth/admin/login` (works for **super_admin** and **admin**)
- `POST /api/auth/client/login`
- `POST /api/auth/user/login`

## OTP flow (email/mobile)

1) Request OTP

- `POST /api/otp/request`

2) Verify OTP → get `verifiedToken`

- `POST /api/otp/verify`

3) Register user (requires both email+mobile verified tokens)

- `POST /api/auth/user/register`
