# CampusVote — College Election Project (No OTP)

A beginner-friendly full-stack college election demonstration using HTML, CSS, vanilla JavaScript, Node.js, Express, and MongoDB.

## Features
- No OTP or email-code flow.
- Separate admin, representative, and voter panels.
- Student registration by admission number, email, and password.
- Password hashing with bcrypt.
- Admin approval required before a student can vote.
- Admin creates, starts, and closes elections; results are available only after closing.
- Admin can approve a voter or assign representative access.
- Candidate applications include position, department, and manifesto.
- Unique MongoDB index enforces one vote per account per election.
- Vote records do not contain the voter account ID; a separate receipt record enforces one-vote eligibility.
- HTTP-only session cookie, role checks, rate limiting, and basic security headers.

## Requirements
- Node.js 18+
- MongoDB Community Server running locally, or a MongoDB Atlas connection string
- VS Code or another editor

## Setup
1. Extract the ZIP and open the folder in VS Code.
2. Open a terminal in this folder and run:
   ```bash
   npm install
   ```
3. Copy `.env.example` to `.env`.
4. In `.env`, set:
   - `MONGODB_URI` to your local MongoDB URL or Atlas connection string.
   - `JWT_SECRET` to a random secret at least 32 characters long.
   - `ADMIN_EMAIL` and `ADMIN_PASSWORD` (use a strong password of at least 12 characters).
5. Make sure MongoDB is running.
6. Run:
   ```bash
   npm run dev
   ```
7. Visit http://localhost:3000.

The admin account is created when the server first starts if the configured admin email does not already exist. If you change the admin password in `.env` later, the existing database account's password is not automatically changed.

## Demo workflow
1. Sign in with the configured admin credentials.
2. Register a test student in another browser session or after signing out.
3. Sign in as admin and approve the student, or assign representative access.
4. A representative submits a candidacy while an election is in draft status.
5. Admin starts the election.
6. An approved voter signs in and submits a vote.
7. Admin closes the election and views the final results.

## Privacy and security limitations
This is a learning/demo application, not a certified election system. Vote documents do not store the voter ID or admission number, and a separate receipt collection enforces one vote per account. This reduces direct linkage in the database, but it is not a cryptographically anonymous voting protocol: database administrators with access to all collections and timestamps may be able to correlate records. The vote and receipt writes are separate operations; production use should use a MongoDB transaction on a replica set and an independently reviewed election protocol.

Because OTP is intentionally removed, the app does not prove that the person registering controls the supplied email. The admin should verify student admission numbers against an authoritative college roster before approval. Do not deploy publicly or use it for a real election without HTTPS, secure deployment configuration, CSRF protection appropriate to the deployment, audit logging, backups, and independent security review.
