# AeroBook backend (Node + Express + MongoDB Atlas)
1. Create a free MongoDB Atlas cluster, a database user, and allow network access (0.0.0.0/0 for Render).
2. Copy `.env.example` to `.env` and fill it in. Never commit `.env`.
3. `npm install` then `npm start` (API on http://localhost:5000).
4. Deploy on Render (Web Service): build `npm install`, start `npm start`, add the same variables.
5. In the frontend `index.html`, set the API URL line to your Render URL.
