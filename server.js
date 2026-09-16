const express = require("express");
const cors = require("cors");

const { initializeApp, cert } = require("firebase-admin/app");
const { getFirestore } = require("firebase-admin/firestore");
const { getAuth } = require("firebase-admin/auth");

const { RtcTokenBuilder, RtcRole } = require("agora-token");

// --- Firebase Admin initialization ---
//
// WHY: `applicationDefault()` relies on Google Cloud's environment
// (a metadata server on GCE/Cloud Run, or GOOGLE_APPLICATION_CREDENTIALS
// pointing at a mounted file). Render provides neither, so ADC will fail
// once a real Firestore/Auth call is made — even though initializeApp()
// itself won't throw immediately.
//
// Fix: use a service account explicitly, loaded from environment
// variables you set in the Render dashboard (never commit the JSON key
// file itself to GitHub).
//
// In Render, set:
//   FIREBASE_PROJECT_ID
//   FIREBASE_CLIENT_EMAIL
//   FIREBASE_PRIVATE_KEY   (paste the key with literal \n for newlines,
//                           the .replace() below converts them back)
initializeApp({
  credential: cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, "\n"),
  }),
});

const db = getFirestore();
const auth = getAuth();

// --- Express app setup ---
//
// WHY: this was missing entirely, which is the direct cause of your
// "ReferenceError: app is not defined" crash.
const app = express();

// WHY: your React frontend runs on a different origin than this backend,
// so without CORS the browser will block the request before it ever
// reaches your route. Restrict `origin` to your real ChatFlow domain
// once you know it — using "*" is fine for early testing, but it means
// literally any website can call this endpoint from a user's browser.
app.use(
  cors({
    origin: process.env.ALLOWED_ORIGIN || "*",
  })
);

app.use(express.json());

app.get("/token", async (req, res) => {
  const { channelName } = req.query;
  const authHeader = req.headers.authorization;

  if (!channelName) {
    return res.status(400).json({ error: "channelName is required" });
  }
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing auth token" });
  }

  let decoded;
  try {
    decoded = await auth.verifyIdToken(authHeader.split(" ")[1]);
  } catch (e) {
    console.error("Firebase auth verification error:", e);
    return res.status(401).json({ error: e.message });
  }

  let callDoc;
  try {
    callDoc = await db.collection("Calls").doc(channelName).get();
  } catch (e) {
    console.error("Firestore read error:", e);
    return res.status(500).json({ error: "Failed to read call record" });
  }

  if (!callDoc.exists) {
    return res.status(404).json({ error: "Call not found" });
  }

  const { callerId, calleeId } = callDoc.data();
  if (decoded.uid !== callerId && decoded.uid !== calleeId) {
    return res.status(403).json({ error: "Not authorized for this channel" });
  }

  // --- Agora token generation ---
  //
  // WHY these were missing: RtcTokenBuilder/RtcRole were referenced in
  // your original file but never imported, and APP_ID/APP_CERTIFICATE
  // were never read from environment variables. Both would have caused
  // a crash the moment this line executed, even after fixing `app`.
  const APP_ID = process.env.AGORA_APP_ID;
  const APP_CERTIFICATE = process.env.AGORA_APP_CERTIFICATE;

  if (!APP_ID || !APP_CERTIFICATE) {
    console.error("Missing AGORA_APP_ID or AGORA_APP_CERTIFICATE env vars");
    return res.status(500).json({ error: "Server misconfiguration" });
  }

  const expireTime = 3600;
  const currentTime = Math.floor(Date.now() / 1000);
  const privilegeExpireTime = currentTime + expireTime;

  const token = RtcTokenBuilder.buildTokenWithUid(
    APP_ID,
    APP_CERTIFICATE,
    channelName,
    0, // 0 = let the client choose its own uid on join
    RtcRole.PUBLISHER,
    privilegeExpireTime, // token expiration
    privilegeExpireTime // privilege expiration
  );

  res.json({ token });
});

// --- Start server ---
//
// WHY: this was missing entirely. Render assigns a port dynamically via
// process.env.PORT and expects your app to bind to it — without this,
// Render's health check times out and the deploy is marked failed even
// if nothing else crashes.
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`agora-token-server listening on port ${PORT}`);
});
