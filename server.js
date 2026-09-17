const express = require("express");
const cors = require("cors");

const { initializeApp, cert } = require("firebase-admin/app");
const { getFirestore } = require("firebase-admin/firestore");
const { getAuth } = require("firebase-admin/auth");

const { RtcTokenBuilder, RtcRole } = require("agora-token");

initializeApp({
  credential: cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, "\n"),
  }),
});

const db = getFirestore();
const auth = getAuth();
const app = express();

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

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`agora-token-server listening on port ${PORT}`);
});
