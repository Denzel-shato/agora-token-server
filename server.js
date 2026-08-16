const admin = require("firebase-admin");
admin.initializeApp({ credential: admin.credential.applicationDefault() });
const db = admin.firestore();

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
    decoded = await admin.auth().verifyIdToken(authHeader.split(" ")[1]);
  } catch (e) {
    return res.status(401).json({ error: "Invalid auth token" });
  }

  const callDoc = await db.collection("Calls").doc(channelName).get();
  if (!callDoc.exists) {
    return res.status(404).json({ error: "Call not found" });
  }
  const { callerId, calleeId } = callDoc.data();
  if (decoded.uid !== callerId && decoded.uid !== calleeId) {
    return res.status(403).json({ error: "Not authorized for this channel" });
  }

  const expireTime = 3600;
  const currentTime = Math.floor(Date.now() / 1000);
  const privilegeExpireTime = currentTime + expireTime;

  const token = RtcTokenBuilder.buildTokenWithUid(
    APP_ID,
    APP_CERTIFICATE,
    channelName,
    0,
    RtcRole.PUBLISHER,
    privilegeExpireTime,
    privilegeExpireTime
  );
  res.json({ token });
});
