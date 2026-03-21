const express = require("express");
const cors = require("cors");
const { RtcTokenBuilder, RtcRole } = require("agora-token");

const app = express();
app.use(cors());

const APP_ID = process.env.AGORA_APP_ID;
const APP_CERTIFICATE = process.env.AGORA_APP_CERTIFICATE;

app.get("/token", (req, res) => {
  const { channelName, uid } = req.query;

  if (!channelName) {
    return res.status(400).json({ error: "channelName is required" });
  }

  const expireTime = 3600; // token valid for 1 hour
  const currentTime = Math.floor(Date.now() / 1000);
  const privilegeExpireTime = currentTime + expireTime;

  const token = RtcTokenBuilder.buildTokenWithUid(
    APP_ID,
    APP_CERTIFICATE,
    channelName,
    uid || 0,
    RtcRole.PUBLISHER,
    privilegeExpireTime,
    privilegeExpireTime
  );

  res.json({ token });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Token server running on port ${PORT}`));