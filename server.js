// server.js
import express from "express";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// layani file web di folder public/
app.use("/", express.static(path.join(__dirname, "public")));

// verifikasi data dari Telegram (biar orang iseng tidak bisa pura-pura)
function verifyTelegramInitData(initData, botToken) {
  try {
    const urlParams = new URLSearchParams(initData);
    const hash = urlParams.get("hash");
    if (!hash) return false;
    urlParams.delete("hash");

    const dataCheckString = [...urlParams.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}=${v}`)
      .join("\n");

    const secretKey = crypto
      .createHmac("sha256", "WebAppData")
      .update(botToken)
      .digest();

    const calcHash = crypto
      .createHmac("sha256", secretKey)
      .update(dataCheckString)
      .digest("hex");

    return crypto.timingSafeEqual(
      Buffer.from(calcHash, "hex"),
      Buffer.from(hash, "hex")
    );
  } catch {
    return false;
  }
}

// tombol test untuk memastikan semuanya hidup
app.post("/api/ping", (req, res) => {
  const { initData } = req.body || {};

  // ====== LOG DEBUG PENTING (aman, tidak cetak token penuh) ======
  const token = process.env.BOT_TOKEN || "";
  console.log("[DBG] initData present?", !!initData, "len:", (initData || "").length);
  console.log("[DBG] BOT_TOKEN suffix:", token ? token.slice(-8) : "(EMPTY)");
  // ===============================================================

  const ok = verifyTelegramInitData(initData || "", token);
  if (!ok) {
    console.log("[DBG] verifyTelegramInitData: FALSE");
    return res.status(401).json({ ok: false, msg: "initData invalid" });
  }

  const params = new URLSearchParams(initData);
  const user = JSON.parse(params.get("user") || "{}");

  console.log("[DBG] verifyTelegramInitData: TRUE for user_id:", user?.id);
  res.json({
    ok: true,
    user_id: user.id,
    username: user.username || null,
    msg: "Verify OK"
  });
});

app.get("/healthz", (_req, res) => res.send("ok"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("listening on", PORT));
