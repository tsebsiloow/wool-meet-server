// server.js
// npm i (上の package.json の依存をインストール)
// 起動: node server.js
// 環境変数（例）:
//   MONGO_URI, REDIS_URL, JWT_SECRET, PORT

const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const mongoose = require("mongoose");
const Redis = require("ioredis");
const { createAdapter } = require("@socket.io/redis-adapter");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");

const MONGO_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/chatdb";
const REDIS_URL = process.env.REDIS_URL || "redis://127.0.0.1:6379";
const JWT_SECRET = process.env.JWT_SECRET || "changeme_in_prod";
const PORT = process.env.PORT || 3000;

(async () => {
  // Mongo
  await mongoose.connect(MONGO_URI, { autoIndex: true });
  console.log("Mongo connected");

  // Schemas
  const UserSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    passwordHash: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
  });
  const MessageSchema = new mongoose.Schema({
    from: String,
    text: String,
    createdAt: { type: Date, default: Date.now },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: false }
  });

  const User = mongoose.model("User", UserSchema);
  const Message = mongoose.model("Message", MessageSchema);

  // Redis (ioredis) - for adapter and pub/sub and presence
  const pubClient = new Redis(REDIS_URL);
  const subClient = pubClient.duplicate();

  // Express + HTTP server
  const app = express();
  app.use(cors());
  app.use(bodyParser.json());

  // Basic API: register, login, recent messages
  app.post("/api/register", async (req, res) => {
    try {
      const { username, password } = req.body;
      if (!username || !password) return res.status(400).json({ error: "username/password required" });
      const exists = await User.findOne({ username });
      if (exists) return res.status(409).json({ error: "username taken" });
      const passwordHash = await bcrypt.hash(password, 10);
      const user = new User({ username, passwordHash });
      await user.save();
      return res.json({ ok: true });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ error: "server error" });
    }
  });

  app.post("/api/login", async (req, res) => {
    try {
      const { username, password } = req.body;
      if (!username || !password) return res.status(400).json({ error: "username/password required" });
      const user = await User.findOne({ username });
      if (!user) return res.status(401).json({ error: "invalid credentials" });
      const match = await bcrypt.compare(password, user.passwordHash);
      if (!match) return res.status(401).json({ error: "invalid credentials" });
      const token = jwt.sign({ uid: user._id.toString(), username: user.username }, JWT_SECRET, { expiresIn: "7d" });
      return res.json({ token, username: user.username });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ error: "server error" });
    }
  });

  // recent messages (last N)
  app.get("/api/messages/recent", async (req, res) => {
    const n = parseInt(req.query.n||"50");
    const msgs = await Message.find().sort({ createdAt: -1 }).limit(n).lean();
    res.json(msgs.reverse()); // 古い順に返す
  });

  // health
  app.get("/api/health", (req, res) => res.json({ ok: true }));

  const server = http.createServer(app);

  const io = new Server(server, {
    cors: { origin: "*", methods: ["GET","POST"] }
  });

  // attach redis adapter for scaling (pub/sub between socket nodes)
  io.adapter(createAdapter(pubClient, subClient));

  // Presence store in Redis: key "presence:<socketId>" => username ; also maintain set "online_users"
  const presencePrefix = "presence:";
  const onlineSet = "online_users";

  // Socket auth helper
  function verifyToken(token){
    try {
      return jwt.verify(token, JWT_SECRET);
    } catch(e) {
      return null;
    }
  }

  // Socket middleware to check token (client sends token in handshake auth)
  io.use(async (socket, next) => {
    const token = socket.handshake.auth && socket.handshake.auth.token;
    if(!token) return next(new Error("auth required"));
    const payload = verifyToken(token);
    if(!payload) return next(new Error("invalid token"));
    socket.user = { id: payload.uid, username: payload.username };
    next();
  });

  io.on("connection", async (socket) => {
    const { id } = socket;
    const { id: userId, username } = socket.user;
    console.log("socket connected:", id, "user:", username);

    // presence: set key and add to set
    await pubClient.set(`${presencePrefix}${id}`, username, "EX", 60*60); // 1h TTL
    await pubClient.sadd(onlineSet, username);

    // broadcast online users (gather from Redis)
    const all = await pubClient.smembers(onlineSet);
    io.emit("users", all);

    // Optionally: notify system
    io.emit("system", `${username} が参加しました`);

    // handle message
    socket.on("message", async (text) => {
      if(typeof text !== "string" || !text.trim()) return;
      const msg = new Message({ from: username, text: text.slice(0, 2000), userId });
      await msg.save();
      const payload = { from: username, text: msg.text, createdAt: msg.createdAt };
      // emit to all nodes/clients (adapter ensures multi-node broadcast)
      io.emit("message", payload);
      // also publish on a Redis channel for any external listeners if desired
      await pubClient.publish("chat_messages", JSON.stringify(payload));
    });

    // disconnect cleanup
    socket.on("disconnect", async () => {
      console.log("disconnect:", id);
      await pubClient.del(`${presencePrefix}${id}`);
      // remove one instance of username from set (if user has multiple sockets, this is naive).
      // For robust multi-socket per user, maintain set per username with socket ids.
      await pubClient.srem(onlineSet, username);

      const all2 = await pubClient.smembers(onlineSet);
      io.emit("users", all2);
      io.emit("system", `${username} が退出しました`);
    });

    // keep presence TTL alive while socket is connected (simple heartbeat)
    const keepalive = setInterval(() => {
      pubClient.expire(`${presencePrefix}${id}`, 60*60).catch(()=>{});
    }, 30*1000);

    socket.on("disconnect", () => clearInterval(keepalive));
  });

  server.listen(PORT, ()=> console.log("listening on", PORT));
})();
