const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*', // عدل هذا لاحقاً للدوامين الآمن
  }
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'secret1234';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const usersFile = path.join(__dirname, 'users.json');

function readUsers() {
  try {
    const data = fs.readFileSync(usersFile);
    return JSON.parse(data);
  } catch {
    return [];
  }
}

function writeUsers(users) {
  fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
}

// تسجيل مستخدم جديد
app.post('/signup', async (req, res) => {
  const { username, password } = req.body;
  if(!username || !password) return res.status(400).json({ message: "يرجى إدخال اسم المستخدم وكلمة المرور" });

  let users = readUsers();
  if(users.find(u => u.username === username)) {
    return res.status(400).json({ message: "المستخدم موجود مسبقاً" });
  }
  const hash = await bcrypt.hash(password, 8);
  users.push({ username, password: hash });
  writeUsers(users);
  res.json({ message: "تم التسجيل بنجاح" });
});

// تسجيل الدخول
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if(!username || !password) return res.status(400).json({ message: "يرجى إدخال اسم المستخدم وكلمة المرور" });

  const users = readUsers();
  const user = users.find(u => u.username === username);
  if(!user) return res.status(400).json({ message: "المستخدم غير موجود" });
  const isValid = await bcrypt.compare(password, user.password);
  if(!isValid) return res.status(400).json({ message: "كلمة المرور خاطئة" });
  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token });
});

// التحقق من التوكن (middleware)
function authenticateToken(socket, next) {
  const token = socket.handshake.auth.token;
  if(!token) return next(new Error("مفقود التوكن"));
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if(err) return next(new Error("توكن غير صالح"));
    socket.user = user;
    next();
  });
}

io.use(authenticateToken);

const rooms = {}; // تخزين المستخدمين في كل غرفة

io.on('connection', (socket) => {
  const username = socket.user.username;
  console.log(`المستخدم ${username} متصل`);

  socket.on('joinRoom', (roomName) => {
    socket.join(roomName);

    if(!rooms[roomName]) rooms[roomName] = [];
    if(!rooms[roomName].includes(username)) rooms[roomName].push(username);

    io.to(roomName).emit('roomUsers', rooms[roomName]);
    io.to(roomName).emit('message', { user: 'system', text: `${username} انضم إلى الغرفة` });
  });

  socket.on('leaveRoom', (roomName) => {
    socket.leave(roomName);
    if(rooms[roomName]) {
      rooms[roomName] = rooms[roomName].filter(u => u !== username);
      io.to(roomName).emit('roomUsers', rooms[roomName]);
      io.to(roomName).emit('message', { user: 'system', text: `${username} غادر الغرفة` });
    }
  });

  socket.on('chatMessage', ({ roomName, message }) => {
    io.to(roomName).emit('message', { user: username, text: message });
  });

  socket.on('disconnecting', () => {
    for(const roomName of socket.rooms) {
      if(roomName !== socket.id) {
        if(rooms[roomName]) {
          rooms[roomName] = rooms[roomName].filter(u => u !== username);
          io.to(roomName).emit('roomUsers', rooms[roomName]);
          io.to(roomName).emit('message', { user: 'system', text: `${username} غادر الغرفة` });
        }
      }
    }
    console.log(`المستخدم ${username} فصل`);
  });
});

server.listen(PORT, () => {
  console.log(`السيرفر يعمل على البورت ${PORT}`);
});
