//server/server.js 
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');

const cors = require('cors');

const moment = require('moment-timezone'); // ติดตั้ง library moment-timezone

const nodemailer = require('nodemailer');
const otpGenerator = require('otp-generator');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// เชื่อมต่อ MongoDB
mongoose.connect('mongodb+srv://sarisat:cpp1234@cluster0.ezcgx.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log("Connected to MongoDB successfully");
}).catch((error) => {
    console.error("Error connecting to MongoDB:", error);
});

// สร้าง Schema สำหรับคำถาม
const quizSchema = new mongoose.Schema({
    type: {
        type: String,
        required: true,
        enum: ['multiple-choice', 'essay'] // ✅ เพิ่มประเภทของคำถามที่รองรับ
    },
    question: String,
    options: [String],  // สำหรับคำถามปรนัย
    correct: mongoose.Schema.Types.Mixed,  // ใช้ Mixed เพื่อรองรับทั้งคำตอบแบบตัวเลือกและคำตอบแบบอัตนัย
    timer: Number,
    level: Number // เพิ่มระดับของคำถาม
});

const Quiz = mongoose.model('Quiz', quizSchema);

// สร้าง Schema สำหรับเก็บประวัติการเล่นของผู้เล่น
const scoreSchema = new mongoose.Schema({
    name: String,
    score: Number,
    username: { type: String, required: true },
    roomCode: { type: String, required: true },
    datePlayed: { type: Date, required: true },
    uniqueIdentifier: { type: String, required: true},  
});

const PlayerScore = mongoose.model('PlayerScore', scoreSchema);

// สร้าง Schema สำหรับผู้ใช้
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    email: { type: String, required: true }, // ฟิลด์ใหม่
    type: { type: String, enum: ['Admin', 'Player'], required: true }
});

const User = mongoose.model('User', userSchema);

const otpSchema = new mongoose.Schema({
    username: { type: String, required: true },
    otp: { type: String, required: true },
    expiresAt: { type: Date, required: true }
});

const OTP = mongoose.model('OTP', otpSchema);

// สร้าง Schema และ Model สำหรับ RoomCode
const roomCodeSchema = new mongoose.Schema({
    roomCode: { type: String, required: true },
    selectedQuestions: [{
        type: {
            type: String,
            required: true,
            enum: ['multiple-choice', 'essay'] // ✅ เพิ่มประเภทของคำถามที่รองรับ
        },
        question: String,
        options: [String],
        correct: Number,
        timer: Number,
        level: Number,
    }],  // เก็บข้อมูลคำถามทั้งหมด
    gameStarted: { type: Boolean, default: false }, // เพิ่มฟิลด์ gameStarted
    totalScore: { type: Number, default: 0 },
    totalTime: { type: Number, default:0 },
    totalmultipleChoice: { type: Number, default:0 },
    totalEssay: { type: Number, default:0 },
    totalQuestions: { type: Number, default:0 }
});

const RoomCode = mongoose.model('RoomCode', roomCodeSchema);

// Schema และ Model สำหรับการบันทึกประวัติ
const gameHistorySchema = new mongoose.Schema({
    name: String,
    username: String,
    roomCode: String,
    score: Number,
    date: { type: Date, default: Date.now }
});

const GameHistory = mongoose.model('GameHistory', gameHistorySchema);

const corsOptions = {
    origin: 'https://sarisa-28pcpp-github-io.onrender.com', // หรือ URL ที่คุณใช้
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type'],
};

// สร้าง transporter สำหรับส่ง email
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'feelbbfeel@gmail.com', // กรอก Gmail ของคุณ
        pass: 'euia rphs ftbv defg'   // กรอกรหัสผ่านหรือ app password
    }
});

function sendOTP(email, otp) {
    const mailOptions = {
        from: 'your-email@gmail.com',
        to: email,
        subject: 'Your OTP code for resetting website passwordWebsite for Evaluating Programming andAlgorithmic Expertise Using C++',
        text: `Your OTP code is: ${otp}. It will expire in 5 minutes.`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log('Error sending OTP:', error);
        } else {
            console.log('OTP sent:', info.response);
        }
    });
}

app.use(cors(corsOptions));

app.use(cors());

// Serve HTML Files
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, ".../public/index.html"));
});
app.get("/addquestion.html", (req, res) => {
    res.sendFile(path.join(__dirname, ".../public/addquestion.html"));
});
app.get("/history.html", (req, res) => {
    res.sendFile(path.join(__dirname, ".../public/history.html"));
});
app.get("/play.html", (req, res) => {
    res.sendFile(path.join(__dirname, ".../public/play.html"));
});
app.get("/roomcode.html", (req, res) => {
    res.sendFile(path.join(__dirname, ".../public/roomcode.html"));
});
app.get("/seeroom.html", (req, res) => {
    res.sendFile(path.join(__dirname, ".../public/seeroom.html"));
});
app.get("/setting.html", (req, res) => {
    res.sendFile(path.join(__dirname, ".../public/setting.html"));
});
app.get("/start.html", (req, res) => {
    res.sendFile(path.join(__dirname, ".../public/start.html"));
});
app.get("/scores.html", (req, res) => {
    res.sendFile(path.join(__dirname, ".../public/scores.html"));
});


// เส้นทางสำหรับการล็อกอิน
app.post('/login', async (req, res) => {
    const { username, password, type } = req.body;

    try {
        const user = await User.findOne({ username, password, type});
        if (!user) {
            return res.status(400).send('Invalid credentials');
        }

        // ส่งข้อมูลประเภทของผู้ใช้กลับไป (Admin/Player)
        res.status(200).json({ type: user.type });

        // คุณไม่ต้องส่ง <script> ที่เกี่ยวข้องกับ sessionStorage ที่นี่
        // ให้หน้าต่างๆ ใช้การเก็บข้อมูลจาก sessionStorage แทน
    } catch (error) {
        console.error('Error logging in:', error);
        res.status(500).send('Error logging in');
    }
});

// เส้นทางสำหรับเพิ่มคำถามใหม่
app.post('/add-quiz', async (req, res) => {
    const { type, question, options, correct, timer, level } = req.body;

    const newQuiz = new Quiz({
        type,
        question,
        options: options || [],  // ถ้าไม่ใช่คำถามปรนัย จะไม่ใช้ options
        correct,
        timer,
        level
    });

    try {
        await newQuiz.save();
        res.status(200).send('Quiz added successfully!');
    } catch (error) {
        console.error('Error adding quiz:', error);
        res.status(500).send('Error adding quiz');
    }
});

// เส้นทางสำหรับดึงคำถามทั้งหมด
app.get('/quiz', async (req, res) => {
    try {
        const quizzes = await Quiz.find();
        res.json(quizzes);
    } catch (error) {
        console.error('Error fetching quizzes:', error);
        res.status(500).send('Error fetching quizzes');
    }
});

// เส้นทางสำหรับดึงคะแนนผู้เล่นทั้งหมดพร้อม Room Code
app.get('/scores', async (req, res) => {
    try {
        const scores = await PlayerScore.find().sort({ datePlayed: -1 }); // เรียงตามวันที่ล่าสุด
        res.json(scores);
    } catch (error) {
        console.error('Error fetching scores:', error);
        res.status(500).send('Error fetching scores');
    }
});

// ดึง RoomCode ทั้งหมด
app.get('/roomcodes', async (req, res) => {
    try {
        const roomCodes = await RoomCode.find();
        res.json(roomCodes);
    } catch (error) {
        console.error('Error fetching room codes:', error);
        res.status(500).send('Error fetching room codes');
    }
});

// ดึง RoomCode เฉพาะรายการที่ต้องการ
app.get('/roomcode/:roomCode', async (req, res) => {
    const { roomCode } = req.params;

    try {
        const room = await RoomCode.findOne({ roomCode });
        if (!room) {
            return res.status(404).send('Room code not found');
        }
        res.json(room);
    } catch (error) {
        console.error('Error fetching room code:', error);
        res.status(500).send('Error fetching room code');
    }
});

// เส้นทางสำหรับบันทึกคะแนนผู้เล่น
app.post('/save-score', async (req, res) => {
    const { name, score, username, roomCode, datePlayed, uniqueIdentifier } = req.body;

    // ตรวจสอบข้อมูลที่ส่งมาจาก client
    if (!name || !score || !username || !roomCode || !datePlayed || !uniqueIdentifier) {
        return res.status(400).json({ error: "Missing required fields" });
    }

    // ปรับเวลาให้ตรงกับเขตเวลาประเทศไทย
    const thailandDate = moment.tz(datePlayed, 'Asia/Bangkok').toDate();     

    // สร้างข้อมูลใหม่ใน MongoDB โดยไม่ตรวจสอบการซ้ำ
    const newPlayerScore = new PlayerScore({
        name,
        score,
        username,
        roomCode,
        datePlayed: thailandDate,
        uniqueIdentifier
    });

    try {
        await newPlayerScore.save();

        // บันทึกประวัติการเล่นใน GameHistory
        const newGameHistory = new GameHistory({
            name,
            username,
            roomCode,
            score,
            date: thailandDate
        });
        await newGameHistory.save();

        res.status(200).json({ message: "Score saved successfully" });
    } catch (err) {
        console.error("Error saving score:", err);
        res.status(500).json({ error: "Error saving score" });
    }
});

// เส้นทางสำหรับสมัครสมาชิก
app.post('/register', async (req, res) => {
    const { username, password, type, email } = req.body; // รับค่า email ด้วย

    // ตรวจสอบเงื่อนไขการสมัคร
    if (type === 'Admin' && !email.endsWith('@gmail.com')) { // แก้จากการเช็ค username มาเป็น email
        return res.status(400).send('Admin email must use a @gmail.com address.');
    }
    if (type === 'Player' && (username.length !== 10 || isNaN(username))) {
        return res.status(400).send('Player username must be a 10-digit number.');
    }

    try {
        const newUser = new User({ username, password, type, email }); // เพิ่ม email ไปที่ newUser
        await newUser.save();
        res.status(201).send('User registered successfully!');
    } catch (error) {
        if (error.code === 11000) {
            res.status(400).send('Username already exists.');
        } else {
            console.error('Error registering user:', error);
            res.status(500).send('Error registering user.');
        }
    }
});

// API สำหรับบันทึก RoomCode และข้อมูลคำถาม
app.post('/save-roomcode', async (req, res) => {
    const { roomCode, selectedQuestions, totalScore, totalTime, totalmultipleChoice, totalEssay, totalQuestions } = req.body;

    // ตรวจสอบว่า roomCode ซ้ำหรือไม่
    const existingRoom = await RoomCode.findOne({ roomCode });
    if (existingRoom) {
        return res.status(400).json({ error: "Room code นี้มีอยู่แล้ว." });
    }

    // สร้างข้อมูลใหม่ใน MongoDB
    const newRoom = new RoomCode({
        roomCode: roomCode,
        selectedQuestions: selectedQuestions.map(q => ({
            type: q.type,
            question: q.question,
            options: q.options,
            correct: q.correct,
            timer: q.timer, // เพิ่ม timer
            level: q.level
        })),
        totalScore: totalScore,
        totalTime: totalTime,
        totalmultipleChoice: totalmultipleChoice,
        totalEssay: totalEssay,
        totalQuestions: totalQuestions,
    });

    try {
        await newRoom.save();
        res.status(200).json({ message: "บันทึก RoomCode สำเร็จ" });
    } catch (err) {
        res.status(500).json({ error: "เกิดข้อผิดพลาดในการบันทึกข้อมูล." });
    }
});

// เส้นทางสำหรับอัปเดตพาสเวิร์ด
app.put('/update-password', async (req, res) => {
    const { username, oldPassword, newPassword, otpCode } = req.body;

    const otpDoc = await OTP.findOne({ username, otp: otpCode });
    if (!otpDoc || otpDoc.expiresAt < new Date()) {
        return res.status(400).send('Invalid or expired OTP');
    }

    if (!username || !oldPassword || !newPassword || !otpCode) {
        return res.status(400).send('Please provide all fields: username, oldPassword, newPassword and OTP');
    }

    try {
        const user = await User.findOne({ username, password: oldPassword });
        
        if (!user) {
            return res.status(400).send('Invalid username or old password');
        }

        // อัปเดตรหัสผ่านใหม่
        user.password = newPassword;
        await user.save();

        res.status(200).send('Password updated successfully!');
    } catch (error) {
        console.error('Error updating password:', error);
        res.status(500).send('Error updating password');
    }
});

app.post('/reset-password', async (req, res) => {
    const { username, oldPassword, newPassword, otpCode, type  } = req.body;

    if (!username || !oldPassword || !newPassword || !otpCode || !type) {
        return res.status(400).send('Please provide all fields: username, oldPassword, newPassword, OTP, and type');
    }

    // ตรวจสอบ OTP
    const otpDoc = await OTP.findOne({ username, otp: otpCode });
    if (!otpDoc || otpDoc.expiresAt < new Date()) {
        return res.status(400).send('Invalid or expired OTP');
    }

    // ค้นหาผู้ใช้ในฐานข้อมูล
    const user = await User.findOne({ username, password: oldPassword, type });
    if (!user) {
        return res.status(400).send('Invalid type, username or old password');
    }

    // อัปเดตรหัสผ่านใหม่
    user.password = newPassword;
    await user.save();

    // ลบ OTP ที่หมดอายุ
    await OTP.deleteOne({ username, otp: otpCode });

    res.status(200).send('Password reset successful!');
});

app.post('/reset-password2', async (req, res) => {
    const { username, email, newPassword, otpCode, type  } = req.body;

    if (!username || !email || !newPassword || !otpCode || !type) {
        return res.status(400).send('Please provide all fields: username, email, newPassword, OTP, and type');
    }

    // ตรวจสอบ OTP
    const otpDoc = await OTP.findOne({ username, otp: otpCode });
    if (!otpDoc || otpDoc.expiresAt < new Date()) {
        return res.status(400).send('Invalid or expired OTP');
    }

    // ค้นหาผู้ใช้ในฐานข้อมูล
    const user = await User.findOne({ username, email, type });
    if (!user) {
        return res.status(400).send('Invalid type, username or old password');
    }

    // อัปเดตรหัสผ่านใหม่
    user.password = newPassword;
    await user.save();

    // ลบ OTP ที่หมดอายุ
    await OTP.deleteOne({ username, otp: otpCode });

    res.status(200).send('Password reset successful!');
});

// เส้นทางสำหรับดึงข้อมูล RoomCode ทั้งหมด
app.get('/api/roomcodes', async (req, res) => {
    try {
        const roomCodes = await RoomCode.find();
        res.json(roomCodes);
    } catch (error) {
        console.error('Error fetching room codes:', error);
        res.status(500).send('Error fetching room codes');
    }
});

// เส้นทางสำหรับดึงข้อมูลคำถามใน RoomCode ที่ระบุ
app.get('/api/roomcodes/:roomCode', async (req, res) => {
    const { roomCode } = req.params;

    try {
        const room = await RoomCode.findOne({ roomCode });
        if (!room) {
            return res.status(404).send('Room code not found');
        }

        res.json(room);
    } catch (error) {
        console.error('Error fetching room code details:', error);
        res.status(500).send('Error fetching room code details');
    }
});

// เส้นทางสำหรับลบ RoomCode
app.delete('/api/roomcode/:roomCode', async (req, res) => {
    const { roomCode } = req.params;

    try {
        // ค้นหาและลบ RoomCode ที่ตรงกับ roomCode
        const deletedRoom = await RoomCode.findOneAndDelete({ roomCode });

        if (!deletedRoom) {
            return res.status(404).send('Room code not found');
        }

        res.status(200).json({ message: 'Room code deleted successfully' });
    } catch (error) {
        console.error('Error deleting room code:', error);
        res.status(500).send('Error deleting room code');
    }
});

// เส้นทางสำหรับเริ่มเกม
app.post('/start-game/:roomCode', async (req, res) => {
    const { roomCode } = req.params;

    try {
        // ค้นหาข้อมูล RoomCode ใน MongoDB
        const room = await RoomCode.findOne({ roomCode });

        if (!room) {
            return res.status(404).send('Room not found.');
        }

        // อัพเดตสถานะว่าเกมเริ่มแล้ว
        room.gameStarted = true;
        await room.save();

        // ส่งข้อมูลให้ผู้เล่นทุกคนใน RoomCode ว่าเกมเริ่มแล้ว
        io.to(roomCode).emit('game-started');

        res.status(200).send('Game started!');
    } catch (error) {
        console.error('Error starting the game:', error);
        res.status(500).send('Error starting the game');
    }
});

// เมื่อผู้เล่นเข้าร่วม RoomCode
let roomPlayers = {};  // เก็บข้อมูลผู้เล่นที่เชื่อมต่อในแต่ละห้อง
let roomAdmins = {};   // เก็บ admin ของแต่ละห้อง

io.on('connection', (socket) => {
    console.log('A player connected');

    socket.on('join-room', (roomCode, playerName, isAdmin) => {
        socket.join(roomCode);
        console.log(`Player ${playerName} joined room ${roomCode}, Admin: ${isAdmin}`);

        if (isAdmin) {
            roomAdmins[roomCode] = socket.id; // กำหนด Admin ของห้อง
            console.log(`Admin ${playerName} assigned to room ${roomCode}`);
        } else {
            if (!roomPlayers[roomCode]) {
                roomPlayers[roomCode] = [];
            }
            roomPlayers[roomCode].push({ id: socket.id, name: playerName });

            // ส่งข้อมูลรายชื่อผู้เล่นให้กับทุกคนในห้อง (ไม่รวม admin)
            io.to(roomCode).emit('update-player-list', roomPlayers[roomCode].map(p => p.name));
        }

        console.log(`Players in room ${roomCode}:`, roomPlayers[roomCode]?.length || 0);
    });

    socket.on('disconnect', () => {
        // ตรวจสอบว่าผู้เล่นอยู่ใน roomPlayers หรือไม่
        for (let roomCode in roomPlayers) {
            let playerIndex = roomPlayers[roomCode].findIndex(p => p.id === socket.id);
            if (playerIndex !== -1) {
                let playerName = roomPlayers[roomCode][playerIndex].name;
                roomPlayers[roomCode].splice(playerIndex, 1);
                io.to(roomCode).emit('update-player-list', roomPlayers[roomCode].map(p => p.name));
                console.log(`Player ${playerName} disconnected from room ${roomCode}`);
                return;  // ออกจาก loop ทันทีเพื่อป้องกัน admin โดนลบผิดพลาด
            }
        }

        // ตรวจสอบว่าเป็น Admin หรือไม่
        for (let roomCode in roomAdmins) {
            if (roomAdmins[roomCode] === socket.id) {
                console.log(`Admin disconnected from room ${roomCode}`);
                delete roomAdmins[roomCode];
                return;
            }
        }
    });

    socket.on('game-over', async (playerName, roomCode, score) => {
        try {
            await fetch('/add-game-history', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: playerName, roomCode, score })
            });

            // ลบ Player ออกจากห้องเมื่อเกมจบ
            if (roomPlayers[roomCode]) {
                roomPlayers[roomCode] = roomPlayers[roomCode].filter(p => p.name !== playerName);
                io.to(roomCode).emit('update-player-list', roomPlayers[roomCode].map(p => p.name));
                console.log(`Player ${playerName} removed from room ${roomCode} after game over`);
            }
        } catch (error) {
            console.error('Error saving game history:', error);
        }
    });

    socket.on('close-popup', (roomCode) => {
        if (roomAdmins[roomCode] === socket.id) {
            console.log(`Admin closed the popup in room ${roomCode}`);
            delete roomAdmins[roomCode];
        }
    });
});

// การตรวจสอบใน server
app.post('/send-otp', async (req, res) => {
    const { email, username, type } = req.body;  // รับ email และ username จาก client
    console.log("Received email:", email, "Received username:", username, "Received type:", type );  // ตรวจสอบค่าที่รับมา

    if (!email || !username || !type) {
        return res.status(400).send('Please provide email, username, and user type.');
    }

    try {
        // ค้นหาผู้ใช้โดยใช้ username
        const user = await User.findOne({ username, type });
        console.log("User found:", user, "Type found:", type );  // ตรวจสอบว่าพบผู้ใช้ในฐานข้อมูลไหม

        if (!user) {
            return res.status(400).send('User not found');
        }

        // ตรวจสอบว่า email ที่ได้รับมาจาก client ตรงกับ email ของผู้ใช้ในฐานข้อมูลหรือไม่
        if (user.email !== email) {
            return res.status(400).send('Email does not match the one on record');
        }

        // สร้าง OTP
        const otp = otpGenerator.generate(6, { upperCase: false, specialChars: false });
        const expiresAt = new Date();
        expiresAt.setMinutes(expiresAt.getMinutes() + 5);

        // บันทึก OTP ในฐานข้อมูล
        const otpDoc = new OTP({ username: user.username, otp, expiresAt });
        await otpDoc.save();

        // ส่ง OTP ไปยัง email
        sendOTP(email, otp);
        res.status(200).send('OTP sent');
    } catch (error) {
        console.error('Error sending OTP:', error);
        res.status(500).send('Error sending OTP');
    }
});

// Endpoint สำหรับดึงประวัติทั้งหมดของผู้ใช้
app.get('/history/:username', async (req, res) => {
    const { username } = req.params;

    try {
        // ค้นหาประวัติการเล่นทั้งหมดสำหรับผู้เล่นในฐานข้อมูล
        const historyData = await GameHistory.find({ username });

        if (!historyData.length) {
            return res.status(404).json({ error: 'No history found for this user' });
        }

        // ส่งข้อมูลทั้งหมดที่ดึงมาในรูปแบบ JSON
        res.json(historyData);
    } catch (error) {
        console.error('Error fetching history:', error);
        res.status(500).json({ error: 'Error fetching history' });
    }
});

// Endpoint สำหรับดึงประวัติของผู้ใช้ใน RoomCode ที่เฉพาะเจาะจง
app.get('/history/:username/:roomCode', async (req, res) => {
    const { username, roomCode } = req.params;

    try {
        // ดึงข้อมูลคะแนนของผู้เล่นใน RoomCode ที่กำหนด
        const roomHistory = await GameHistory.find({ username, roomCode });  // ใช้ find แทน findOne เพื่อดึงข้อมูลหลายตัว

        if (!roomHistory.length) {
            return res.status(404).json({ error: 'Room history not found' });
        }

        // ส่งข้อมูลในรูปแบบ JSON
        res.json(roomHistory);
    } catch (error) {
        console.error('Error fetching room history:', error);
        res.status(500).json({ error: 'Error fetching room history' });
    }
});

// เพิ่มข้อมูลประวัติการเล่นเกม (ตัวอย่าง)
app.post('/add-game-history', async (req, res) => {
    const { name, username, roomCode, score } = req.body;
    const newGameHistory = new GameHistory({ name, username, roomCode, score });
    
    try {
        await newGameHistory.save();
        res.status(200).json({ message: 'Game history saved' });
    } catch (error) {
        res.status(500).json({ message: 'Error saving game history' });
    }
});

// เริ่มเซิร์ฟเวอร์
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
