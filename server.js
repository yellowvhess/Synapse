const express = require('express');
const http = require('http');
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*" } // Разрешаем CORS для теста
});

app.use(express.static('public')); // Раздаем статику (клиент)

io.on('connection', (socket) => {
    console.log(`[Synapse] User connected: ${socket.id}`);

    // Присоединение к комнате
    socket.on('join', (roomId) => {
        const rooms = io.sockets.adapter.rooms;
        const room = rooms.get(roomId);

        if (room && room.size >= 2) {
            socket.emit('full'); // P2P только для двоих
            return;
        }

        socket.join(roomId);
        socket.emit('joined', roomId);
        
        // Уведомляем собеседника, что кто-то зашел (пора начинать WebRTC)
        socket.to(roomId).emit('ready');
    });

    // Пересылка WebRTC сигналов (Offer, Answer, ICE Candidates)
    // Сервер просто пересылает JSON, не вникая в содержимое
    socket.on('signal', (data) => {
        io.to(data.room).emit('signal', {
            sender: socket.id,
            type: data.type,
            payload: data.payload
        });
    });

    socket.on('disconnect', () => {
        console.log(`[Synapse] User disconnected: ${socket.id}`);
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`[Synapse] Server running on port ${PORT}`);
});
