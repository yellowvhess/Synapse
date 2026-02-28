/**
 * SYNAPSE CLIENT CORE
 * Security: AES-GCM (256) for data, RSA-OAEP (2048) for key exchange.
 */

// --- CONFIGURATION ---
const ICE_SERVERS = {
    iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] // Public STUN
};

// --- STATE (RAM ONLY) ---
let localStream; // Audio/Video placeholder
let peerConnection;
let dataChannel;
let socket;
let roomId;
let isInitiator = false;

// Crypto Keys
let myKeyPair; // RSA
let peerPublicKey; // RSA (imported)
let sharedSecretKey; // AES-GCM (The session key)

// UI Elements
const ui = {
    status: document.getElementById('status'),
    chat: document.getElementById('chat-area'),
    input: document.getElementById('msg-input'),
    btnSend: document.getElementById('btn-send'),
    btnFile: document.getElementById('btn-file'),
    fileInput: document.getElementById('file-input')
};

// --- 1. CRYPTO UTILITIES ---

const CryptoUtils = {
    // Генерация пары RSA ключей для handshake
    async generateRSAKeyPair() {
        return window.crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256"
            },
            true,
            ["encrypt", "decrypt"]
        );
    },

    // Генерация AES ключа для сессии (Symmetric)
    async generateAESKey() {
        return window.crypto.subtle.generateKey(
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
    },

    // Экспорт ключа в формат для отправки по сети (JWK/SPKI)
    async exportKey(key) {
        return window.crypto.subtle.exportKey("spki", key);
    },

    // Импорт публичного ключа собеседника
    async importKey(buffer) {
        return window.crypto.subtle.importKey(
            "spki",
            buffer,
            { name: "RSA-OAEP", hash: "SHA-256" },
            true,
            ["encrypt"]
        );
    },

    // Шифрование AES ключа публичным ключом собеседника (RSA)
    async wrapKey(aesKey, pubKey) {
        // Экспортируем AES как raw данные
        const rawKey = await window.crypto.subtle.exportKey("raw", aesKey);
        // Шифруем эти данные RSA ключом
        return window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, pubKey, rawKey);
    },

    // Расшифровка AES ключа своим приватным ключом (RSA)
    async unwrapKey(encryptedKeyBuffer, privKey) {
        const decryptedRaw = await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            privKey,
            encryptedKeyBuffer
        );
        return window.crypto.subtle.importKey(
            "raw",
            decryptedRaw,
            "AES-GCM",
            true,
            ["encrypt", "decrypt"]
        );
    },

    // Шифрование сообщения (AES-GCM)
    async encryptMessage(text, key) {
        const iv = window.crypto.getRandomValues(new Uint8Array(12)); // Уникальный IV для каждого сообщения
        const encoded = new TextEncoder().encode(text);
        
        const ciphertext = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            key,
            encoded
        );

        // Возвращаем IV + Ciphertext
        return { iv: Array.from(iv), data: Array.from(new Uint8Array(ciphertext)) };
    },

    // Расшифровка сообщения
    async decryptMessage(payload, key) {
        const iv = new Uint8Array(payload.iv);
        const data = new Uint8Array(payload.data);

        try {
            const decrypted = await window.crypto.subtle.decrypt(
                { name: "AES-GCM", iv: iv },
                key,
                data
            );
            return new TextDecoder().decode(decrypted);
        } catch (e) {
            console.error("Decryption failed", e);
            return "[CORRUPTED DATA]";
        }
    }
};

// --- 2. WEBRTC & SOCKET LOGIC ---

async function init() {
    logSystem("Generating 2048-bit RSA Key Pair...");
    myKeyPair = await CryptoUtils.generateRSAKeyPair();
    logSystem("Keys Generated. Connecting to Signaling Node...");

    socket = io();

    // Получаем ID комнаты из URL или генерируем новый
    const urlParams = new URLSearchParams(window.location.search);
    roomId = urlParams.get('room');

    if (!roomId) {
        roomId = Math.random().toString(36).substring(7);
        window.history.pushState({}, '', `?room=${roomId}`);
        logSystem(`Room created. Share URL: ${window.location.href}`);
        isInitiator = true;
    } else {
        logSystem(`Joining room: ${roomId}`);
    }

    socket.emit('join', roomId);

    socket.on('full', () => alert("Room is full!"));

    // Собеседник зашел
    socket.on('ready', () => {
        if (isInitiator) startWebRTC();
    });

    // Обработка сигналов
    socket.on('signal', async (data) => {
        if (data.sender === socket.id) return;

        if (data.type === 'offer') {
            if (!isInitiator) startWebRTC();
            await peerConnection.setRemoteDescription(new RTCSessionDescription(data.payload));
            const answer = await peerConnection.createAnswer();
            await peerConnection.setLocalDescription(answer);
            socket.emit('signal', { room: roomId, type: 'answer', payload: answer });
        } else if (data.type === 'answer') {
            await peerConnection.setRemoteDescription(new RTCSessionDescription(data.payload));
        } else if (data.type === 'candidate') {
            if (data.payload) {
                await peerConnection.addIceCandidate(new RTCIceCandidate(data.payload));
            }
        }
    });
}

function startWebRTC() {
    peerConnection = new RTCPeerConnection(ICE_SERVERS);

    // Обработка ICE кандидатов
    peerConnection.onicecandidate = (event) => {
        if (event.candidate) {
            socket.emit('signal', { room: roomId, type: 'candidate', payload: event.candidate });
        }
    };

    if (isInitiator) {
        // Создаем Data Channel (Инициатор)
        dataChannel = peerConnection.createDataChannel("synapse_secure");
        setupDataChannel();
        
        peerConnection.createOffer().then(async (offer) => {
            await peerConnection.setLocalDescription(offer);
            socket.emit('signal', { room: roomId, type: 'offer', payload: offer });
        });
    } else {
        // Принимаем Data Channel (Гость)
        peerConnection.ondatachannel = (event) => {
            dataChannel = event.channel;
            setupDataChannel();
        };
    }
}

// --- 3. DATA CHANNEL & KEY EXCHANGE FLOW ---

function setupDataChannel() {
    dataChannel.onopen = async () => {
        logSystem("P2P Tunnel Established. Starting Key Exchange...");
        ui.status.innerText = "HANDSHAKE...";
        
        // 1. Отправляем свой Публичный RSA ключ
        const exportedPubKey = await CryptoUtils.exportKey(myKeyPair.publicKey);
        sendRaw({ type: 'KEY_EXCHANGE_PUB', key: exportedPubKey });
    };

    dataChannel.onmessage = async (event) => {
        const msg = JSON.parse(event.data);

        // --- HANDSHAKE LOGIC ---
        if (msg.type === 'KEY_EXCHANGE_PUB') {
            // Получили чужой публичный RSA ключ
            peerPublicKey = await CryptoUtils.importKey(msg.key);
            
            if (isInitiator) {
                // Если мы инициатор, мы создаем AES ключ сессии
                sharedSecretKey = await CryptoUtils.generateAESKey();
                // Шифруем AES ключ чужим RSA ключом
                const encryptedAES = await CryptoUtils.wrapKey(sharedSecretKey, peerPublicKey);
                
                sendRaw({ type: 'KEY_EXCHANGE_AES', key: Array.from(new Uint8Array(encryptedAES)) });
                finalizeConnection();
            }
        } 
        else if (msg.type === 'KEY_EXCHANGE_AES') {
            // Получили зашифрованный AES ключ
            const encryptedBuffer = new Uint8Array(msg.key).buffer;
            sharedSecretKey = await CryptoUtils.unwrapKey(encryptedBuffer, myKeyPair.privateKey);
            finalizeConnection();
        }
        // --- CHAT LOGIC ---
        else if (msg.type === 'CHAT') {
            const text = await CryptoUtils.decryptMessage(msg.payload, sharedSecretKey);
            appendMessage(text, 'remote');
        }
        // --- FILE LOGIC ---
        else if (msg.type === 'FILE_CHUNK') {
             // (Упрощенно) В реальном приложении здесь сборка чанков
             logSystem(`Received encrypted file chunk: ${msg.payload.data.length} bytes`);
        }
    };
}

function finalizeConnection() {
    ui.status.innerText = "SECURE // ENCRYPTED (AES-GCM)";
    ui.status.classList.add('secure');
    ui.input.disabled = false;
    ui.btnSend.disabled = false;
    logSystem("E2EE Session Key Established. Channel is secure.");
}

// Отправка JSON объекта через канал
function sendRaw(obj) {
    dataChannel.send(JSON.stringify(obj));
}

// Отправка зашифрованного сообщения
async function sendMessage() {
    const text = ui.input.value;
    if (!text || !sharedSecretKey) return;

    const encryptedData = await CryptoUtils.encryptMessage(text, sharedSecretKey);
    sendRaw({ type: 'CHAT', payload: encryptedData });

    appendMessage(text, 'local');
    ui.input.value = '';
}

// --- 4. UI HELPERS ---

function logSystem(text) {
    const div = document.createElement('div');
    div.className = 'msg system';
    div.innerText = `[SYS] ${text}`;
    ui.chat.appendChild(div);
    ui.chat.scrollTop = ui.chat.scrollHeight;
}

function appendMessage(text, type) {
    const div = document.createElement('div');
    div.className = `msg ${type}`;
    div.innerText = text;
    ui.chat.appendChild(div);
    ui.chat.scrollTop = ui.chat.scrollHeight;
}

// Listeners
ui.btnSend.addEventListener('click', sendMessage);
ui.input.addEventListener('keypress', (e) => { if(e.key === 'Enter') sendMessage(); });

ui.btnFile.addEventListener('click', () => ui.fileInput.click());
ui.fileInput.addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    
    // Пример отправки метаданных (сама отправка чанков требует большего объема кода)
    const encryptedFilename = await CryptoUtils.encryptMessage(file.name, sharedSecretKey);
    sendRaw({ type: 'CHAT', payload: encryptedFilename }); // Отправляем имя как сообщение
    logSystem(`File upload started: ${file.name} (Logic stub)`);
});

// START
init();
