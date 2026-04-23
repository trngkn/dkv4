/**
 * PhatNguoi API Server - Tra cứu phạt nguội qua CLI trên VPS
 * 
 * Kiến trúc:
 *   1. EzSolver (Python, port 8191) → bypass Cloudflare Turnstile
 *   2. Server này (Node.js, port 3001) → proxy API + expose REST endpoint
 * 
 * Cách hoạt động:
 *   - Lấy Turnstile token từ EzSolver service
 *   - Gọi api.phatnguoi.com/v1/violations với token + HMAC signature
 *   - Parse kết quả và trả về JSON sạch
 * 
 * LƯU Ý QUAN TRỌNG:
 *   - Turnstile token là SINGLE-USE: mỗi token chỉ dùng được 1 request
 *   - bypassCache=true yêu cầu token MỚI (token cũ sẽ bị 403)
 *   - Luôn invalidate token sau mỗi lần gọi API
 * 
 * Sử dụng trên VPS:
 *   1. python EzSolver/service.py   (chạy trước)
 *   2. node phatnguoi_api.js        (chạy API)
 *   3. curl "http://localhost:3001/api/lookup?plate=51L57382"
 */

import express from 'express';
import cors from 'cors';
import crypto from 'crypto';

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ==================== CẤU HÌNH ====================
const CONFIG = {
    // Chế độ giải Turnstile: 'ezsolver' hoặc 'capsolver'
    SOLVER_MODE: process.env.SOLVER_MODE || 'ezsolver',
    
    // EzSolver service (local Chrome automation)
    EZSOLVER_URL: process.env.EZSOLVER_URL || 'http://localhost:8191/solve',
    
    // CapSolver (dịch vụ giải captcha trả phí, ~$1-2/1000 lần)
    // Đăng ký tại: https://www.capsolver.com
    CAPSOLVER_KEY: process.env.CAPSOLVER_KEY || '',
    
    // PhatNguoi.com Turnstile
    SITE_KEY: '0x4AAAAAAAeYZSLe26PNB1mK',
    SITE_URL: 'https://phatnguoi.com/',
    
    // PhatNguoi.com direct API
    API_URL: 'https://api.phatnguoi.com/v1/violations',
    API_SECRET: 'e6263836144c1a04ece5644347f8d221f1ca112a1d183efe831f361f97ab63ef',
    
    // Solver timeout
    SOLVER_TIMEOUT: 60,
};

// ==================== REQUEST QUEUE ====================
// Chỉ xử lý 1 request tra cứu tại 1 thời điểm.
// Request tiếp theo phải đợi request trước hoàn tất.
let requestChain = Promise.resolve();
let queueSize = 0;

function enqueue(fn) {
    queueSize++;
    if (queueSize > 1) {
        console.log(`[QUEUE] ⏳ Đang chờ... (${queueSize - 1} request phía trước)`);
    }
    const task = requestChain.then(() => fn()).finally(() => { queueSize--; });
    requestChain = task.catch(() => {}); // Đảm bảo chain không bị reject
    return task;
}

// ==================== TOKEN MANAGEMENT ====================
// Token Turnstile là single-use nên KHÔNG cache.
// Mỗi lần tra cứu cần lấy token mới.
let tokenFetching = false;
let tokenQueue = [];

/**
 * Lấy Turnstile token - tự chọn backend theo SOLVER_MODE
 */
async function getTurnstileToken() {
    if (tokenFetching) {
        console.log('[TOKEN] ⏳ Đang chờ token từ request khác...');
        return new Promise((resolve, reject) => {
            tokenQueue.push({ resolve, reject });
        });
    }
    
    tokenFetching = true;
    const mode = CONFIG.SOLVER_MODE;
    console.log(`[TOKEN] 🔐 Giải Turnstile qua ${mode}...`);
    
    try {
        const startTime = Date.now();
        let token;
        
        if (mode === 'capsolver') {
            token = await solveViaCapsolver();
        } else {
            token = await solveViaEzSolver();
        }
        
        const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
        console.log(`[TOKEN] ✅ Đã nhận token (${elapsed}s): ${token.substring(0, 30)}...`);
        
        tokenQueue.forEach(q => q.resolve(token));
        tokenQueue = [];
        return token;
    } catch (err) {
        console.error(`[TOKEN] ❌ Lỗi: ${err.message}`);
        tokenQueue.forEach(q => q.reject(err));
        tokenQueue = [];
        throw err;
    } finally {
        tokenFetching = false;
    }
}

/**
 * Backend 1: EzSolver (local Chrome, cần Xvfb trên VPS)
 */
async function solveViaEzSolver() {
    const response = await fetch(CONFIG.EZSOLVER_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'ngrok-skip-browser-warning': 'true' },
        body: JSON.stringify({
            sitekey: CONFIG.SITE_KEY,
            siteurl: CONFIG.SITE_URL,
            timeout: CONFIG.SOLVER_TIMEOUT
        })
    });
    const data = await response.json();
    if (data.token) return data.token;
    throw new Error(data.error || 'EzSolver không trả về token');
}

/**
 * Backend 2: CapSolver (dịch vụ trả phí, không cần Chrome)
 * Đăng ký: https://www.capsolver.com → lấy API key
 * Giá: ~$1-2 / 1000 lần giải
 */
async function solveViaCapsolver() {
    if (!CONFIG.CAPSOLVER_KEY) {
        throw new Error('Chưa cấu hình CAPSOLVER_KEY. Set env: CAPSOLVER_KEY=your_key');
    }
    
    // Bước 1: Tạo task
    const createRes = await fetch('https://api.capsolver.com/createTask', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            clientKey: CONFIG.CAPSOLVER_KEY,
            task: {
                type: 'AntiTurnstileTaskProxyLess',
                websiteURL: CONFIG.SITE_URL,
                websiteKey: CONFIG.SITE_KEY,
            }
        })
    });
    const createData = await createRes.json();
    
    if (createData.errorId !== 0) {
        throw new Error(`CapSolver createTask: ${createData.errorDescription || 'Unknown error'}`);
    }
    
    const taskId = createData.taskId;
    console.log(`[CAPSOLVER] Task created: ${taskId}`);
    
    // Bước 2: Poll kết quả
    for (let i = 0; i < 30; i++) {
        await new Promise(r => setTimeout(r, 2000));
        
        const resultRes = await fetch('https://api.capsolver.com/getTaskResult', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                clientKey: CONFIG.CAPSOLVER_KEY,
                taskId: taskId
            })
        });
        const resultData = await resultRes.json();
        
        if (resultData.status === 'ready') {
            return resultData.solution?.token;
        }
        if (resultData.errorId !== 0) {
            throw new Error(`CapSolver: ${resultData.errorDescription}`);
        }
    }
    
    throw new Error('CapSolver timeout sau 60s');
}

// ==================== API SIGNING ====================

/**
 * Tạo HMAC-SHA256 signature cho API trực tiếp
 */
function createSignature(method, path, timestamp, body) {
    const bodyStr = JSON.stringify(body);
    const bodyHash = crypto.createHash('sha256').update(bodyStr).digest('hex');
    const signString = `${method}\n${path}\n${timestamp}\n${bodyHash}`;
    return crypto.createHmac('sha256', CONFIG.API_SECRET).update(signString).digest('hex');
}

// ==================== LOOKUP FUNCTIONS ====================

/**
 * Tra cứu qua API trực tiếp (api.phatnguoi.com)
 * 
 * LƯU Ý: Turnstile token là SINGLE-USE.
 * bypassCache=false dùng cache server-side (nhanh, không tốn token phụ)
 * bypassCache=true bắt CSGT trả data mới (cần token mới)
 */
async function lookupDirectAPI(plate, vehicleType, token, bypassCache = false) {
    const timestamp = Math.floor(Date.now() / 1000).toString();
    const payload = {
        licensePlate: plate,
        vehicleType: vehicleType,
        userType: 'standard',
        bypassCache: bypassCache
    };
    
    const signature = createSignature('POST', '/v1/violations', timestamp, payload);
    
    console.log(`[API] 📡 Gọi API: biển=${plate}, loại=${vehicleType}, bypassCache=${bypassCache}`);
    
    const response = await fetch(CONFIG.API_URL, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Platform': 'web',
            'X-Timestamp': timestamp,
            'X-Signature': signature,
            'X-Turnstile-Token': token,
            'Origin': 'https://phatnguoi.com',
            'Referer': 'https://phatnguoi.com/',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
        },
        body: JSON.stringify(payload)
    });
    
    const httpStatus = response.status;
    let result;
    
    try {
        result = await response.json();
    } catch (e) {
        throw new Error(`API trả về không phải JSON (HTTP ${httpStatus})`);
    }
    
    // Xử lý lỗi HTTP (4xx, 5xx)
    if (httpStatus >= 400) {
        const errCode = result.error?.code || 'UNKNOWN';
        const errMsg = result.error?.message || `HTTP ${httpStatus}`;
        console.log(`[API] ❌ Lỗi HTTP ${httpStatus}: ${errCode} - ${errMsg}`);
        return { _error: true, _httpStatus: httpStatus, error: result.error };
    }
    
    // Log kết quả
    const vd = result.violationData || {};
    const cacheInfo = result.cache ? `(cache: ${result.cache.source}, stale: ${result.cache.isStale})` : '';
    console.log(`[API] ✅ HTTP ${httpStatus}: ${vd.totalViolations || 0} vi phạm ${cacheInfo}`);
    
    return result;
}

// ==================== FORMAT KẾT QUẢ ====================

/**
 * Format kết quả từ direct API sang dạng sạch
 * Mapping fields theo đúng script.min.js của phatnguoi.com
 */
function formatDirectAPIResult(plate, data) {
    if (!data) return { success: false, plate, message: 'Không có dữ liệu' };
    
    // Lỗi từ API (HTTP 4xx/5xx)
    if (data._error) {
        const errCode = data.error?.code || 'UNKNOWN';
        const errMsg = data.error?.message || 'Lỗi từ API';
        return {
            success: false,
            plate,
            error_code: errCode,
            message: errMsg
        };
    }
    
    const vd = data.violationData || {};
    const result = {
        success: true,
        plate: data.licensePlate || plate,
        vehicle_type: data.vehicleType || '',
        total_violations: vd.totalViolations || 0,
        unhandled: vd.unhandledCount || 0,
        handled: vd.handledCount || 0,
        updated_at: vd.updatedAt || null,
        is_stale: !!(data.cache && data.cache.isStale),
        cache_source: data.cache?.source || '',
        source: 'api.phatnguoi.com',
        violations: []
    };
    
    if (vd.violations && Array.isArray(vd.violations)) {
        result.violations = vd.violations.map((v, i) => ({
            stt: i + 1,
            thoi_gian: v.violationTime || '',
            dia_diem: v.violationLocation || '',
            hanh_vi: v.violationBehavior || '',
            muc_phat: v.penaltyAmount || '',
            trang_thai: (v.status || '').toUpperCase(),
            don_vi: v.handlingUnit || '',
            noi_giai_quyet: v.resolutionAddress || v.handlingUnit || ''
        }));
    }
    
    return result;
}

// ==================== API ROUTES ====================

/**
 * Health check
 */
app.get('/health', async (req, res) => {
    let solverOk = false;
    try {
        const r = await fetch('http://localhost:8191/health');
        const d = await r.json();
        solverOk = d.status === 'ok';
    } catch (e) {}
    
    res.json({
        status: 'ok',
        solver: solverOk ? 'connected' : 'disconnected'
    });
});

/**
 * Tra cứu phạt nguội
 * 
 * Query params:
 *   plate:   biển số xe (bắt buộc)
 *   loaixe:  1=ô tô, 2=xe máy, 3=xe máy điện (mặc định: 1)
 */
app.get('/api/lookup', async (req, res) => {
    let { plate, loaixe, type } = req.query;
    
    if (!plate) {
        return res.status(400).json({ 
            success: false, 
            message: 'Thiếu biển số xe. Ví dụ: /api/lookup?plate=51L57382' 
        });
    }
    
    plate = plate.replace(/[-.\s]/g, '').toUpperCase();
    loaixe = loaixe || type || '1';
    const vehicleType = loaixe === '2' ? 'motorbike' : loaixe === '3' ? 'electricbike' : 'car';
    
    try {
        const result = await enqueue(() => doLookup(plate, vehicleType, loaixe));
        res.json(result);
    } catch (error) {
        console.error(`[LOOKUP] ❌ Lỗi: ${error.message}`);
        res.status(500).json({
            success: false, plate,
            message: error.message,
            hint: 'Kiểm tra EzSolver/CapSolver'
        });
    }
});

/**
 * Tra cứu phạt nguội - POST
 */
app.post('/api/lookup', async (req, res) => {
    let { plate, loaixe, type } = req.body;
    
    if (!plate) {
        return res.status(400).json({ 
            success: false, 
            message: 'Thiếu biển số xe. Gửi {"plate": "51L57382"}' 
        });
    }
    
    plate = plate.replace(/[-.\s]/g, '').toUpperCase();
    loaixe = loaixe || type || '1';
    const vehicleType = loaixe === '2' ? 'motorbike' : loaixe === '3' ? 'electricbike' : 'car';
    
    try {
        const result = await enqueue(() => doLookup(plate, vehicleType, loaixe));
        res.json(result);
    } catch (error) {
        console.error(`[LOOKUP] ❌ Lỗi: ${error.message}`);
        res.status(500).json({ success: false, plate, message: error.message });
    }
});

/**
 * Logic tra cứu chung (dùng cho cả GET và POST)
 * Hàm này chạy bên trong queue - đảm bảo chỉ 1 request tại 1 thời điểm
 */
async function doLookup(plate, vehicleType, loaixe) {
    console.log(`\n${'='.repeat(60)}`);
    console.log(`[LOOKUP] 🔍 Biển số: ${plate} | Loại xe: ${getLoaixeText(loaixe)} (${vehicleType})`);
    console.log(`${'='.repeat(60)}`);
    
    // Bước 1: Lấy Turnstile token MỚI (single-use)
    const token = await getTurnstileToken();
    
    // Bước 2: Gọi API
    let rawResult = await lookupDirectAPI(plate, vehicleType, token);
    
    // Nếu token bị reject -> lấy token mới và thử lại
    if (rawResult._error && rawResult.error?.code === 'TURNSTILE_FAILED') {
        console.log('[LOOKUP] ⚠️  Token bị reject, đang lấy token mới...');
        const newToken = await getTurnstileToken();
        rawResult = await lookupDirectAPI(plate, vehicleType, newToken);
    }
    
    const formattedResult = formatDirectAPIResult(plate, rawResult);
    console.log(`[LOOKUP] 📊 Kết quả: ${formattedResult.total_violations || 0} vi phạm (${formattedResult.unhandled || 0} chưa xử phạt)`);
    return formattedResult;
}

/**
 * Tra cứu đăng kiểm (qua API trực tiếp)
 */
app.get('/api/dangkiem', async (req, res) => {
    let { plate, tem, bien } = req.query;
    
    if (!plate) {
        return res.status(400).json({ 
            success: false, 
            message: 'Thiếu biển số xe. Ví dụ: /api/dangkiem?plate=30A12345&tem=KC2860472' 
        });
    }
    
    plate = plate.replace(/[-.\s]/g, '').toUpperCase();
    bien = bien || 'T';
    tem = (tem || '').replace(/[-.\s]/g, '').toUpperCase();
    
    if (!tem) {
        return res.status(400).json({ 
            success: false, 
            message: 'Thiếu tem đăng kiểm. Ví dụ: /api/dangkiem?plate=30A12345&tem=KC2860472' 
        });
    }
    
    console.log(`\n${'='.repeat(60)}`);
    console.log(`[ĐĂNG KIỂM] 🔍 Biển: ${plate} | Tem: ${tem} | Màu biển: ${bien}`);
    console.log(`${'='.repeat(60)}`);
    
    try {
        const token = await getTurnstileToken();
        const timestamp = Math.floor(Date.now() / 1000).toString();
        const payload = {
            licensePlate: plate,
            registrationCode: tem,
            plateColor: bien
        };
        const signature = createSignature('POST', '/v1/inspection', timestamp, payload);
        
        const response = await fetch('https://api.phatnguoi.com/v1/inspection', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Platform': 'web',
                'X-Timestamp': timestamp,
                'X-Signature': signature,
                'X-Turnstile-Token': token,
                'Origin': 'https://phatnguoi.com',
                'Referer': 'https://phatnguoi.com/',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            body: JSON.stringify(payload)
        });
        
        if (response.status >= 400) {
            const errData = await response.json();
            return res.status(response.status).json({ 
                success: false, plate, 
                message: errData.error?.message || `HTTP ${response.status}` 
            });
        }
        
        const result = await response.json();
        console.log(`[ĐĂNG KIỂM] ✅ Hoàn tất`);
        res.json({ success: true, plate, source: 'api.phatnguoi.com (Đăng Kiểm)', data: result });
        
    } catch (error) {
        console.error(`[ĐĂNG KIỂM] ❌ Lỗi: ${error.message}`);
        res.status(500).json({ success: false, plate, message: error.message });
    }
});

/**
 * Lấy token mới (debug/admin)
 */
app.get('/api/token', async (req, res) => {
    try {
        const token = await getTurnstileToken();
        res.json({ 
            success: true, 
            token: token.substring(0, 40) + '...',
            note: 'Token là single-use, chỉ dùng được cho 1 request API'
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// ==================== HELPERS ====================

function getLoaixeText(loaixe) {
    switch (String(loaixe)) {
        case '1': return 'Ô tô';
        case '2': return 'Xe máy';
        case '3': return 'Xe máy điện';
        default: return 'Ô tô';
    }
}

// ==================== KHỞI ĐỘNG ====================

app.listen(PORT, () => {
    const solverInfo = CONFIG.SOLVER_MODE === 'capsolver' 
        ? 'CapSolver (API)' 
        : CONFIG.EZSOLVER_URL;
    
    console.log(`
╔══════════════════════════════════════════════════════════╗
║         🚗 PhatNguoi API Server v3.1                    ║
║         Tra cứu phạt nguội qua CLI                      ║
╠══════════════════════════════════════════════════════════╣
║  Server:  http://localhost:${PORT}                        ║
║  Solver:  ${solverInfo.padEnd(42)}║
║  Mode:    ${CONFIG.SOLVER_MODE.padEnd(42)}║
╠══════════════════════════════════════════════════════════╣
║  GET /api/lookup?plate=51L57382&loaixe=1                 ║
║  GET /api/dangkiem?plate=30A12345&tem=KC2860472           ║
║  GET /health                                             ║
╚══════════════════════════════════════════════════════════╝
`);
    
    checkSolver();
});

async function checkSolver() {
    if (CONFIG.SOLVER_MODE === 'capsolver') {
        if (CONFIG.CAPSOLVER_KEY) {
            console.log('[STARTUP] ✅ CapSolver mode (API key configured)');
        } else {
            console.log('[STARTUP] ❌ CapSolver mode nhưng chưa set CAPSOLVER_KEY!');
        }
        return;
    }
    
    try {
        const r = await fetch('http://localhost:8191/health');
        const d = await r.json();
        if (d.status === 'ok') {
            console.log(`[STARTUP] ✅ EzSolver đã kết nối (${d.workers} worker, ${d.active} active)`);
        }
    } catch (e) {
        console.log('[STARTUP] ⚠️  EzSolver chưa chạy! Hãy chạy: python EzSolver/service.py');
    }
}
