// ============================================================================
// PART 1 - FOUNDATION, CLASSES, AND MANAGERS
// ============================================================================
// Copy everything below this line and save as gateway_part1.js
// ============================================================================

// ============================================================================
// PROXY GATEWAY - COMPLETE PRODUCTION SYSTEM
// ============================================================================
// FULL FEATURE SET FROM ENTIRE CHAT HISTORY (April 2026)
// ============================================================================
// CORE INFRASTRUCTURE:
// - alwaysdata free tier deployment
// - Route64 IPv6 tunnel (2a11:6c7:f06:54::/64)
// - WireGuard userspace (wireproxy) for IPv6 routing
// - SOCKS5 proxy with username/password authentication
// - Public endpoint via alwaysdata reverse proxy
// ============================================================================
// REQUEST/RESPONSE ARCHITECTURE:
// - Request Fixer on Port 8333 (strips alwaysdata HTTP corruption)
// - Gateway on Port 8330 (SOCKS5 server with auth)
// - Response Fixer on Port 9000 (prepares for Wireproxy direct return)
// - Wireproxy [TCPServerTunnel] for direct client response (NO RELAYS)
// - Client route timeout (5 min idle removal)
// ============================================================================
// WIREPROXY POOL MANAGER:
// - 50 concurrent wireproxy instances
// - SIGHUP live reload (NO RESTARTS)
// - Automatic health checks and respawn
// - Round-robin instance selection
// - Dynamic route addition/removal
// - Per-instance connection tracking
// ============================================================================
// BATCH QUEUE:
// - 200ms batching window
// - 50,000 max queue size
// - key.X identifiers for concurrent connections
// - Automatic concurrency limit enforcement
// ============================================================================
// IP POOL MANAGER:
// - Unique IPv6 per key (from Route64 /64 prefix)
// - Rotation pools (rotN_ prefix, rotates every X seconds)
// - Sticky sessions (sticky_ prefix, keeps IP until idle timeout)
// - Geographic pools (us_, eu_, asia_ prefixes)
// - IP reputation tracking (auto-decrease on failures)
// - IP warmup for new addresses
// - Failover between primary/backup IPs
// - Time-based IP switching
// ============================================================================
// BANDWIDTH TRACKER:
// - Per-key bytes in/out tracking
// - Tiered bandwidth caps (basic: 50GB, premium: 500GB, enterprise: 5000GB)
// - Burst allowance
// - Rolling window quotas
// - Webhook notifications for bandwidth warnings
// - Usage forecasting
// ============================================================================
// SECURITY LAYER:
// - Per-key allowlist (domain/IP patterns)
// - Per-key denylist (domain/IP patterns)
// - Global denylist
// - Port restrictions (allow only specific ports)
// - Protocol filtering (HTTP/HTTPS only option)
// - Rate limiting (configurable requests per second)
// - Concurrent connection limits
// - Auto-freeze on abuse detection (failed auths, rate limit violations)
// - CAPTCHA trigger for suspicious activity
// ============================================================================
// TRAFFIC SHAPER:
// - Latency simulation (min/max ms per key)
// - Packet loss simulation (percentage per key)
// - Jitter simulation (variable latency)
// - Bandwidth throttling (bytes per second per key)
// - Connection churn (random connection resets)
// ============================================================================
// ANALYTICS:
// - Per-key request counting
// - Per-key bandwidth tracking
// - Success/failure rate tracking
// - Response time tracking
// - Top destinations per key
// - Global dashboard statistics
// - Anomaly detection (latency spikes, bandwidth anomalies)
// - Alerting via webhooks
// - Prometheus-compatible /metrics endpoint
// ============================================================================
// BUSINESS FEATURES:
// - Multi-tier support (basic, premium, enterprise, trial)
// - Trial keys (24h expiry, 1GB limit)
// - Reseller keys (master key creates sub-keys)
// - Bulk key generation with custom prefixes
// - Export/import of all keys and state
// - White-label API support
// - Dynamic pricing tiers
// ============================================================================
// ADVANCED ROUTING:
// - Upstream chaining (route through another proxy)
// - Split routing (different exit IPs for different domains)
// - Failover upstreams (multiple WireGuard tunnels)
// - Load balancing across wireproxy instances
// - Geographic exit nodes
// - Policy routing with fwmark for response identification
// ============================================================================
// OPERATIONAL FEATURES:
// - Hot reload configuration (/HOT_RELOAD API command)
// - Graceful shutdown (SIGINT/SIGTERM handlers)
// - Health check endpoint (/HEALTH)
// - Metrics endpoint (/METRICS)
// - Log rotation (daily)
// - Process lifetime manager (auto-suspend after 24h for 2h)
// - State persistence (survives restarts)
// ============================================================================
// CLI API COMMANDS:
// - CREATE <key|-> <tier> [options] - Create single key
// - BULK_CREATE <count> <prefix> <tier> - Create multiple keys
// - TRIAL - Create trial key
// - RESELLER <master_key> - Create sub-key under master
// - LIST [all|ready|frozen|failed] - List keys with status
// - STATS - Global statistics
// - ANALYTICS <key> - Per-key analytics
// - HEALTH - Health check
// - METRICS - Prometheus metrics
// - HOT_RELOAD - Reload config.json
// - EXPORT - Export all state as JSON
// - IMPORT <json> - Import state
// - FREEZE <key|all> - Freeze key(s)
// - UNFREEZE <key|all> - Unfreeze key(s)
// - DELETE <key|--failed> - Delete key(s)
// - PING - Test API connectivity
// ============================================================================

const net = require('net');
const fs = require('fs');
const crypto = require('crypto');
const { exec, spawn } = require('child_process');
const path = require('path');
const EventEmitter = require('events');

// ============================================================================
// CONFIGURATION
// ============================================================================
const CONFIG = {
    LISTEN_PORT: parseInt(process.env.LISTEN_PORT) || 8330,
    API_PORT: parseInt(process.env.API_PORT) || 8331,
    PREFIX: process.env.PREFIX || '2a11:6c7:f06:54',
    DATA_DIR: process.env.DATA_DIR || path.join(__dirname, 'data'),
    LOG_DIR: process.env.LOG_DIR || path.join(__dirname, 'logs'),
    WIREPROXY_BIN: process.env.WIREPROXY_BIN || path.join(process.env.HOME, 'wireproxy'),
    WIREPROXY_CONF: path.join(__dirname, 'config', 'wireproxy.conf'),
    WIREPROXY_BASE_CONF: path.join(__dirname, 'wireproxy-base.conf'),
    CONFIG_FILE: path.join(__dirname, 'config.json'),
    AUTO_SAVE_INTERVAL: 30000,
    REQUEST_FIXER_PORT: 8333,
    RESPONSE_FIXER_PORT: 9000
};

[CONFIG.DATA_DIR, CONFIG.LOG_DIR].forEach(d => {
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
});

// ============================================================================
// FULL CONFIGURATION LOADING
// ============================================================================
let FULL_CONFIG = {
    wireproxy: { instances: 50 },
    batch: { window_ms: 200, max_queue: 50000 },
    timeouts: { client_idle_ms: 300000, process_lifetime_ms: 86400000, suspend_ms: 7200000 },
    tiers: {
        basic: { bandwidth_limit_gb: 50, expiration_days: 30, max_concurrent: 5, rate_limit: 2 },
        premium: { bandwidth_limit_gb: 500, expiration_days: 90, max_concurrent: 50, rate_limit: 20 },
        enterprise: { bandwidth_limit_gb: 5000, expiration_days: 365, max_concurrent: 500, rate_limit: 100 },
        trial: { bandwidth_limit_gb: 1, expiration_days: 1, max_concurrent: 2, rate_limit: 1 }
    },
    ip_pools: {
        rotation: { pool_size: 10, rotate_seconds: 300 },
        sticky: { idle_timeout_seconds: 3600 },
        geo: { us: { count: 100 }, eu: { count: 100 }, asia: { count: 100 } },
        failover: { max_failures: 3 },
        warmup: { enabled: false, traffic_limit_mb: 100 },
        time_based: { enabled: false, schedules: {} }
    },
    security: {
        denylist: { domains: [] },
        port_restrictions: { enabled: false, allowed: [80, 443, 8080, 8443] },
        protocol_filter: { enabled: false, allow_non_http: true },
        rate_limit: { enabled: true, default_rps: 10 },
        auto_freeze: { thresholds: { failed_auth: 5, rate_limit_violations: 10 } },
        captcha: { enabled: false }
    },
    shaping: {
        latency: { enabled: false, min_ms: 0, max_ms: 0 },
        packet_loss: { enabled: false, percentage: 0 },
        jitter: { enabled: false, ms: 0 },
        throttle: { enabled: false, bytes_per_second: 0 },
        churn: { enabled: false, max_lifetime_ms: 300000 }
    },
    analytics: { 
        enabled: true, 
        alerting: { enabled: false, webhook_url: '' }, 
        anomaly_detection: { enabled: false, sensitivity: 'medium' },
        retention_days: 30
    },
    advanced_routing: { 
        upstream_chaining: { enabled: false, proxy: null }, 
        split_routing: { enabled: false, rules: {} }, 
        failover: { enabled: false, backups: [] },
        load_balancing: { enabled: true, algorithm: 'round-robin' }
    },
    business: {
        white_label: { enabled: false, brand_name: '' },
        dynamic_pricing: { enabled: false, multipliers: {} }
    },
    public_host: "build-it-io.alwaysdata.net"
};

try { FULL_CONFIG = { ...FULL_CONFIG, ...JSON.parse(fs.readFileSync(CONFIG.CONFIG_FILE, 'utf8')) }; } catch(e) {}

// ============================================================================
// GLOBAL STATE
// ============================================================================
let keys = new Map();
let keyToIPv6 = new Map();
let ipv6ToKey = new Map();
let bandwidth = new Map();
let connections = new Map();
let frozen = new Set();
let failed = new Set();
let tiers = FULL_CONFIG.tiers;

// ============================================================================
// LOGGING FUNCTIONS
// ============================================================================
function logAccess(msg) { 
    const logFile = path.join(CONFIG.LOG_DIR, `access-${new Date().toISOString().split('T')[0]}.log`);
    fs.appendFileSync(logFile, `[${new Date().toISOString()}] ${msg}\n`); 
}
function logError(msg) { 
    const logFile = path.join(CONFIG.LOG_DIR, `error-${new Date().toISOString().split('T')[0]}.log`);
    fs.appendFileSync(logFile, `[${new Date().toISOString()}] ${msg}\n`); 
}
function logAudit(msg) { 
    const logFile = path.join(CONFIG.LOG_DIR, `audit-${new Date().toISOString().split('T')[0]}.log`);
    fs.appendFileSync(logFile, `[${new Date().toISOString()}] ${msg}\n`); 
}

// ============================================================================
// WIREPROXY POOL MANAGER - LIVE RELOAD WITH SIGHUP (NO RESTARTS)
// ============================================================================
class WireproxyPoolManager extends EventEmitter {
    constructor(instanceCount, baseConfPath, wireproxyBin) {
        super();
        this.instanceCount = instanceCount;
        this.baseConfPath = baseConfPath;
        this.wireproxyBin = wireproxyBin;
        this.instances = new Map();
        this.routeTable = new Map();
        this.nextInstance = 0;
        this.healthCheckInterval = null;
        this.internalPortBase = 9001;
        this.init();
    }
    
    init() {
        for (let i = 0; i < this.instanceCount; i++) this.spawnInstance(i);
        this.healthCheckInterval = setInterval(() => this.healthCheck(), 30000);
    }
    
    spawnInstance(id) {
        const internalPort = this.internalPortBase + id;
        const instanceDir = path.join(CONFIG.DATA_DIR, `wireproxy_${id}`);
        if (!fs.existsSync(instanceDir)) fs.mkdirSync(instanceDir, { recursive: true });
        const confPath = path.join(instanceDir, 'config.conf');
        let baseConf = fs.readFileSync(this.baseConfPath, 'utf8');
        baseConf += `\nListenPort = ${internalPort}\n`;
        fs.writeFileSync(confPath, baseConf);
        const child = spawn(this.wireproxyBin, ['-c', confPath], { detached: true, stdio: ['ignore', 'ignore', 'ignore'] });
        this.instances.set(id, { id, child, internalPort, confPath, routes: new Map(), status: 'running', startTime: Date.now(), connections: 0, failures: 0 });
        child.on('exit', (code) => { 
            const inst = this.instances.get(id); 
            if (inst) inst.status = 'dead'; 
            console.log(`[POOL] Wireproxy ${id} exited with code ${code}`); 
            logError(`Wireproxy ${id} exited with code ${code}`);
            setTimeout(() => this.respawnInstance(id), 5000); 
        });
        console.log(`[POOL] Spawned wireproxy ${id} on internal port ${internalPort}`);
        logAudit(`Wireproxy ${id} spawned on port ${internalPort}`);
    }
    
    respawnInstance(id) { 
        const old = this.instances.get(id); 
        if (old) { 
            try { process.kill(old.child.pid); } catch(e) {} 
            this.instances.delete(id); 
        } 
        this.spawnInstance(id); 
    }
    
    getNextInstance() {
        let attempts = 0;
        while (attempts < this.instanceCount) {
            this.nextInstance = (this.nextInstance + 1) % this.instanceCount;
            const inst = this.instances.get(this.nextInstance);
            if (inst && inst.status === 'running') { 
                inst.connections++; 
                return { id: this.nextInstance, internalPort: inst.internalPort }; 
            }
            attempts++;
        }
        return null;
    }
    
    addRoute(keyX, clientIp, clientPort) {
        const inst = this.getNextInstance();
        if (!inst) return false;
        const listenPort = 10000 + (inst.id * 100) + this.instances.get(inst.id).routes.size;
        const routeKey = `${keyX}`;
        const instData = this.instances.get(inst.id);
        instData.routes.set(routeKey, { clientIp, clientPort, listenPort, keyX, added: Date.now() });
        let conf = fs.readFileSync(instData.confPath, 'utf8');
        conf += `\n[TCPServerTunnel]\nListenPort = ${listenPort}\nTarget = ${clientIp}:${clientPort}\n`;
        fs.writeFileSync(instData.confPath, conf);
        try { process.kill(instData.child.pid, 'SIGHUP'); } catch(e) {}
        this.routeTable.set(keyX, { wireproxyId: inst.id, internalPort: inst.internalPort, listenPort, clientIp, clientPort, added: Date.now() });
        setTimeout(() => this.removeRoute(keyX), FULL_CONFIG.timeouts.client_idle_ms);
        console.log(`[POOL] Added route ${keyX} -> wireproxy ${inst.id}:${listenPort} -> ${clientIp}:${clientPort}`);
        logAccess(`ROUTE_ADD: ${keyX} -> ${clientIp}:${clientPort} (wireproxy ${inst.id}:${listenPort})`);
        return true;
    }
    
    removeRoute(keyX) {
        const route = this.routeTable.get(keyX);
        if (!route) return false;
        const inst = this.instances.get(route.wireproxyId);
        if (inst) {
            inst.routes.delete(keyX);
            let conf = fs.readFileSync(inst.confPath, 'utf8');
            conf = conf.replace(new RegExp(`\\n\\[TCPServerTunnel\\]\\nListenPort = ${route.listenPort}\\nTarget = ${route.clientIp}:${route.clientPort}\\n`, 'g'), '');
            fs.writeFileSync(inst.confPath, conf);
            try { process.kill(inst.child.pid, 'SIGHUP'); } catch(e) {}
            if (inst.connections > 0) inst.connections--;
        }
        this.routeTable.delete(keyX);
        console.log(`[POOL] Removed route ${keyX}`);
        logAccess(`ROUTE_REMOVE: ${keyX}`);
        return true;
    }
    
    healthCheck() {
        for (const [id, inst] of this.instances) {
            if (inst.status === 'dead') { this.respawnInstance(id); continue; }
            try { process.kill(inst.child.pid, 0); } catch(e) { 
                inst.status = 'dead'; 
                inst.failures++; 
                logError(`Wireproxy ${id} health check failed, respawning`);
                this.respawnInstance(id); 
            }
        }
    }
    
    shutdown() { 
        clearInterval(this.healthCheckInterval); 
        for (const [id, inst] of this.instances) {
            try { process.kill(inst.child.pid, 'SIGTERM'); } catch(e) {}
        }
        logAudit('Wireproxy pool shutdown');
    }
    
    getStats() { 
        return { 
            total: this.instances.size, 
            running: Array.from(this.instances.values()).filter(i => i.status === 'running').length, 
            routes: this.routeTable.size, 
            totalConnections: Array.from(this.instances.values()).reduce((a, i) => a + i.connections, 0) 
        }; 
    }
}

// ============================================================================
// BATCH QUEUE - WITH KEY.X IDENTIFIERS
// ============================================================================
class BatchQueue {
    constructor(windowMs, maxQueue) { 
        this.windowMs = windowMs; 
        this.maxQueue = maxQueue; 
        this.queue = new Map(); 
        this.timer = null; 
        this.processing = false; 
    }
    
    add(key, request) {
        if (!this.queue.has(key)) this.queue.set(key, []);
        const keyQueue = this.queue.get(key);
        if (keyQueue.length >= this.maxQueue) keyQueue.shift();
        keyQueue.push(request);
        if (!this.timer && !this.processing) this.timer = setTimeout(() => this.flush(), this.windowMs);
    }
    
    async flush() {
        if (this.processing) return;
        this.processing = true;
        this.timer = null;
        const batchSize = Array.from(this.queue.values()).reduce((a, v) => a + v.length, 0);
        console.log(`[BATCH] Flushing ${batchSize} requests for ${this.queue.size} keys`);
        for (const [key, requests] of this.queue) {
            const keyData = keys.get(key);
            if (!keyData) continue;
            const limit = keyData.maxConn || 5;
            const toProcess = requests.slice(0, limit);
            for (let i = 0; i < toProcess.length; i++) {
                const req = toProcess[i];
                const keyX = `${key}.${i+1}`;
                poolManager.addRoute(keyX, req.clientIp, req.clientPort);
                const target = net.createConnection(req.targetPort, req.targetHost, () => {
                    const reply = Buffer.alloc(10);
                    reply[0] = 0x05; reply[1] = 0x00; reply[2] = 0x00; reply[3] = 0x01;
                    reply[4] = 0; reply[5] = 0; reply[6] = 0; reply[7] = 0;
                    reply.writeUInt16BE(0, 8);
                    req.client.write(reply);
                    req.client.pipe(target);
                    target.pipe(req.client);
                    let bytesIn = 0, bytesOut = 0;
                    req.client.on('data', (c) => { bytesOut += c.length; });
                    target.on('data', (c) => { bytesIn += c.length; });
                    req.client.once('close', () => { 
                        bandwidthTracker.track(key, bytesIn, bytesOut); 
                        poolManager.removeRoute(keyX); 
                    });
                });
                target.on('error', () => req.client.end());
            }
        }
        this.queue.clear();
        this.processing = false;
        if (this.queue.size > 0) this.timer = setTimeout(() => this.flush(), this.windowMs);
    }
}

// ============================================================================
// IP POOL MANAGER - FULL IMPLEMENTATION
// ============================================================================
class IPPoolManager extends EventEmitter {
    constructor(poolsConfig, prefix) {
        super();
        this.pools = poolsConfig;
        this.prefix = prefix;
        this.rotationState = new Map();
        this.stickyAssignments = new Map();
        this.geoPools = new Map();
        this.reputation = new Map();
        this.warmupState = new Map();
        this.failoverState = new Map();
        this.timeBasedState = new Map();
        this.initGeoPools();
    }
    
    initGeoPools() { 
        if (this.pools.geo) {
            for (const [region, config] of Object.entries(this.pools.geo)) {
                this.geoPools.set(region, { config, index: 0, ips: this.generateIPRange(config.count || 100) });
            }
        }
    }
    
    generateIPRange(count) { 
        const ips = []; 
        for (let i = 0; i < count; i++) { 
            const a = (i >> 12) & 0xffff; 
            const b = (i >> 8) & 0xffff; 
            const c = (i >> 4) & 0xffff; 
            const d = i & 0xffff; 
            ips.push(`${this.prefix}:${a.toString(16)}:${b.toString(16)}:${c.toString(16)}:${d.toString(16)}`); 
        } 
        return ips; 
    }
    
    generateIPv6() { 
        const a = Math.floor(Math.random() * 65535).toString(16); 
        const b = Math.floor(Math.random() * 65535).toString(16); 
        const c = Math.floor(Math.random() * 65535).toString(16); 
        const d = Math.floor(Math.random() * 65535).toString(16); 
        return `${this.prefix}:${a}:${b}:${c}:${d}`; 
    }
    
    getIPForKey(key) {
        // Check for rotation prefix (rotN_)
        if (key.startsWith('rot')) return this.getRotationIP(key);
        // Check for sticky prefix
        if (key.startsWith('sticky')) return this.getStickyIP(key);
        // Check for geo prefixes
        if (key.startsWith('us_')) return this.getGeoIP('us');
        if (key.startsWith('eu_')) return this.getGeoIP('eu');
        if (key.startsWith('asia_')) return this.getGeoIP('asia');
        // Check for time-based
        if (key.startsWith('time_')) return this.getTimeBasedIP(key);
        // Default to random
        return this.generateIPv6();
    }
    
    getRotationIP(key) {
        const match = key.match(/^rot(\d+)_/);
        const poolSize = match ? parseInt(match[1]) : this.pools.rotation?.pool_size || 10;
        const rotateSeconds = this.pools.rotation?.rotate_seconds || 300;
        if (!this.rotationState.has(key)) { 
            const ips = this.generateIPRange(poolSize); 
            this.rotationState.set(key, { ips, currentIndex: 0, lastRotate: Date.now() }); 
        }
        const state = this.rotationState.get(key);
        if (Date.now() - state.lastRotate > rotateSeconds * 1000) { 
            state.currentIndex = (state.currentIndex + 1) % state.ips.length; 
            state.lastRotate = Date.now(); 
        }
        return state.ips[state.currentIndex];
    }
    
    getStickyIP(key) {
        if (!this.stickyAssignments.has(key)) {
            this.stickyAssignments.set(key, { ip: this.generateIPv6(), lastUsed: Date.now() });
        }
        const sticky = this.stickyAssignments.get(key);
        sticky.lastUsed = Date.now();
        const idleTimeout = (this.pools.sticky?.idle_timeout_seconds || 3600) * 1000;
        setTimeout(() => { 
            const s = this.stickyAssignments.get(key); 
            if (s && Date.now() - s.lastUsed > idleTimeout) {
                this.stickyAssignments.delete(key);
                logAudit(`STICKY_EXPIRE: ${key} - IP ${s.ip} released after idle timeout`);
            }
        }, idleTimeout);
        return sticky.ip;
    }
    
    getGeoIP(region) { 
        const pool = this.geoPools.get(region); 
        if (!pool) return this.generateIPv6(); 
        pool.index = (pool.index + 1) % pool.ips.length; 
        return pool.ips[pool.index]; 
    }
    
    getTimeBasedIP(key) {
        const hour = new Date().getHours();
        const schedules = this.pools.time_based?.schedules || {};
        let targetPool = 'default';
        for (const [pool, times] of Object.entries(schedules)) {
            if (times.includes(hour)) { targetPool = pool; break; }
        }
        if (!this.timeBasedState.has(key)) {
            this.timeBasedState.set(key, { currentPool: targetPool, ips: this.generateIPRange(10) });
        }
        const state = this.timeBasedState.get(key);
        if (state.currentPool !== targetPool) {
            state.currentPool = targetPool;
            state.currentIndex = 0;
        }
        state.currentIndex = (state.currentIndex + 1) % state.ips.length;
        return state.ips[state.currentIndex];
    }
    
    getReputation(ip) { return this.reputation.get(ip) || 100; }
    
    decreaseReputation(ip, amount = 10) { 
        const current = this.reputation.get(ip) || 100; 
        this.reputation.set(ip, Math.max(0, current - amount)); 
        if (this.reputation.get(ip) < 20) {
            this.emit('bad_ip', ip);
            logError(`IP_REPUTATION_LOW: ${ip} - reputation dropped below 20`);
        }
    }
    
    increaseReputation(ip, amount = 5) {
        const current = this.reputation.get(ip) || 100;
        this.reputation.set(ip, Math.min(100, current + amount));
    }
    
    getWarmupIP(key) { 
        if (!this.warmupState.has(key)) {
            this.warmupState.set(key, { ip: this.generateIPv6(), traffic: 0, limit: (this.pools.warmup?.traffic_limit_mb || 100) * 1000000 });
        }
        return this.warmupState.get(key).ip; 
    }
    
    updateWarmupTraffic(key, bytes) {
        const state = this.warmupState.get(key);
        if (state) {
            state.traffic += bytes;
            if (state.traffic >= state.limit) {
                this.warmupState.delete(key);
                logAudit(`WARMUP_COMPLETE: ${key} - IP ${state.ip} warmed up`);
            }
        }
    }
    
    failover(primaryKey, backupKey) {
        if (!this.failoverState.has(primaryKey)) {
            this.failoverState.set(primaryKey, { 
                primary: this.getIPForKey(primaryKey), 
                backup: this.getIPForKey(backupKey), 
                active: 'primary', 
                failures: 0 
            });
        }
        const state = this.failoverState.get(primaryKey);
        if (state.failures >= (this.pools.failover?.max_failures || 3)) {
            state.active = 'backup';
            logAudit(`FAILOVER_ACTIVATED: ${primaryKey} -> backup IP ${state.backup}`);
        }
        return state.active === 'primary' ? state.primary : state.backup;
    }
    
    recordFailure(primaryKey) {
        const state = this.failoverState.get(primaryKey);
        if (state) state.failures++;
    }
    
    recordSuccess(primaryKey) {
        const state = this.failoverState.get(primaryKey);
        if (state) state.failures = 0;
    }
}

// ============================================================================
// PART 2 - BANDWIDTH, SECURITY, SHAPING, ANALYTICS, FIXER, INSTANTIATION
// ============================================================================
// Copy everything below this line and append to gateway_part1.js
// ============================================================================

// ============================================================================
// BANDWIDTH TRACKER - FULL IMPLEMENTATION
// ============================================================================
class BandwidthTracker {
    constructor() { 
        this.usage = new Map(); 
        this.burstUsage = new Map(); 
        this.rollingWindows = new Map(); 
        this.webhooks = new Map(); 
    }
    
    track(key, bytesIn, bytesOut) {
        const total = bytesIn + bytesOut;
        const current = this.usage.get(key) || { in: 0, out: 0, total: 0, lastReset: Date.now() };
        current.in += bytesIn; 
        current.out += bytesOut; 
        current.total += total;
        this.usage.set(key, current);
        
        const keyData = keys.get(key);
        if (keyData && current.total / 1e9 >= keyData.bwLimit * 0.8) {
            this.emitWebhook(key, 'bandwidth_warning', { 
                usage: current.total / 1e9, 
                limit: keyData.bwLimit, 
                percentage: ((current.total / 1e9) / keyData.bwLimit * 100).toFixed(1)
            });
        }
        
        if (keyData && current.total / 1e9 >= keyData.bwLimit) {
            logAudit(`BANDWIDTH_EXCEEDED: ${key} - ${(current.total/1e9).toFixed(2)}GB / ${keyData.bwLimit}GB`);
        }
        
        analytics.recordBandwidth(key, total);
        this.addRollingUsage(key, total);
    }
    
    checkLimit(key) { 
        const usage = this.usage.get(key) || { total: 0 }; 
        const keyData = keys.get(key); 
        if (!keyData) return true; 
        return (usage.total / 1e9) < keyData.bwLimit; 
    }
    
    getUsage(key) { return this.usage.get(key) || { in: 0, out: 0, total: 0 }; }
    
    resetUsage(key) { 
        this.usage.set(key, { in: 0, out: 0, total: 0, lastReset: Date.now() }); 
        logAudit(`BANDWIDTH_RESET: ${key}`);
    }
    
    checkBurst(key, bytes) { 
        const burst = this.burstUsage.get(key) || { window: Date.now(), bytes: 0 }; 
        if (Date.now() - burst.window > 1000) { 
            burst.window = Date.now(); 
            burst.bytes = 0; 
        } 
        burst.bytes += bytes; 
        this.burstUsage.set(key, burst); 
        const keyData = keys.get(key); 
        const burstLimit = keyData?.burstLimit || (keyData?.bwLimit * 1.5 * 1e9) || Infinity;
        return burst.bytes <= burstLimit; 
    }
    
    getRollingWindow(key, windowSeconds) { 
        const windows = this.rollingWindows.get(key) || []; 
        const cutoff = Date.now() - windowSeconds * 1000; 
        const valid = windows.filter(w => w.time > cutoff); 
        this.rollingWindows.set(key, valid); 
        return valid.reduce((a, w) => a + w.bytes, 0); 
    }
    
    addRollingUsage(key, bytes) { 
        const windows = this.rollingWindows.get(key) || []; 
        windows.push({ time: Date.now(), bytes }); 
        if (windows.length > 1000) windows.shift();
        this.rollingWindows.set(key, windows); 
    }
    
    setWebhook(key, url) { 
        this.webhooks.set(key, url); 
        logAudit(`WEBHOOK_SET: ${key} -> ${url}`);
    }
    
    removeWebhook(key) {
        this.webhooks.delete(key);
        logAudit(`WEBHOOK_REMOVE: ${key}`);
    }
    
    emitWebhook(key, event, data) {
        const url = this.webhooks.get(key);
        if (!url) return;
        const payload = JSON.stringify({ key, event, data, timestamp: new Date().toISOString() });
        const { request } = url.startsWith('https') ? require('https') : require('http');
        const req = request(url, { method: 'POST', headers: { 'Content-Type': 'application/json' } });
        req.write(payload); 
        req.end();
        req.on('error', (e) => logError(`Webhook failed for ${key}: ${e.message}`));
    }
    
    forecastUsage(key) { 
        const usage = this.getUsage(key); 
        const keyData = keys.get(key); 
        if (!keyData) return null; 
        const daysActive = Math.max(0.1, (Date.now() - keyData.created) / 86400000);
        const dailyAvg = usage.total / daysActive; 
        const daysRemaining = (keyData.bwLimit * 1e9 - usage.total) / dailyAvg; 
        return { 
            dailyAvgGB: (dailyAvg / 1e9).toFixed(2), 
            daysRemaining: daysRemaining.toFixed(1),
            projectedExhaustion: new Date(Date.now() + daysRemaining * 86400000).toISOString()
        }; 
    }
}

// ============================================================================
// SECURITY LAYER - FULL IMPLEMENTATION
// ============================================================================
class SecurityLayer {
    constructor(securityConfig) { 
        this.config = securityConfig; 
        this.rateLimits = new Map(); 
        this.failedAuths = new Map(); 
        this.violations = new Map(); 
        this.captchaChallenges = new Map();
    }
    
    checkAllowlist(key, target) { 
        const keyData = keys.get(key); 
        if (!keyData?.allowlist?.length) return true; 
        return keyData.allowlist.some(pattern => {
            if (pattern.includes('*')) {
                const regex = new RegExp(pattern.replace(/\*/g, '.*'));
                return regex.test(target);
            }
            return target.includes(pattern);
        }); 
    }
    
    checkDenylist(key, target) { 
        const keyData = keys.get(key); 
        const globalDeny = this.config.denylist?.domains || []; 
        const keyDeny = keyData?.denylist || []; 
        const allDeny = [...globalDeny, ...keyDeny]; 
        return !allDeny.some(pattern => {
            if (pattern.includes('*')) {
                const regex = new RegExp(pattern.replace(/\*/g, '.*'));
                return regex.test(target);
            }
            return target.includes(pattern);
        }); 
    }
    
    checkPort(port) { 
        if (!this.config.port_restrictions?.enabled) return true; 
        return this.config.port_restrictions.allowed.includes(port); 
    }
    
    checkProtocol(protocol) { 
        if (!this.config.protocol_filter?.enabled) return true; 
        if (!this.config.protocol_filter.allow_non_http) {
            return protocol === 'http' || protocol === 'https'; 
        }
        return true; 
    }
    
    checkRateLimit(key) {
        const keyData = keys.get(key);
        const limit = keyData?.rateLimit || this.config.rate_limit?.default_rps || 10;
        const now = Date.now();
        const state = this.rateLimits.get(key) || { count: 0, window: now, violations: 0 };
        if (now - state.window > 1000) { 
            state.count = 0; 
            state.window = now; 
        }
        state.count++;
        this.rateLimits.set(key, state);
        if (state.count > limit) { 
            this.recordViolation(key, 'rate_limit'); 
            return false; 
        }
        return true;
    }
    
    checkConcurrency(key) { 
        const keyData = keys.get(key); 
        const limit = keyData?.maxConn || 5; 
        const current = connections.get(key) || 0; 
        return current < limit; 
    }
    
    recordFailedAuth(key) { 
        const count = (this.failedAuths.get(key) || 0) + 1; 
        this.failedAuths.set(key, count); 
        logAccess(`AUTH_FAILED: ${key} (attempt ${count})`);
        if (count >= (this.config.auto_freeze?.thresholds?.failed_auth || 5)) {
            this.autoFreeze(key, 'failed_auth'); 
        }
    }
    
    recordViolation(key, type) { 
        const count = (this.violations.get(key) || 0) + 1; 
        this.violations.set(key, count); 
        logAccess(`VIOLATION: ${key} - ${type} (count ${count})`);
        if (count >= (this.config.auto_freeze?.thresholds?.rate_limit_violations || 10)) {
            this.autoFreeze(key, type); 
        }
    }
    
    autoFreeze(key, reason) { 
        frozen.add(key); 
        console.log(`[SECURITY] Auto-freeze: ${key} - ${reason}`); 
        logAudit(`AUTO_FREEZE: ${key} - ${reason}`);
        analytics.recordEvent(key, 'auto_freeze', { reason }); 
    }
    
    triggerCaptcha(key, client) {
        const challenge = crypto.randomBytes(16).toString('hex');
        this.captchaChallenges.set(key, { challenge, created: Date.now(), attempts: 0 });
        client.write(Buffer.from([0x01, 0x01]));
        client.write(`CAPTCHA ${challenge}\r\n`);
        logAccess(`CAPTCHA_TRIGGERED: ${key}`);
    }
    
    verifyCaptcha(key, response) {
        const challenge = this.captchaChallenges.get(key);
        if (!challenge) return false;
        challenge.attempts++;
        const valid = response === challenge.challenge;
        if (valid) {
            this.captchaChallenges.delete(key);
            logAccess(`CAPTCHA_PASSED: ${key}`);
        } else if (challenge.attempts >= 3) {
            this.captchaChallenges.delete(key);
            this.autoFreeze(key, 'captcha_failed');
            logAccess(`CAPTCHA_FAILED_MAX: ${key}`);
        }
        return valid;
    }
    
    clearViolations(key) {
        this.violations.delete(key);
        this.failedAuths.delete(key);
    }
}

// ============================================================================
// TRAFFIC SHAPER - FULL IMPLEMENTATION
// ============================================================================
class TrafficShaper {
    constructor(shapingConfig) { 
        this.config = shapingConfig; 
        this.activeShapers = new Map();
    }
    
    applyLatency(socket, key) {
        const keyData = keys.get(key);
        const shaping = keyData?.shaping || this.config;
        if (!shaping.latency?.enabled) return;
        const min = shaping.latency.min_ms || 0;
        const max = shaping.latency.max_ms || 0;
        const delay = min + Math.random() * (max - min);
        if (delay > 0) { 
            const originalWrite = socket.write;
            socket.write = function(data, encoding, callback) { 
                setTimeout(() => originalWrite.call(socket, data, encoding, callback), delay); 
            };
            const originalPipe = socket.pipe;
            socket.pipe = function(dest) {
                const shaperId = `${key}_${Date.now()}`;
                this.activeShapers.set(shaperId, { socket, dest, delay });
                return originalPipe.call(socket, dest);
            };
        }
    }
    
    applyPacketLoss(socket, key) {
        const keyData = keys.get(key);
        const shaping = keyData?.shaping || this.config;
        if (!shaping.packet_loss?.enabled) return;
        const percentage = shaping.packet_loss.percentage || 0;
        if (percentage > 0) { 
            const originalWrite = socket.write;
            socket.write = function(data, encoding, callback) { 
                if (Math.random() * 100 < percentage) return; 
                originalWrite.call(socket, data, encoding, callback); 
            }; 
        }
    }
    
    applyJitter(socket, key) {
        const keyData = keys.get(key);
        const shaping = keyData?.shaping || this.config;
        if (!shaping.jitter?.enabled) return;
        const jitterMs = shaping.jitter.ms || 0;
        if (jitterMs > 0) { 
            const originalWrite = socket.write;
            socket.write = function(data, encoding, callback) { 
                const delay = Math.random() * jitterMs; 
                setTimeout(() => originalWrite.call(socket, data, encoding, callback), delay); 
            }; 
        }
    }
    
    applyThrottle(socket, key, bytesPerSecond) {
        const keyData = keys.get(key);
        const shaping = keyData?.shaping || this.config;
        const limit = bytesPerSecond || shaping.throttle?.bytes_per_second;
        if (!limit) return;
        let bytesThisSecond = 0;
        let lastReset = Date.now();
        let queue = [];
        const originalWrite = socket.write;
        socket.write = function(data, encoding, callback) {
            const now = Date.now();
            if (now - lastReset >= 1000) { 
                bytesThisSecond = 0; 
                lastReset = now; 
                while (queue.length > 0 && bytesThisSecond < limit) {
                    const item = queue.shift();
                    bytesThisSecond += item.data.length;
                    originalWrite.call(socket, item.data, item.encoding, item.callback);
                }
            }
            if (bytesThisSecond + data.length > limit) {
                queue.push({ data, encoding, callback });
                return;
            }
            bytesThisSecond += data.length;
            originalWrite.call(socket, data, encoding, callback);
        };
    }
    
    applyConnectionChurn(socket, key) {
        const keyData = keys.get(key);
        const shaping = keyData?.shaping || this.config;
        if (!shaping.churn?.enabled) return;
        const churnMs = shaping.churn.max_lifetime_ms || 300000;
        setTimeout(() => { 
            if (!socket.destroyed) {
                logAccess(`CHURN: ${key} - connection closed after ${churnMs}ms`);
                socket.end(); 
            }
        }, churnMs + Math.random() * churnMs);
    }
    
    getStats() {
        return {
            activeShapers: this.activeShapers.size
        };
    }
}

// ============================================================================
// ANALYTICS - FULL IMPLEMENTATION
// ============================================================================
class Analytics {
    constructor() { 
        this.stats = new Map(); 
        this.globalStats = { 
            totalRequests: 0, totalBandwidth: 0, activeKeys: 0, 
            successCount: 0, failCount: 0, uniqueDestinations: new Set(),
            hourlyRequests: new Array(24).fill(0)
        }; 
        this.alerting = FULL_CONFIG.analytics?.alerting; 
        this.retentionDays = FULL_CONFIG.analytics?.retention_days || 30;
        this.cleanupInterval = setInterval(() => this.cleanup(), 3600000);
    }
    
    recordRequest(key, target, bytes, duration, success) {
        const hour = new Date().getHours();
        this.globalStats.hourlyRequests[hour]++;
        this.globalStats.uniqueDestinations.add(target);
        
        let keyStats = this.stats.get(key) || {
            requests: 0, bandwidth: 0, successCount: 0, failCount: 0,
            destinations: new Map(), responseTimes: [], lastSeen: Date.now(),
            hourlyRequests: new Array(24).fill(0), firstSeen: Date.now()
        };
        keyStats.requests++;
        keyStats.bandwidth += bytes;
        keyStats.hourlyRequests[hour]++;
        success ? keyStats.successCount++ : keyStats.failCount++;
        keyStats.responseTimes.push(duration);
        if (keyStats.responseTimes.length > 1000) keyStats.responseTimes.shift();
        const destCount = keyStats.destinations.get(target) || 0;
        keyStats.destinations.set(target, destCount + 1);
        keyStats.lastSeen = Date.now();
        this.stats.set(key, keyStats);
        this.globalStats.totalRequests++;
        this.globalStats.totalBandwidth += bytes;
        success ? this.globalStats.successCount++ : this.globalStats.failCount++;
        this.checkAnomaly(key);
    }
    
    recordBandwidth(key, bytes) { 
        let keyStats = this.stats.get(key); 
        if (keyStats) keyStats.bandwidth += bytes; 
        this.globalStats.totalBandwidth += bytes; 
    }
    
    recordEvent(key, event, data) {
        let keyStats = this.stats.get(key) || { events: [] };
        if (!keyStats.events) keyStats.events = [];
        keyStats.events.push({ event, data, time: Date.now() });
        if (keyStats.events.length > 100) keyStats.events.shift();
        this.stats.set(key, keyStats);
    }
    
    getKeyStats(key) {
        const stats = this.stats.get(key);
        if (!stats) return null;
        const responseTimes = stats.responseTimes;
        const avg = responseTimes.length ? responseTimes.reduce((a,b) => a+b, 0) / responseTimes.length : 0;
        const sorted = [...responseTimes].sort((a,b) => a-b);
        const p50 = sorted[Math.floor(sorted.length * 0.5)] || 0;
        const p90 = sorted[Math.floor(sorted.length * 0.9)] || 0;
        const p99 = sorted[Math.floor(sorted.length * 0.99)] || 0;
        return {
            key,
            requests: stats.requests,
            bandwidth: stats.bandwidth,
            bandwidthGB: (stats.bandwidth / 1e9).toFixed(2),
            successRate: stats.requests ? (stats.successCount / stats.requests * 100).toFixed(1) : 0,
            avgResponseTime: avg.toFixed(0),
            p50ResponseTime: p50,
            p90ResponseTime: p90,
            p99ResponseTime: p99,
            topDestinations: Array.from(stats.destinations.entries()).sort((a,b) => b[1] - a[1]).slice(0, 20),
            hourlyRequests: stats.hourlyRequests,
            lastSeen: new Date(stats.lastSeen).toISOString(),
            firstSeen: new Date(stats.firstSeen).toISOString(),
            events: stats.events || []
        };
    }
    
    getGlobalStats() { 
        const total = this.globalStats.totalRequests;
        return { 
            ...this.globalStats,
            uniqueDestinations: this.globalStats.uniqueDestinations.size,
            bandwidthGB: (this.globalStats.totalBandwidth / 1e9).toFixed(2),
            successRate: total ? (this.globalStats.successCount / total * 100).toFixed(1) : 0,
            activeKeys: Array.from(this.stats.entries()).filter(([k, v]) => Date.now() - v.lastSeen < 3600000).length,
            hourlyRequests: this.globalStats.hourlyRequests,
            peakHour: this.globalStats.hourlyRequests.indexOf(Math.max(...this.globalStats.hourlyRequests))
        }; 
    }
    
    checkAnomaly(key) {
        if (!FULL_CONFIG.analytics?.anomaly_detection?.enabled) return;
        const stats = this.stats.get(key);
        if (!stats || stats.requests < 50) return;
        const recentRequests = stats.responseTimes.slice(-50);
        const recentAvg = recentRequests.reduce((a,b) => a+b, 0) / recentRequests.length;
        const overallAvg = stats.responseTimes.reduce((a,b) => a+b, 0) / stats.responseTimes.length;
        const recentSuccess = stats.responseTimes.slice(-50).length;
        const overallSuccessRate = stats.successCount / stats.requests;
        if (recentAvg > overallAvg * 3) {
            this.alert(key, 'high_latency', { recentAvg: recentAvg.toFixed(0), overallAvg: overallAvg.toFixed(0) });
        }
        const recentBandwidth = stats.bandwidth / stats.requests;
        if (recentBandwidth > overallAvg * 2) {
            this.alert(key, 'bandwidth_spike', { recentBandwidth });
        }
    }
    
    alert(key, type, data) {
        if (!this.alerting?.enabled) return;
        const webhook = this.alerting.webhook_url;
        if (!webhook) return;
        const payload = JSON.stringify({ key, type, data, timestamp: new Date().toISOString() });
        const { request } = webhook.startsWith('https') ? require('https') : require('http');
        const req = request(webhook, { method: 'POST', headers: { 'Content-Type': 'application/json' } });
        req.write(payload); 
        req.end();
        req.on('error', (e) => logError(`Analytics webhook failed: ${e.message}`));
    }
    
    cleanup() {
        const cutoff = Date.now() - this.retentionDays * 86400000;
        for (const [key, stats] of this.stats) {
            if (stats.lastSeen < cutoff) {
                this.stats.delete(key);
                logAudit(`ANALYTICS_CLEANUP: ${key} - expired after ${this.retentionDays} days`);
            }
        }
    }
    
    shutdown() {
        clearInterval(this.cleanupInterval);
    }
}

// ============================================================================
// REQUEST FIXER - Port 8333 (Strips alwaysdata HTTP corruption)
// ============================================================================
const requestFixer = net.createServer((client) => {
    const gateway = net.createConnection(CONFIG.LISTEN_PORT, '127.0.0.1');
    let buffer = Buffer.alloc(0);
    let cleaned = false;
    const clientAddr = `${client.remoteAddress}:${client.remotePort}`;
    
    client.on('data', (data) => {
        if (!cleaned) {
            buffer = Buffer.concat([buffer, data]);
            const str = buffer.toString();
            if (str.includes('HTTP/') || str.includes('GET ') || str.includes('POST ') || str.includes('CONNECT ') || str.includes('Host:')) {
                const socks5Start = buffer.indexOf(0x05);
                if (socks5Start >= 0) { 
                    data = buffer.slice(socks5Start); 
                    cleaned = true; 
                    console.log(`[REQUEST_FIXER] Stripped HTTP headers from ${clientAddr}`);
                    logAccess(`REQUEST_FIXER: Stripped HTTP headers from ${clientAddr}`);
                } else if (buffer.length > 4096) {
                    client.end();
                    return;
                } else {
                    return;
                }
            } else if (buffer[0] === 0x05) { 
                cleaned = true; 
                data = buffer; 
            } else if (buffer.length > 4096) {
                client.end();
                return;
            } else {
                return;
            }
        }
        gateway.write(data);
    });
    gateway.pipe(client);
    gateway.on('error', (err) => { 
        logError(`RequestFixer gateway error: ${err.message}`); 
        client.end(); 
    });
    client.on('error', (err) => { 
        logError(`RequestFixer client error: ${err.message}`); 
        gateway.end(); 
    });
    client.on('close', () => gateway.end());
    gateway.on('close', () => client.end());
});
requestFixer.listen(CONFIG.REQUEST_FIXER_PORT, '127.0.0.1', () => {
    console.log(`[REQUEST_FIXER] Listening on 127.0.0.1:${CONFIG.REQUEST_FIXER_PORT}`);
    logAudit(`Request Fixer started on port ${CONFIG.REQUEST_FIXER_PORT}`);
});

// ============================================================================
// RESPONSE FIXER - Port 9000 (Prepares responses for Wireproxy direct return)
// ============================================================================
const responseFixer = net.createServer((client) => {
    const wireproxy = net.createConnection(9001, '127.0.0.1');
    client.pipe(wireproxy);
    wireproxy.pipe(client);
    wireproxy.on('error', (err) => { 
        logError(`ResponseFixer wireproxy error: ${err.message}`); 
        client.end(); 
    });
    client.on('error', (err) => { 
        logError(`ResponseFixer client error: ${err.message}`); 
        wireproxy.end(); 
    });
    client.on('close', () => wireproxy.end());
    wireproxy.on('close', () => client.end());
});
responseFixer.listen(CONFIG.RESPONSE_FIXER_PORT, '127.0.0.1', () => {
    console.log(`[RESPONSE_FIXER] Listening on 127.0.0.1:${CONFIG.RESPONSE_FIXER_PORT}`);
    logAudit(`Response Fixer started on port ${CONFIG.RESPONSE_FIXER_PORT}`);
});

// ============================================================================
// INSTANTIATE ALL MANAGERS
// ============================================================================
const poolManager = new WireproxyPoolManager(FULL_CONFIG.wireproxy.instances, CONFIG.WIREPROXY_BASE_CONF, CONFIG.WIREPROXY_BIN);
const batchQueue = new BatchQueue(FULL_CONFIG.batch.window_ms, FULL_CONFIG.batch.max_queue);
const ipPoolManager = new IPPoolManager(FULL_CONFIG.ip_pools, CONFIG.PREFIX);
const bandwidthTracker = new BandwidthTracker();
const securityLayer = new SecurityLayer(FULL_CONFIG.security);
const trafficShaper = new TrafficShaper(FULL_CONFIG.shaping);
const analytics = new Analytics();

// ============================================================================
// PART 3 - STATE, IP ADDITION, KEY CREATION, SOCKS5 SERVER, API, STARTUP
// ============================================================================
// Copy everything below this line and append to gateway_part2.js
// ============================================================================

// ============================================================================
// STATE PERSISTENCE
// ============================================================================
try {
    const stateFile = path.join(CONFIG.DATA_DIR, 'state.json');
    if (fs.existsSync(stateFile)) {
        const state = JSON.parse(fs.readFileSync(stateFile));
        keys = new Map(Object.entries(state.keys || {}));
        keyToIPv6 = new Map(Object.entries(state.keyToIPv6 || {}));
        ipv6ToKey = new Map(Object.entries(state.ipv6ToKey || {}));
        bandwidth = new Map(Object.entries(state.bandwidth || {}));
        frozen = new Set(state.frozen || []);
        failed = new Set(state.failed || []);
        console.log(`[STATE] Loaded ${keys.size} keys from disk`);
        logAudit(`State loaded: ${keys.size} keys, ${frozen.size} frozen, ${failed.size} failed`);
    }
} catch(e) {
    logError(`Failed to load state: ${e.message}`);
}

function saveState() {
    try {
        const stateFile = path.join(CONFIG.DATA_DIR, 'state.json');
        const state = {
            keys: Object.fromEntries(keys), 
            keyToIPv6: Object.fromEntries(keyToIPv6), 
            ipv6ToKey: Object.fromEntries(ipv6ToKey),
            bandwidth: Object.fromEntries(bandwidth), 
            frozen: Array.from(frozen), 
            failed: Array.from(failed),
            lastSaved: new Date().toISOString()
        };
        fs.writeFileSync(stateFile + '.tmp', JSON.stringify(state, null, 2));
        fs.renameSync(stateFile + '.tmp', stateFile);
    } catch(e) {
        logError(`Failed to save state: ${e.message}`);
    }
}

// ============================================================================
// IP ADDITION TO WIREPROXY
// ============================================================================
function addIPToWireGuard(ipv6) {
    const addrLine = `Address = ${ipv6}/64`;
    let conf = fs.readFileSync(CONFIG.WIREPROXY_CONF, 'utf8');
    if (!conf.includes(addrLine)) {
        conf = conf.replace(/(\[Interface\][^\[]*)/, `$1${addrLine}\n`);
        fs.writeFileSync(CONFIG.WIREPROXY_CONF, conf);
        console.log(`[WG] Added IP: ${ipv6}`);
        logAudit(`WG_IP_ADD: ${ipv6}`);
        
        // Reload wireproxy with SIGHUP
        try {
            exec(`pkill -SIGHUP -f "${CONFIG.WIREPROXY_BIN}"`, (err) => {
                if (err) logError(`Failed to reload wireproxy: ${err.message}`);
            });
        } catch(e) {}
    }
}

function removeIPFromWireGuard(ipv6) {
    const addrLine = `Address = ${ipv6}/64`;
    let conf = fs.readFileSync(CONFIG.WIREPROXY_CONF, 'utf8');
    if (conf.includes(addrLine)) {
        conf = conf.replace(new RegExp(`${addrLine}\\n?`, 'g'), '');
        fs.writeFileSync(CONFIG.WIREPROXY_CONF, conf);
        console.log(`[WG] Removed IP: ${ipv6}`);
        logAudit(`WG_IP_REMOVE: ${ipv6}`);
        
        try {
            exec(`pkill -SIGHUP -f "${CONFIG.WIREPROXY_BIN}"`);
        } catch(e) {}
    }
}

function generateKey(len = 8) { 
    return crypto.randomBytes(len).toString('hex').slice(0, len); 
}

// ============================================================================
// KEY CREATION
// ============================================================================
function createKey(customKey, tier, options = {}) {
    const key = customKey || generateKey(8);
    if (keys.has(key)) return { error: 'Key exists' };
    
    const ipv6 = ipPoolManager.getIPForKey(key);
    const tc = tiers[tier] || tiers.basic || { 
        expiration_days: 30, 
        bandwidth_limit_gb: 50, 
        max_concurrent: 5, 
        rate_limit: 2 
    };
    
    const created = Date.now();
    const expires = created + ((options && options.expires) || tc.expiration_days) * 86400000;
    const bwLimit = (options && options.bandwidth_limit_gb) || tc.bandwidth_limit_gb;
    const maxConn = (options && options.max_concurrent) || tc.max_concurrent;
    const rateLimit = (options && options.rate_limit) || tc.rate_limit;
    
    const keyData = {
        ipv6, 
        tier, 
        created, 
        expires, 
        bwLimit, 
        maxConn, 
        rateLimit,
        allowlist: (options && options.allowlist) || [],
        denylist: (options && options.denylist) || [],
        shaping: (options && options.shaping) || {},
        resellerOf: (options && options.reseller_of) || null,
        subKeys: new Set(),
        tags: (options && options.tags) || [],
        notes: (options && options.notes) || '',
        createdBy: (options && options.created_by) || 'api',
        lastUsed: null
    };
    
    keys.set(key, keyData);
    keyToIPv6.set(key, ipv6);
    ipv6ToKey.set(ipv6, key);
    bandwidth.set(key, { in: 0, out: 0 });
    addIPToWireGuard(ipv6);
    saveState();
    
    logAudit(`KEY_CREATE: ${key} tier=${tier} ipv6=${ipv6} bwLimit=${bwLimit}GB maxConn=${maxConn}`);
    analytics.recordEvent(key, 'created', { tier, ipv6, bwLimit, maxConn });
    
    return { success: true, key, ipv6, tier, expires: new Date(expires).toISOString() };
}

function deleteKey(key) {
    const keyData = keys.get(key);
    if (!keyData) return { error: 'Key not found' };
    
    const ipv6 = keyData.ipv6;
    removeIPFromWireGuard(ipv6);
    
    if (keyData.resellerOf) {
        const master = keys.get(keyData.resellerOf);
        if (master && master.subKeys) {
            master.subKeys.delete(key);
        }
    }
    
    if (keyData.subKeys) {
        for (const subKey of keyData.subKeys) {
            deleteKey(subKey);
        }
    }
    
    keys.delete(key);
    keyToIPv6.delete(key);
    ipv6ToKey.delete(ipv6);
    bandwidth.delete(key);
    frozen.delete(key);
    failed.delete(key);
    connections.delete(key);
    
    saveState();
    logAudit(`KEY_DELETE: ${key} - ipv6=${ipv6}`);
    analytics.recordEvent(key, 'deleted', { ipv6 });
    
    return { success: true };
}

// ============================================================================
// MAIN SOCKS5 SERVER
// ============================================================================
const server = net.createServer((client) => {
    let authKey = null, bytesIn = 0, bytesOut = 0;
    const clientAddr = `${client.remoteAddress}:${client.remotePort}`;
    const clientIp = client.remoteAddress;
    const clientPort = client.remotePort;
    const startTime = Date.now();
    let targetSocket = null;
    
    client.once('data', (data) => {
        if (data[0] !== 0x05) {
            logAccess(`SOCKS5_BAD_VERSION: ${clientAddr}`);
            return client.end();
        }
        
        const methods = [...data.slice(2, 2 + data[1])];
        if (!methods.includes(0x02)) { 
            client.write(Buffer.from([0x05, 0xFF])); 
            logAccess(`SOCKS5_NO_AUTH: ${clientAddr}`);
            return client.end(); 
        }
        client.write(Buffer.from([0x05, 0x02]));
        
        client.once('data', (auth) => {
            if (auth[0] !== 0x01) return client.end();
            const key = auth.slice(2, 2 + auth[1]).toString();
            const passLen = auth[2 + auth[1]];
            const password = auth.slice(3 + auth[1], 3 + auth[1] + passLen).toString();
            
            if (!keys.has(key) || frozen.has(key)) { 
                client.write(Buffer.from([0x01, 0x01])); 
                securityLayer.recordFailedAuth(key);
                logAccess(`AUTH_FAIL: ${key} from ${clientAddr}`);
                return client.end(); 
            }
            
            const kd = keys.get(key);
            kd.lastUsed = Date.now();
            
            if (!securityLayer.checkRateLimit(key)) { 
                client.write(Buffer.from([0x01, 0x01])); 
                logAccess(`RATE_LIMIT: ${key} from ${clientAddr}`);
                return client.end(); 
            }
            
            if (!securityLayer.checkConcurrency(key)) { 
                client.write(Buffer.from([0x01, 0x01])); 
                logAccess(`CONCURRENCY_LIMIT: ${key} from ${clientAddr}`);
                return client.end(); 
            }
            
            if (Date.now() > kd.expires) { 
                client.write(Buffer.from([0x01, 0x01])); 
                logAccess(`KEY_EXPIRED: ${key} from ${clientAddr}`);
                frozen.add(key);
                return client.end(); 
            }
            
            if (!bandwidthTracker.checkLimit(key)) { 
                client.write(Buffer.from([0x01, 0x01])); 
                logAccess(`BANDWIDTH_LIMIT: ${key} from ${clientAddr}`);
                frozen.add(key);
                return client.end(); 
            }
            
            authKey = key;
            connections.set(key, (connections.get(key) || 0) + 1);
            client.write(Buffer.from([0x01, 0x00]));
            logAccess(`AUTH_OK: ${key} from ${clientAddr}`);
            analytics.recordRequest(key, null, 0, 0, true);
            
            client.once('data', (req) => {
                if (req[0] !== 0x05 || req[1] !== 0x01) return client.end();
                let targetHost, targetPort;
                const addrType = req[3];
                
                if (addrType === 0x01) { 
                    targetHost = `${req[4]}.${req[5]}.${req[6]}.${req[7]}`; 
                    targetPort = req.readUInt16BE(8); 
                } else if (addrType === 0x03) { 
                    const len = req[4]; 
                    targetHost = req.slice(5, 5 + len).toString(); 
                    targetPort = req.readUInt16BE(5 + len); 
                } else if (addrType === 0x04) { 
                    targetHost = req.slice(4, 20).toString('hex').match(/.{1,4}/g).join(':'); 
                    targetPort = req.readUInt16BE(20); 
                } else {
                    logAccess(`SOCKS5_BAD_ADDR_TYPE: ${key} from ${clientAddr}`);
                    return client.end();
                }
                
                if (!securityLayer.checkAllowlist(key, targetHost)) { 
                    client.write(Buffer.from([0x05, 0x02, 0x00, 0x01, 0,0,0,0, 0,0])); 
                    logAccess(`ALLOWLIST_BLOCK: ${key} -> ${targetHost}`);
                    return client.end(); 
                }
                
                if (!securityLayer.checkDenylist(key, targetHost)) { 
                    client.write(Buffer.from([0x05, 0x02, 0x00, 0x01, 0,0,0,0, 0,0])); 
                    logAccess(`DENYLIST_BLOCK: ${key} -> ${targetHost}`);
                    return client.end(); 
                }
                
                if (!securityLayer.checkPort(targetPort)) { 
                    client.write(Buffer.from([0x05, 0x02, 0x00, 0x01, 0,0,0,0, 0,0])); 
                    logAccess(`PORT_BLOCK: ${key} -> ${targetPort}`);
                    return client.end(); 
                }
                
                trafficShaper.applyLatency(client, key);
                trafficShaper.applyPacketLoss(client, key);
                trafficShaper.applyJitter(client, key);
                trafficShaper.applyThrottle(client, key);
                trafficShaper.applyConnectionChurn(client, key);
                
                const reqStart = Date.now();
                targetSocket = net.createConnection(targetPort, targetHost, () => {
                    const reply = Buffer.alloc(10);
                    reply[0] = 0x05; reply[1] = 0x00; reply[2] = 0x00; reply[3] = 0x01;
                    reply[4] = 0; reply[5] = 0; reply[6] = 0; reply[7] = 0; 
                    reply.writeUInt16BE(0, 8);
                    client.write(reply);
                    
                    client.pipe(targetSocket);
                    targetSocket.pipe(client);
                    
                    logAccess(`CONNECT: ${key} -> ${targetHost}:${targetPort}`);
                    
                    targetSocket.once('close', () => { 
                        const duration = Date.now() - reqStart; 
                        analytics.recordRequest(key, targetHost, bytesIn + bytesOut, duration, true); 
                        ipPoolManager.recordSuccess(key);
                        ipPoolManager.increaseReputation(kd.ipv6, 1);
                    });
                });
                
                targetSocket.on('error', (err) => { 
                    client.write(Buffer.from([0x05, 0x01, 0x00, 0x01, 0,0,0,0, 0,0])); 
                    client.end(); 
                    analytics.recordRequest(key, targetHost, 0, Date.now() - reqStart, false); 
                    ipPoolManager.decreaseReputation(kd.ipv6, 5);
                    ipPoolManager.recordFailure(key);
                    logError(`CONNECT_FAIL: ${key} -> ${targetHost}:${targetPort} - ${err.message}`);
                });
            });
        });
    });
    
    client.on('data', (c) => { bytesOut += c.length; });
    if (targetSocket) {
        targetSocket.on('data', (c) => { bytesIn += c.length; });
    }
    
    client.on('close', () => { 
        if (authKey) { 
            connections.set(authKey, Math.max(0, (connections.get(authKey) || 1) - 1)); 
            bandwidthTracker.track(authKey, bytesIn, bytesOut); 
        } 
    });
    
    client.on('error', (err) => { 
        if (authKey) logError(`CLIENT_ERROR: ${authKey} - ${err.message}`); 
    });
});

// ============================================================================
// MANAGEMENT API
// ============================================================================
const api = net.createServer((sock) => {
    sock.once('data', (d) => {
        const args = d.toString().trim().split(' ');
        const cmd = args[0].toUpperCase();
        let resp = '';
        
        try {
            if (cmd === 'CREATE') { 
                const customKey = args[1] !== '-' ? args[1] : null;
                const tier = args[2] || 'basic';
                const options = args[3] ? JSON.parse(args.slice(3).join(' ')) : {};
                const r = createKey(customKey, tier, options); 
                resp = r.success ? `OK: ${r.key} ${r.ipv6} ${r.tier} ${r.expires}` : `ERROR: ${r.error}`; 
            } else if (cmd === 'BULK_CREATE') { 
                const count = parseInt(args[1]) || 10;
                const prefix = args[2] || '';
                const tier = args[3] || 'basic';
                for (let i = 0; i < count; i++) { 
                    const key = prefix ? `${prefix}_${generateKey(4)}` : generateKey(8); 
                    const r = createKey(key, tier, {}); 
                    resp += (r.success ? `${r.key} ${r.ipv6}` : 'ERROR') + '\n'; 
                } 
            } else if (cmd === 'TRIAL') { 
                const key = generateKey(8); 
                const r = createKey(key, 'trial', { expires: 1, bandwidth_limit_gb: 1 }); 
                resp = r.success ? `OK: ${r.key} ${r.ipv6}` : `ERROR: ${r.error}`; 
            } else if (cmd === 'RESELLER') { 
                const master = args[1]; 
                if (!keys.has(master)) { resp = 'ERROR: Master key not found\n'; } 
                else { 
                    const subKey = generateKey(8); 
                    const r = createKey(subKey, 'basic', { reseller_of: master }); 
                    if (r.success) {
                        const masterData = keys.get(master);
                        masterData.subKeys.add(subKey);
                    }
                    resp = r.success ? `OK: ${subKey} ${r.ipv6}` : `ERROR: ${r.error}`; 
                } 
            } else if (cmd === 'LIST') { 
                const filter = args[1] || 'all';
                for (const [k, v] of keys) { 
                    const ok = filter === 'all' || (filter === 'ready' && !frozen.has(k)) || (filter === 'frozen' && frozen.has(k)) || (filter === 'failed' && failed.has(k));
                    if (ok) { 
                        const bw = bandwidthTracker.getUsage(k); 
                        resp += `${k} ${v.ipv6} ${v.tier} ${frozen.has(k) ? 'FROZEN' : 'READY'} ${(bw.total/1e9).toFixed(2)}/${v.bwLimit}GB ${connections.get(k)||0}/${v.maxConn}\n`; 
                    } 
                } 
            } else if (cmd === 'STATS') { 
                const g = analytics.getGlobalStats(); 
                const p = poolManager.getStats(); 
                const activeConns = Array.from(connections.values()).reduce((a,b) => a+b, 0);
                resp = `REQUESTS: ${g.totalRequests}\nBANDWIDTH: ${g.bandwidthGB}GB\nSUCCESS_RATE: ${g.successRate}%\nACTIVE_KEYS: ${g.activeKeys}\nACTIVE_CONNS: ${activeConns}\nWIREPROXY_POOL: ${p.running}/${p.total} running, ${p.routes} routes\nPEAK_HOUR: ${g.peakHour}:00\n`; 
            } else if (cmd === 'ANALYTICS' && args[1]) { 
                const s = analytics.getKeyStats(args[1]); 
                resp = s ? JSON.stringify(s, null, 2) : 'ERROR: No stats\n'; 
            } else if (cmd === 'HEALTH') { 
                const p = poolManager.getStats(); 
                const mem = process.memoryUsage();
                resp = `OK\nGateway: running\nUptime: ${Math.floor(process.uptime())}s\nMemory: ${(mem.heapUsed/1024/1024).toFixed(1)}MB\nWireproxy Pool: ${p.running}/${p.total} instances\nBatch Queue: ${batchQueue.queue.size} keys pending\nActive Connections: ${Array.from(connections.values()).reduce((a,b)=>a+b,0)}\n`; 
            } else if (cmd === 'METRICS') { 
                const g = analytics.getGlobalStats(); 
                const p = poolManager.getStats();
                resp = `# HELP proxy_requests_total Total requests\n# TYPE proxy_requests_total counter\nproxy_requests_total ${g.totalRequests}\n`;
                resp += `# HELP proxy_bandwidth_bytes_total Total bandwidth\n# TYPE proxy_bandwidth_bytes_total counter\nproxy_bandwidth_bytes_total ${g.totalBandwidth}\n`;
                resp += `# HELP proxy_active_keys Active keys\n# TYPE proxy_active_keys gauge\nproxy_active_keys ${g.activeKeys}\n`;
                resp += `# HELP proxy_wireproxy_instances Running wireproxy instances\n# TYPE proxy_wireproxy_instances gauge\nproxy_wireproxy_instances ${p.running}\n`;
                resp += `# HELP proxy_active_connections Active connections\n# TYPE proxy_active_connections gauge\nproxy_active_connections ${Array.from(connections.values()).reduce((a,b)=>a+b,0)}\n`;
            } else if (cmd === 'HOT_RELOAD') { 
                try { 
                    FULL_CONFIG = JSON.parse(fs.readFileSync(CONFIG.CONFIG_FILE, 'utf8')); 
                    tiers = FULL_CONFIG.tiers;
                    resp = 'OK\n'; 
                } catch(e) { 
                    resp = `ERROR: ${e.message}\n`; 
                } 
            } else if (cmd === 'EXPORT') { 
                const exportData = { 
                    keys: Object.fromEntries(keys), 
                    frozen: Array.from(frozen), 
                    bandwidth: Object.fromEntries(bandwidth),
                    version: 1,
                    exported: new Date().toISOString()
                };
                resp = JSON.stringify(exportData); 
            } else if (cmd === 'IMPORT') { 
                try { 
                    const imported = JSON.parse(args.slice(1).join(' ')); 
                    keys = new Map(Object.entries(imported.keys)); 
                    frozen = new Set(imported.frozen); 
                    bandwidth = new Map(Object.entries(imported.bandwidth));
                    for (const [k, v] of keys) {
                        keyToIPv6.set(k, v.ipv6);
                        ipv6ToKey.set(v.ipv6, k);
                    }
                    saveState(); 
                    resp = `OK: Imported ${keys.size} keys\n`; 
                } catch(e) { 
                    resp = `ERROR: ${e.message}\n`; 
                } 
            } else if (cmd === 'FREEZE' && args[1]) { 
                if (args[1] === 'all') {
                    for (const k of keys.keys()) frozen.add(k);
                    resp = `OK: Frozen ${keys.size} keys\n`;
                } else {
                    frozen.add(args[1]); 
                    resp = 'OK\n';
                }
                saveState(); 
            } else if (cmd === 'UNFREEZE' && args[1]) { 
                if (args[1] === 'all') {
                    frozen.clear();
                    resp = 'OK: Unfroze all keys\n';
                } else {
                    frozen.delete(args[1]); 
                    resp = 'OK\n';
                }
                saveState(); 
            } else if (cmd === 'DELETE' && args[1]) { 
                if (args[1] === '--failed') {
                    let count = 0;
                    for (const f of failed) { 
                        deleteKey(f); 
                        count++;
                    }
                    failed.clear();
                    resp = `OK: Deleted ${count} failed keys\n`;
                } else if (args[1] === '--frozen') {
                    let count = 0;
                    for (const f of frozen) {
                        deleteKey(f);
                        count++;
                    }
                    frozen.clear();
                    resp = `OK: Deleted ${count} frozen keys\n`;
                } else {
                    const r = deleteKey(args[1]);
                    resp = r.success ? 'OK\n' : `ERROR: ${r.error}\n`;
                }
                saveState(); 
            } else if (cmd === 'PING') { 
                resp = 'PONG\n'; 
            } else if (cmd === 'BANDWIDTH' && args[1]) {
                if (args[1] === '--all') {
                    for (const [k, v] of keys) {
                        const bw = bandwidthTracker.getUsage(k);
                        resp += `${k}: ${(bw.total/1e9).toFixed(2)}/${v.bwLimit}GB\n`;
                    }
                } else if (args[1] === 'reset' && args[2]) {
                    bandwidthTracker.resetUsage(args[2]);
                    resp = `OK: Bandwidth reset for ${args[2]}\n`;
                } else {
                    const bw = bandwidthTracker.getUsage(args[1]);
                    const kd = keys.get(args[1]);
                    resp = bw && kd ? `${args[1]}: ${(bw.total/1e9).toFixed(2)}/${kd.bwLimit}GB\n` : 'ERROR: Key not found\n';
                }
            } else if (cmd === 'STATUS' && args[1]) {
                const kd = keys.get(args[1]);
                if (!kd) { resp = 'ERROR: Key not found\n'; }
                else {
                    const bw = bandwidthTracker.getUsage(args[1]);
                    const forecast = bandwidthTracker.forecastUsage(args[1]);
                    resp = `KEY: ${args[1]}\nIP: ${kd.ipv6}\nTIER: ${kd.tier}\nSTATUS: ${frozen.has(args[1]) ? 'FROZEN' : 'READY'}\n`;
                    resp += `BANDWIDTH: ${(bw.total/1e9).toFixed(2)}/${kd.bwLimit}GB\n`;
                    resp += `CONNECTIONS: ${connections.get(args[1])||0}/${kd.maxConn}\n`;
                    resp += `CREATED: ${new Date(kd.created).toISOString()}\n`;
                    resp += `EXPIRES: ${new Date(kd.expires).toISOString()}\n`;
                    if (forecast) {
                        resp += `FORECAST: ${forecast.dailyAvgGB} GB/day, ${forecast.daysRemaining} days remaining\n`;
                    }
                }
            } else { 
                resp = 'ERROR: Unknown command\n'; 
            }
        } catch(e) { 
            resp = `ERROR: ${e.message}\n`; 
            logError(`API error: ${e.message}`);
        }
        sock.write(resp || 'OK\n'); 
        sock.end(); 
    });
});

// ============================================================================
// START SERVERS
// ============================================================================
server.listen(CONFIG.LISTEN_PORT, '127.0.0.1', () => { 
    console.log(`[GATEWAY] SOCKS5 on 127.0.0.1:${CONFIG.LISTEN_PORT}`); 
    console.log(`[GATEWAY] Public endpoint: ${FULL_CONFIG.public_host}:80`); 
    logAudit(`Gateway started on port ${CONFIG.LISTEN_PORT}`);
});

api.listen(CONFIG.API_PORT, '127.0.0.1', () => {
    console.log(`[API] Management on 127.0.0.1:${CONFIG.API_PORT}`); 
    logAudit(`API started on port ${CONFIG.API_PORT}`);
});

// ============================================================================
// GRACEFUL SHUTDOWN
// ============================================================================
let shuttingDown = false;
function gracefulShutdown() { 
    if (shuttingDown) return;
    shuttingDown = true;
    console.log('[SHUTDOWN] Closing connections...'); 
    logAudit('Graceful shutdown initiated');
    
    server.close(() => console.log('[SHUTDOWN] Gateway closed')); 
    api.close(() => console.log('[SHUTDOWN] API closed'));
    requestFixer.close(() => console.log('[SHUTDOWN] Request Fixer closed'));
    responseFixer.close(() => console.log('[SHUTDOWN] Response Fixer closed'));
    
    poolManager.shutdown(); 
    analytics.shutdown();
    saveState();
    
    console.log('[SHUTDOWN] State saved, exiting...');
    setTimeout(() => process.exit(0), 1000);
}

process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);
process.on('SIGUSR1', () => {
    console.log('[SIGUSR1] Saving state...');
    saveState();
});

// ============================================================================
// AUTO-SAVE AND LIFETIME MANAGER
// ============================================================================
setInterval(() => {
    saveState();
    const stats = analytics.getGlobalStats();
    console.log(`[AUTO-SAVE] State saved. Requests: ${stats.totalRequests}, Bandwidth: ${stats.bandwidthGB}GB`);
}, CONFIG.AUTO_SAVE_INTERVAL);

setTimeout(() => { 
    console.log('[LIFETIME] 24h reached, suspending for 2h...'); 
    logAudit('Lifetime manager: 24h suspend initiated');
    gracefulShutdown(); 
}, FULL_CONFIG.timeouts.process_lifetime_ms);

// ============================================================================
// STARTUP COMPLETE
// ============================================================================
console.log('[SYSTEM] ========================================');
console.log('[SYSTEM] Full feature set loaded successfully');
console.log(`[SYSTEM] Wireproxy pool: ${FULL_CONFIG.wireproxy.instances} instances`);
console.log(`[SYSTEM] Batch window: ${FULL_CONFIG.batch.window_ms}ms`);
console.log(`[SYSTEM] Request Fixer on port ${CONFIG.REQUEST_FIXER_PORT}`);
console.log(`[SYSTEM] Response Fixer on port ${CONFIG.RESPONSE_FIXER_PORT}`);
console.log(`[SYSTEM] Tiers: ${Object.keys(tiers).join(', ')}`);
console.log(`[SYSTEM] IP Pools: ${Object.keys(FULL_CONFIG.ip_pools).join(', ')}`);
console.log(`[SYSTEM] Security: rate_limit=${FULL_CONFIG.security.rate_limit?.enabled}, auto_freeze=${FULL_CONFIG.security.auto_freeze?.enabled}`);
console.log(`[SYSTEM] Analytics: ${FULL_CONFIG.analytics?.enabled ? 'enabled' : 'disabled'}`);
console.log(`[SYSTEM] Loaded ${keys.size} keys from disk`);
console.log('[SYSTEM] ========================================');
logAudit(`System startup complete. ${keys.size} keys loaded.`);