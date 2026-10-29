/**
 * server.js
 * 
 * Express server for Pressure Map.
 * "Find Unfair Targets, Not Faulty Workers."
 * Principle: "Strengthen the system; protect the people in it."
 */

const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// Load environment variables from .env file if present
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
  try {
    const envContent = fs.readFileSync(envPath, 'utf8');
    envContent.split(/\r?\n/).forEach(line => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) return;
      const eqIdx = trimmed.indexOf('=');
      if (eqIdx > 0) {
        const key = trimmed.slice(0, eqIdx).trim();
        let val = trimmed.slice(eqIdx + 1).trim();
        if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
          val = val.slice(1, -1);
        }
        if (!process.env[key]) {
          process.env[key] = val;
        }
      }
    });
  } catch (err) {
    console.error('Error reading .env file:', err);
  }
}

const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'PressureMap2026!';

const { checkRow, validateRowFormat, getRowStatus } = require('./logic/checks.js');
const { calculateBlockStatus } = require('./logic/mapStatus.js');
const { suggestTargetRange } = require('./logic/suggestTarget.js');
const { 
  validatePrivacy, 
  isSmallGroup, 
  maskRowForPrivacy, 
  maskFindingsForPrivacy, 
  calculatePrivacySafeTotals 
} = require('./logic/privacy.js');

const app = express();
const PORT = process.env.PORT || 3000;

// Paths
const DATA_FILE = path.join(__dirname, 'data', 'reports.json');
const BACKUP_FILE = path.join(__dirname, 'data', 'reports.backup.json');
const BLOCKS_FILE = path.join(__dirname, 'data', 'blocks.json');
const BLOCK_CODES_FILE = path.join(__dirname, 'data', 'blockCodes.json');
const WORKER_VOICE_FILE = path.join(__dirname, 'data', 'workerVoice.json');
const WORKER_VOICE_BACKUP = path.join(__dirname, 'data', 'workerVoice.backup.json');

// Middleware: Body parsers
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));
app.use(express.text({ type: ['text/csv', 'text/plain'], limit: '5mb' }));

/**
 * Cookie Parser Middleware (Vanilla JS, zero dependencies)
 */
function parseCookies(req) {
  const list = {};
  const cookieHeader = req.headers.cookie;
  if (!cookieHeader) return list;
  cookieHeader.split(';').forEach(cookie => {
    const parts = cookie.split('=');
    const name = parts[0]?.trim();
    if (!name) return;
    const val = parts.slice(1).join('=').trim();
    try {
      list[name] = decodeURIComponent(val);
    } catch {
      list[name] = val;
    }
  });
  return list;
}

app.use((req, res, next) => {
  req.cookies = parseCookies(req);
  next();
});

// Serve static frontend assets
app.use(express.static(path.join(__dirname, 'public')));

// ==========================================
// SESSION & AUTHENTICATION STATE
// ==========================================

// In-memory sessions map: token -> { role, block, district, expiresAt }
const sessions = new Map();
const SESSION_DURATION_MS = 2 * 60 * 60 * 1000; // 2 hours

// Rate limiter state for login: ip -> [timestamp, ...]
const loginAttempts = new Map();

/**
 * Basic Rate Limiter: Max 10 attempts per minute per IP
 */
function loginRateLimiter(req, res, next) {
  const ip = req.ip || req.connection?.remoteAddress || '127.0.0.1';
  const now = Date.now();
  const windowMs = 60 * 1000; // 1 minute
  let timestamps = loginAttempts.get(ip) || [];
  timestamps = timestamps.filter(t => (now - t) < windowMs);
  
  if (timestamps.length >= 10) {
    return res.status(429).json({
      success: false,
      error: 'Too many login attempts. Please wait 1 minute before trying again.'
    });
  }
  
  timestamps.push(now);
  loginAttempts.set(ip, timestamps);
  next();
}

/**
 * Helper: Retrieve valid session from memory
 */
function getSession(token) {
  if (!token) return null;
  const sess = sessions.get(token);
  if (!sess) return null;
  if (Date.now() > sess.expiresAt) {
    sessions.delete(token);
    return null;
  }
  return sess;
}

/**
 * Middleware: Require specific role ('admin' or 'worker')
 */
function requireRole(requiredRole) {
  return (req, res, next) => {
    const token = req.cookies?.session_token;
    const session = getSession(token);

    if (!session) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required. Please log in.'
      });
    }

    if (session.role !== requiredRole) {
      return res.status(403).json({
        success: false,
        error: `Forbidden: ${requiredRole} role required.`
      });
    }

    req.session = session;
    next();
  };
}

/**
 * Helper: Read reports JSON file safely
 */
function readReports() {
  try {
    if (!fs.existsSync(DATA_FILE)) {
      if (fs.existsSync(BACKUP_FILE)) {
        fs.copyFileSync(BACKUP_FILE, DATA_FILE);
      } else {
        return [];
      }
    }
    const raw = fs.readFileSync(DATA_FILE, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    console.error('Error reading reports file:', err);
    return [];
  }
}

/**
 * Helper: Write reports JSON file safely
 */
function writeReports(data) {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
    return true;
  } catch (err) {
    console.error('Error writing reports file:', err);
    return false;
  }
}

/**
 * Helper: Read blocks JSON file safely
 */
function readBlocks() {
  try {
    if (fs.existsSync(BLOCKS_FILE)) {
      const raw = fs.readFileSync(BLOCKS_FILE, 'utf8');
      return JSON.parse(raw);
    }
  } catch (err) {
    console.error('Error reading blocks file:', err);
  }
  return [];
}

/**
 * Helper: Read block codes JSON safely
 */
function readBlockCodes() {
  try {
    if (fs.existsSync(BLOCK_CODES_FILE)) {
      const raw = fs.readFileSync(BLOCK_CODES_FILE, 'utf8');
      return JSON.parse(raw);
    }
  } catch (err) {
    console.error('Error reading block codes file:', err);
  }
  return [];
}

/**
 * Helper: Read worker voice JSON safely
 */
function readWorkerVoice() {
  try {
    if (!fs.existsSync(WORKER_VOICE_FILE)) {
      if (fs.existsSync(WORKER_VOICE_BACKUP)) {
        fs.copyFileSync(WORKER_VOICE_BACKUP, WORKER_VOICE_FILE);
      } else {
        return [];
      }
    }
    const raw = fs.readFileSync(WORKER_VOICE_FILE, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    console.error('Error reading worker voice file:', err);
    return [];
  }
}

/**
 * Helper: Write worker voice JSON safely
 */
function writeWorkerVoice(data) {
  try {
    fs.writeFileSync(WORKER_VOICE_FILE, JSON.stringify(data, null, 2), 'utf8');
    return true;
  } catch (err) {
    console.error('Error writing worker voice file:', err);
    return false;
  }
}

/**
 * Simple standard CSV parser (handles commas and quotes)
 */
function parseCSV(text) {
  const lines = text.split(/\r?\n/).filter(line => line.trim().length > 0);
  if (lines.length < 2) return [];

  // Parse header
  const headerLine = lines[0];
  const headers = splitCSVRow(headerLine).map(h => h.trim().replace(/^["']|["']$/g, ''));

  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    const rawValues = splitCSVRow(lines[i]);
    if (rawValues.length === 0 || (rawValues.length === 1 && rawValues[0].trim() === '')) continue;
    
    const rowObj = {};
    headers.forEach((header, index) => {
      let val = rawValues[index] !== undefined ? rawValues[index].trim() : '';
      val = val.replace(/^["']|["']$/g, '');
      rowObj[header] = val;
    });
    rows.push({ rowNumber: i + 1, data: rowObj });
  }

  return rows;
}

/**
 * Split CSV line respecting quotation marks
 */
function splitCSVRow(line) {
  const values = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (char === '"' || char === "'") {
      inQuotes = !inQuotes;
    } else if (char === ',' && !inQuotes) {
      values.push(current);
      current = '';
    } else {
      current += char;
    }
  }
  values.push(current);
  return values;
}

// ==========================================
// AUTHENTICATION API ROUTES
// ==========================================

/**
 * POST /api/login
 * Body: { code } for Worker, OR { username, password } for Admin
 * Sets httpOnly cookie session_token on success.
 */
app.post('/api/login', loginRateLimiter, (req, res) => {
  const { code, username, password } = req.body || {};

  // Case 1: Worker Login via Block Access Code
  if (code && typeof code === 'string') {
    const cleanCode = code.trim().toUpperCase();
    const codes = readBlockCodes();
    
    // Match either exact code or normalized code without spaces/hyphens
    const matched = codes.find(c => {
      const target = c.code.toUpperCase();
      return target === cleanCode || target.replace(/[\s_-]/g, '') === cleanCode.replace(/[\s_-]/g, '');
    });

    if (!matched) {
      return res.status(401).json({
        success: false,
        error: 'Invalid block access code. Please check the code provided for your catchment area.'
      });
    }

    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, {
      role: 'worker',
      block: matched.block,
      district: matched.district,
      expiresAt: Date.now() + SESSION_DURATION_MS
    });

    res.cookie('session_token', token, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: SESSION_DURATION_MS,
      path: '/'
    });

    return res.json({
      success: true,
      role: 'worker',
      block: matched.block,
      district: matched.district
    });
  }

  // Case 2: Admin Login via Username + Password
  if (username !== undefined && password !== undefined) {
    const userMatch = (String(username).trim() === ADMIN_USER);
    const passMatch = (String(password) === ADMIN_PASS);

    if (!userMatch || !passMatch) {
      return res.status(401).json({
        success: false,
        error: 'Invalid username or password.'
      });
    }

    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, {
      role: 'admin',
      block: null,
      district: null,
      expiresAt: Date.now() + SESSION_DURATION_MS
    });

    res.cookie('session_token', token, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: SESSION_DURATION_MS,
      path: '/'
    });

    return res.json({
      success: true,
      role: 'admin',
      block: null
    });
  }

  return res.status(400).json({
    success: false,
    error: 'Missing credentials. Provide a block access code for worker login, or username and password for admin.'
  });
});

/**
 * POST /api/logout
 * Destroys session in memory and clears cookie.
 */
app.post('/api/logout', (req, res) => {
  const token = req.cookies?.session_token;
  if (token) {
    sessions.delete(token);
  }
  res.clearCookie('session_token', { path: '/' });
  res.json({
    success: true,
    message: 'Logged out successfully.'
  });
});

/**
 * GET /api/me
 * Returns current session info: { role, block, district } or 401
 */
app.get('/api/me', (req, res) => {
  const token = req.cookies?.session_token;
  const session = getSession(token);
  if (!session) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  res.json({
    role: session.role,
    block: session.block,
    district: session.district
  });
});

// ==========================================
// CORE DATA API ROUTES (PROTECTED)
// ==========================================

/**
 * GET /api/findings
 * Protected: Admin only
 * Computes findings live from current data file with optional filtering.
 * Privacy-safe: small groups (<30) are masked with "Suppressed (small group)".
 */
app.get('/api/findings', requireRole('admin'), (req, res) => {
  const rawReports = readReports();
  const workerVoiceData = readWorkerVoice();
  const { district, block, month, status } = req.query;

  const results = [];

  for (const rawRow of rawReports) {
    // 1. Compute findings live (nothing hardcoded)
    const rawFindings = checkRow(rawRow);
    const statusInfo = getRowStatus(rawFindings);

    // 2. Filter matching
    if (district && district !== 'All' && rawRow.district !== district) continue;
    if (block && block !== 'All' && rawRow.block !== block) continue;
    if (month && month !== 'All' && rawRow.month !== month) continue;
    if (status && status !== 'All' && statusInfo.status !== status) continue;

    // 3. Privacy suppression for small groups (< 30)
    const maskedRow = maskRowForPrivacy(rawRow);
    const maskedFindings = maskFindingsForPrivacy(rawFindings, rawRow);
    const isSupp = isSmallGroup(rawRow);

    // 4. Suggested fair target calculation
    const suggestedTarget = isSupp ? null : suggestTargetRange(rawRow);

    // 5. Worker voice context (only if >= 5 reports and not suppressed)
    let workerVoiceSummary = null;
    if (!isSupp) {
      const wv = workerVoiceData.find(w => w.district === rawRow.district && w.block === rawRow.block && w.month === rawRow.month);
      if (wv && wv.totalReports >= 5) {
        workerVoiceSummary = {
          totalReports: wv.totalReports,
          issues: wv.issues
        };
      }
    }

    results.push({
      row: maskedRow,
      findings: maskedFindings,
      statusInfo,
      suggestedFairTarget: suggestedTarget,
      workerVoice: workerVoiceSummary,
      rawRowSummary: {
        isSuppressed: isSupp
      }
    });
  }

  res.json({
    totalCount: results.length,
    results,
    notice: 'Privacy Notice: Demographic cohorts with fewer than 30 eligible individuals are suppressed to prevent re-identification.'
  });
});

/**
 * GET /api/summary
 * Protected: Admin only
 * Computes live KPI cards and metadata for filters.
 * Totals strictly exclude small suppressed groups.
 */
app.get('/api/summary', requireRole('admin'), (req, res) => {
  const reports = readReports();

  let groupsReviewed = 0;
  let needingReview = 0;
  let unfairTargets = 0;
  let dataErrors = 0;
  let inconclusiveCount = 0;
  let suppressedSmallGroups = 0;

  const districtsSet = new Set();
  const blocksSet = new Set();
  const monthsSet = new Set();

  for (const row of reports) {
    if (isSmallGroup(row)) {
      suppressedSmallGroups++;
      continue; // Strictly excluded from KPI counts, filters, and charts!
    }

    groupsReviewed++;
    if (row.district) districtsSet.add(row.district);
    if (row.block) blocksSet.add(row.block);
    if (row.month) monthsSet.add(row.month);

    const findings = checkRow(row);
    const statusInfo = getRowStatus(findings);

    if (statusInfo.status === 'error') {
      dataErrors++;
    } else if (statusInfo.status === 'feasibility') {
      unfairTargets++;
      needingReview++;
    } else if (statusInfo.status === 'review') {
      needingReview++;
    } else if (statusInfo.status === 'inconclusive') {
      inconclusiveCount++;
    }
  }

  // Calculate privacy safe totals (strictly excluding < 30)
  const privacyTotals = calculatePrivacySafeTotals(reports);

  res.json({
    kpi: {
      groupsReviewed,
      needingReview,
      unfairTargets,
      dataErrors,
      inconclusiveCount,
      suppressedSmallGroups
    },
    privacyTotals,
    filters: {
      districts: Array.from(districtsSet).sort(),
      blocks: Array.from(blocksSet).sort(),
      months: Array.from(monthsSet).sort()
    },
    tagline: 'Find Unfair Targets, Not Faulty Workers.',
    principle: 'Strengthen the system; protect the people in it.'
  });
});

/**
 * GET /api/chart-data
 * Protected: Admin only
 * Computes district-wise stacked bar counts live from current data.
 * Suppressed groups (eligible < 30) are strictly EXCLUDED.
 * Filters supported: district, block, month
 */
app.get('/api/chart-data', requireRole('admin'), (req, res) => {
  const rawReports = readReports();
  const { district, block, month } = req.query;

  // District accumulator
  const districtMap = new Map();

  for (const rawRow of rawReports) {
    // Strictly exclude suppressed groups (< 30)
    if (isSmallGroup(rawRow)) continue;

    // Filter matching
    if (district && district !== 'All' && rawRow.district !== district) continue;
    if (block && block !== 'All' && rawRow.block !== block) continue;
    if (month && month !== 'All' && rawRow.month !== month) continue;

    const dist = rawRow.district || 'Unknown District';
    if (!districtMap.has(dist)) {
      districtMap.set(dist, {
        dataError: 0,
        needsReview: 0,
        unfairTarget: 0,
        ok: 0,
        inconclusive: 0
      });
    }

    const counts = districtMap.get(dist);
    const findings = checkRow(rawRow);
    const statusInfo = getRowStatus(findings);

    if (statusInfo.status === 'error') {
      counts.dataError++;
    } else if (statusInfo.status === 'feasibility') {
      counts.unfairTarget++;
    } else if (statusInfo.status === 'review') {
      counts.needsReview++;
    } else if (statusInfo.status === 'inconclusive') {
      counts.inconclusive++;
    } else {
      counts.ok++;
    }
  }

  const sortedDistricts = Array.from(districtMap.keys()).sort();

  if (sortedDistricts.length === 0) {
    return res.json({
      labels: [],
      datasets: [],
      summaryText: 'No data to display'
    });
  }

  const dataErrorArr = [];
  const needsReviewArr = [];
  const unfairTargetArr = [];
  const okArr = [];
  const inconclusiveArr = [];
  const summaryParts = [];

  for (const dist of sortedDistricts) {
    const c = districtMap.get(dist);
    dataErrorArr.push(c.dataError);
    needsReviewArr.push(c.needsReview);
    unfairTargetArr.push(c.unfairTarget);
    okArr.push(c.ok);
    inconclusiveArr.push(c.inconclusive);

    const parts = [];
    if (c.dataError > 0) parts.push(`${c.dataError} data error${c.dataError > 1 ? 's' : ''}`);
    if (c.needsReview > 0) parts.push(`${c.needsReview} review`);
    if (c.unfairTarget > 0) parts.push(`${c.unfairTarget} unfair target${c.unfairTarget > 1 ? 's' : ''}`);
    if (c.ok > 0) parts.push(`${c.ok} OK`);
    if (c.inconclusive > 0) parts.push(`${c.inconclusive} inconclusive`);
    summaryParts.push(`${dist}: ${parts.join(', ')}`);
  }

  res.json({
    labels: sortedDistricts,
    datasets: [
      {
        label: 'Data error',
        data: dataErrorArr,
        backgroundColor: '#DC2626' // red
      },
      {
        label: 'Needs review',
        data: needsReviewArr,
        backgroundColor: '#D97706' // amber
      },
      {
        label: 'Unfair target',
        data: unfairTargetArr,
        backgroundColor: '#EA580C' // orange
      },
      {
        label: 'OK',
        data: okArr,
        backgroundColor: '#166534' // green
      },
      {
        label: 'Inconclusive',
        data: inconclusiveArr,
        backgroundColor: '#6B7280' // grey
      }
    ],
    summaryText: summaryParts.join(' | ')
  });
});

/**
 * GET /api/map-data
 * Protected: Admin only
 * Returns block status and coordinates for the Leaflet map.
 * Filters supported: district, month
 */
app.get('/api/map-data', requireRole('admin'), (req, res) => {
  const blocks = readBlocks();
  const rawReports = readReports();
  const { district, month } = req.query;

  // Filter raw reports by district and month
  const filteredReports = rawReports.filter(row => {
    if (district && district !== 'All' && row.district !== district) return false;
    if (month && month !== 'All' && row.month !== month) return false;
    return true;
  });

  // Group reports by district + block
  const blockMap = new Map();
  for (const r of filteredReports) {
    const key = `${r.district}___${r.block}`;
    if (!blockMap.has(key)) blockMap.set(key, []);
    blockMap.get(key).push(r);
  }

  const mapResults = [];
  for (const b of blocks) {
    if (district && district !== 'All' && b.district !== district) continue;

    const key = `${b.district}___${b.block}`;
    const rows = blockMap.get(key) || [];

    // Calculate block status
    const statusResult = calculateBlockStatus(rows);

    mapResults.push({
      district: b.district,
      block: b.block,
      lat: b.lat,
      lng: b.lng,
      status: statusResult.status,
      color: statusResult.color,
      symbol: statusResult.symbol,
      label: statusResult.label,
      reason: statusResult.reason,
      allReasons: statusResult.allReasons,
      counts: statusResult.counts,
      isSuppressed: statusResult.isSuppressed,
      hasRecords: rows.length > 0
    });
  }

  res.json({
    blocks: mapResults,
    notice: 'Map positions are illustrative. All data is synthetic.'
  });
});

/**
 * GET /api/worker-voice
 * Protected: Admin only
 * Returns group-level aggregated problem reports per block.
 * Anonymity rules:
 * - Only shown if block has >= 5 reports, otherwise "Not enough reports to display"
 * - Suppressed blocks (eligible < 30) are NEVER shown!
 */
app.get('/api/worker-voice', requireRole('admin'), (req, res) => {
  const reports = readReports();
  const workerVoice = readWorkerVoice();
  const { district, month } = req.query;

  // Build a set of suppressed blocks from current reports
  const suppressedBlocks = new Set();
  for (const r of reports) {
    if (isSmallGroup(r)) {
      suppressedBlocks.add(`${r.district}___${r.block}`);
    }
  }

  const results = [];

  for (const entry of workerVoice) {
    // 1. Never show suppressed blocks (eligible < 30)
    const key = `${entry.district}___${entry.block}`;
    if (suppressedBlocks.has(key)) {
      continue; // Strictly omitted!
    }

    // 2. Filters
    if (district && district !== 'All' && entry.district !== district) continue;
    if (month && month !== 'All' && entry.month !== month) continue;

    // 3. Anonymity threshold: at least 5 reports required
    const hasEnoughReports = (entry.totalReports || 0) >= 5;

    results.push({
      district: entry.district,
      block: entry.block,
      month: entry.month,
      totalReports: hasEnoughReports ? entry.totalReports : null,
      hasEnoughReports,
      message: hasEnoughReports ? null : 'Not enough reports to display',
      issues: hasEnoughReports ? (entry.issues || {}) : {}
    });
  }

  res.json({
    totalBlocks: results.length,
    results,
    notice: 'Worker Voice reports are aggregate group totals only. Cohorts with fewer than 5 submissions or fewer than 30 eligible individuals are excluded.'
  });
});

/**
 * POST /api/report
 * Protected: Worker only
 * Worker submits a group-level report.
 * The report's block is strictly taken from the SESSION, not from the form.
 * Validates against allowlist & privacy rules, ensures no individual identifiers,
 * appends to data/reports.json.
 */
app.post('/api/report', requireRole('worker'), (req, res) => {
  const payload = req.body || {};

  // 1. Strict Privacy Check (reject workerName, patientId, Aadhaar, phone, etc.)
  const privacyCheck = validatePrivacy(payload);
  if (!privacyCheck.valid) {
    return res.status(400).json({
      success: false,
      error: privacyCheck.error
    });
  }

  // Force block from the worker's session (worker can only report for their own block!)
  const sessionBlock = req.session.block;
  const sessionDistrict = req.session.district || (payload.district ? String(payload.district).trim() : '');

  // Construct normalized payload for format checking
  const checkPayload = {
    ...payload,
    block: sessionBlock,
    district: sessionDistrict
  };

  // 2. Format & Schema Validation
  const formatError = validateRowFormat(checkPayload);
  if (formatError) {
    return res.status(400).json({
      success: false,
      error: `${formatError.explanation} (${formatError.observed})`
    });
  }

  // Clean and construct record strictly without personal identifiers
  const newRecord = {
    district: sessionDistrict,
    block: sessionBlock, // Strictly from session!
    month: String(payload.month).trim(),
    indicator: payload.indicator ? String(payload.indicator).trim() : 'General',
    eligible: payload.eligible !== '' && payload.eligible !== undefined ? Number(payload.eligible) : 0,
    reported: payload.reported !== '' && payload.reported !== undefined ? Number(payload.reported) : 0,
    target: payload.target !== '' && payload.target !== undefined ? Number(payload.target) : 0,
    avg: payload.avg !== '' && payload.avg !== undefined ? Number(payload.avg) : 0,
    sessionsPlanned: payload.sessionsPlanned !== '' && payload.sessionsPlanned !== undefined ? Number(payload.sessionsPlanned) : 0,
    sessionsHeld: payload.sessionsHeld !== '' && payload.sessionsHeld !== undefined ? Number(payload.sessionsHeld) : 0
  };

  if (payload.problems) newRecord.problems = payload.problems;
  if (payload.notes) newRecord.notes = String(payload.notes).trim();

  // 3. Save to data file
  const reports = readReports();
  reports.push(newRecord);
  const ok = writeReports(reports);

  if (!ok) {
    return res.status(500).json({
      success: false,
      error: 'Failed to write record to storage.'
    });
  }

  // 4. Update anonymous group-level worker voice tallies (no names, no IDs, no free text)
  if (Array.isArray(payload.problems) && payload.problems.length > 0) {
    const wvList = readWorkerVoice();
    let wvEntry = wvList.find(w => w.district === newRecord.district && w.block === newRecord.block && w.month === newRecord.month);
    if (!wvEntry) {
      wvEntry = {
        district: newRecord.district,
        block: newRecord.block,
        month: newRecord.month,
        totalReports: 0,
        issues: {}
      };
      wvList.push(wvEntry);
    }
    wvEntry.totalReports = (wvEntry.totalReports || 0) + 1;
    for (const prob of payload.problems) {
      if (typeof prob === 'string' && prob.trim()) {
        const cleanProb = prob.trim();
        wvEntry.issues[cleanProb] = (wvEntry.issues[cleanProb] || 0) + 1;
      }
    }
    writeWorkerVoice(wvList);
  }

  // Live findings check for immediate feedback
  const findings = checkRow(newRecord);
  const statusInfo = getRowStatus(findings);

  res.status(201).json({
    success: true,
    message: 'Group report recorded safely without individual identifiers.',
    record: maskRowForPrivacy(newRecord),
    findings: maskFindingsForPrivacy(findings, newRecord),
    statusInfo
  });
});

/**
 * POST /api/upload
 * Protected: Admin only
 * Accepts CSV string or raw text, parses it, validates privacy and schema,
 * appends or replaces data, and reports accepted/rejected counts.
 */
app.post('/api/upload', requireRole('admin'), (req, res) => {
  let csvText = '';
  if (typeof req.body === 'string') {
    csvText = req.body;
  } else if (req.body && req.body.csv) {
    csvText = req.body.csv;
  } else {
    return res.status(400).json({
      success: false,
      error: 'No CSV content provided in request body.'
    });
  }

  const parsed = parseCSV(csvText);
  if (parsed.length === 0) {
    return res.status(400).json({
      success: false,
      error: 'CSV file is empty or could not be parsed.'
    });
  }

  const accepted = [];
  const rejected = [];

  for (const item of parsed) {
    const rawRow = item.data;

    // Normalize keys to lowercase for standard matching
    const normalized = {};
    for (const [k, v] of Object.entries(rawRow)) {
      const lower = k.toLowerCase().replace(/[\s_-]/g, '');
      if (lower === 'district') normalized.district = v;
      else if (lower === 'block') normalized.block = v;
      else if (lower === 'month') normalized.month = v;
      else if (lower === 'indicator') normalized.indicator = v;
      else if (lower === 'eligible') normalized.eligible = v;
      else if (lower === 'reported') normalized.reported = v;
      else if (lower === 'target') normalized.target = v;
      else if (lower === 'avg' || lower === 'historicalavg' || lower === 'average') normalized.avg = v;
      else if (lower === 'sessionsplanned' || lower === 'planned') normalized.sessionsPlanned = v;
      else if (lower === 'sessionsheld' || lower === 'held') normalized.sessionsHeld = v;
      else normalized[k] = v; // Keep original for privacy check
    }

    // 1. Privacy Check
    const privacyResult = validatePrivacy(normalized);
    if (!privacyResult.valid) {
      rejected.push({
        rowNumber: item.rowNumber,
        reason: privacyResult.error,
        data: rawRow
      });
      continue;
    }

    // 2. Format Check
    const formatError = validateRowFormat(normalized);
    if (formatError) {
      rejected.push({
        rowNumber: item.rowNumber,
        reason: `${formatError.explanation} (${formatError.observed})`,
        data: rawRow
      });
      continue;
    }

    // Prepare accepted row
    accepted.push({
      district: String(normalized.district).trim(),
      block: String(normalized.block).trim(),
      month: String(normalized.month).trim(),
      indicator: normalized.indicator ? String(normalized.indicator).trim() : 'Health Indicator',
      eligible: Number(normalized.eligible) || 0,
      reported: Number(normalized.reported) || 0,
      target: Number(normalized.target) || 0,
      avg: Number(normalized.avg) || 0,
      sessionsPlanned: Number(normalized.sessionsPlanned) || 0,
      sessionsHeld: Number(normalized.sessionsHeld) || 0
    });
  }

  // Update storage
  if (accepted.length > 0) {
    let currentData = req.query.mode === 'replace' ? [] : readReports();
    currentData = currentData.concat(accepted);
    writeReports(currentData);
  }

  res.json({
    success: true,
    totalProcessed: parsed.length,
    acceptedCount: accepted.length,
    rejectedCount: rejected.length,
    rejected
  });
});

/**
 * POST /api/reset
 * Protected: Admin only
 * Restores demo data and demo worker voice tallies from backup files.
 */
app.post('/api/reset', requireRole('admin'), (req, res) => {
  try {
    if (fs.existsSync(BACKUP_FILE)) {
      fs.copyFileSync(BACKUP_FILE, DATA_FILE);
    }
    if (fs.existsSync(WORKER_VOICE_BACKUP)) {
      fs.copyFileSync(WORKER_VOICE_BACKUP, WORKER_VOICE_FILE);
    }

    if (fs.existsSync(BACKUP_FILE)) {
      return res.json({
        success: true,
        message: 'Synthetic demo data and worker voice tallies restored successfully.'
      });
    } else {
      return res.status(404).json({
        success: false,
        error: 'Backup data file not found.'
      });
    }
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: `Failed to reset demo data: ${err.message}`
    });
  }
});

/**
 * GET /api/export
 * Protected: Admin only
 * Downloads a privacy-safe CSV of findings.
 * Small groups (<30) are strictly EXCLUDED from CSV export.
 */
app.get('/api/export', requireRole('admin'), (req, res) => {
  const reports = readReports();

  const headers = [
    'District',
    'Block',
    'Month',
    'Indicator',
    'Eligible',
    'Reported',
    'Target',
    'Historical_Avg',
    'Sessions_Planned',
    'Sessions_Held',
    'Status',
    'Rule_Violated',
    'Severity',
    'System_Explanation',
    'Recommended_Action'
  ];

  const csvLines = [headers.join(',')];

  for (const rawRow of reports) {
    // Strictly exclude suppressed small groups (< 30) from CSV export
    if (isSmallGroup(rawRow)) continue;

    const rawFindings = checkRow(rawRow);
    const statusInfo = getRowStatus(rawFindings);
    const maskedRow = maskRowForPrivacy(rawRow);
    const maskedFindings = maskFindingsForPrivacy(rawFindings, rawRow);

    const escapeCSV = (val) => {
      if (val === null || val === undefined) return '""';
      const str = String(val).replace(/"/g, '""');
      return `"${str}"`;
    };

    if (maskedFindings.length === 0) {
      // Clean row with no findings
      const line = [
        escapeCSV(maskedRow.district),
        escapeCSV(maskedRow.block),
        escapeCSV(maskedRow.month),
        escapeCSV(maskedRow.indicator),
        escapeCSV(maskedRow.eligible),
        escapeCSV(maskedRow.reported),
        escapeCSV(maskedRow.target),
        escapeCSV(maskedRow.avg),
        escapeCSV(maskedRow.sessionsPlanned),
        escapeCSV(maskedRow.sessionsHeld),
        escapeCSV(statusInfo.label),
        escapeCSV('NONE'),
        escapeCSV('none'),
        escapeCSV('Target is aligned with eligible demographic cohort.'),
        escapeCSV('Maintain current supportive supervision schedule.')
      ].join(',');
      csvLines.push(line);
    } else {
      for (const finding of maskedFindings) {
        const line = [
          escapeCSV(maskedRow.district),
          escapeCSV(maskedRow.block),
          escapeCSV(maskedRow.month),
          escapeCSV(maskedRow.indicator),
          escapeCSV(maskedRow.eligible),
          escapeCSV(maskedRow.reported),
          escapeCSV(maskedRow.target),
          escapeCSV(maskedRow.avg),
          escapeCSV(maskedRow.sessionsPlanned),
          escapeCSV(maskedRow.sessionsHeld),
          escapeCSV(statusInfo.label),
          escapeCSV(finding.rule),
          escapeCSV(finding.severity),
          escapeCSV(finding.explanation),
          escapeCSV(finding.recommendedAction)
        ].join(',');
        csvLines.push(line);
      }
    }
  }

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="pressure_map_findings_privacy_safe.csv"');
  res.send(csvLines.join('\r\n'));
});

// Start Server
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Pressure Map server running on http://localhost:${PORT}`);
    console.log(`Tagline: "Find Unfair Targets, Not Faulty Workers."`);
  });
}

module.exports = app;
