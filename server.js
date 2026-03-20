/**
 * ELEVO API Proxy
 * Verbindet elevo.solutions mit Pipedrive CRM
 * 
 * Endpoints:
 *   POST /api/contact  — Kontaktformular → Pipedrive (Person + Deal + Activity)
 *   GET  /api/health    — Health Check
 */

const http = require('http');
const https = require('https');

// ─── Config ───────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const PIPEDRIVE_TOKEN = process.env.PIPEDRIVE_API_TOKEN;
const PIPEDRIVE_BASE = 'https://api.pipedrive.com/v1';
const ALLOWED_ORIGINS = [
  'https://elevo.solutions',
  'https://www.elevo.solutions',
  'http://localhost:3000',
  'http://localhost:8080'
];

// ─── Helpers ──────────────────────────────────────────────────────

function jsonResponse(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json'
  });
  res.end(JSON.stringify(data));
}

function setCORS(req, res) {
  const origin = req.headers.origin || '';
  // Erlaube alle elevo.solutions Subdomains + localhost für Dev
  if (origin.endsWith('.elevo.solutions') || origin === 'https://elevo.solutions' || origin.startsWith('http://localhost')) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else {
    // Fallback: elevo.solutions immer erlauben
    res.setHeader('Access-Control-Allow-Origin', 'https://elevo.solutions');
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Max-Age', '86400');
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 1e6) { // 1MB limit
        req.destroy();
        reject(new Error('Body too large'));
      }
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(body));
      } catch (e) {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

function pipedriveFetch(endpoint, method, data) {
  return new Promise((resolve, reject) => {
    const url = new URL(`${PIPEDRIVE_BASE}${endpoint}`);
    url.searchParams.set('api_token', PIPEDRIVE_TOKEN);

    const payload = JSON.stringify(data);
    const options = {
      hostname: url.hostname,
      path: url.pathname + url.search,
      method: method,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      }
    };

    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(body);
          if (parsed.success) {
            resolve(parsed.data);
          } else {
            reject(new Error(`Pipedrive error: ${JSON.stringify(parsed)}`));
          }
        } catch (e) {
          reject(new Error('Failed to parse Pipedrive response'));
        }
      });
    });

    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

// ─── Validation ───────────────────────────────────────────────────

function validateContact(data) {
  const errors = [];
  if (!data.firstName || data.firstName.trim().length < 1) errors.push('Vorname fehlt');
  if (!data.lastName || data.lastName.trim().length < 1) errors.push('Nachname fehlt');
  if (!data.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.email)) errors.push('Ungültige E-Mail');
  
  // Sanitize
  if (errors.length === 0) {
    return {
      valid: true,
      data: {
        firstName: data.firstName.trim().substring(0, 100),
        lastName: data.lastName.trim().substring(0, 100),
        email: data.email.trim().toLowerCase().substring(0, 200),
        topic: (data.topic || 'Allgemein').trim().substring(0, 200),
        message: (data.message || '').trim().substring(0, 2000),
        source: (data.source || 'Website').trim().substring(0, 100)
      }
    };
  }
  return { valid: false, errors };
}

// ─── Rate Limiting (simple in-memory) ─────────────────────────────

const rateLimit = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 Minute
const RATE_LIMIT_MAX = 5; // Max 5 Requests pro Minute pro IP

function isRateLimited(ip) {
  const now = Date.now();
  const entry = rateLimit.get(ip);
  
  if (!entry || now - entry.start > RATE_LIMIT_WINDOW) {
    rateLimit.set(ip, { start: now, count: 1 });
    return false;
  }
  
  entry.count++;
  if (entry.count > RATE_LIMIT_MAX) return true;
  return false;
}

// Cleanup alte Einträge alle 5 Minuten
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateLimit) {
    if (now - entry.start > RATE_LIMIT_WINDOW * 2) rateLimit.delete(ip);
  }
}, 5 * 60 * 1000);

// ─── Spam-Schutz (Honeypot) ──────────────────────────────────────

function isSpam(data) {
  // Honeypot-Feld: wenn "company" ausgefüllt ist, ist es ein Bot
  if (data.company && data.company.trim().length > 0) return true;
  // Zeitcheck: wenn das Formular in unter 2 Sekunden ausgefüllt wird
  if (data._ts && Date.now() - parseInt(data._ts) < 2000) return true;
  return false;
}

// ─── Main Handler ─────────────────────────────────────────────────

async function handleContact(req, res) {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  
  // Rate Limit
  if (isRateLimited(ip)) {
    return jsonResponse(res, 429, { 
      success: false, 
      error: 'Zu viele Anfragen. Bitte versuche es in einer Minute erneut.' 
    });
  }

  try {
    const rawData = await parseBody(req);
    
    // Spam Check
    if (isSpam(rawData)) {
      // Gib trotzdem 200 zurück damit Bots denken es hat geklappt
      return jsonResponse(res, 200, { success: true });
    }

    // Validation
    const validation = validateContact(rawData);
    if (!validation.valid) {
      return jsonResponse(res, 400, { success: false, errors: validation.errors });
    }

    const { firstName, lastName, email, topic, message, source } = validation.data;

    // 1. Person in Pipedrive anlegen
    const person = await pipedriveFetch('/persons', 'POST', {
      name: `${firstName} ${lastName}`,
      first_name: firstName,
      last_name: lastName,
      email: [{ value: email, primary: true }],
      visible_to: 3 // Für alle sichtbar
    });

    console.log(`✓ Person erstellt: ${person.id} — ${firstName} ${lastName}`);

    // 2. Deal anlegen und mit Person verknüpfen
    const dealTitle = `${firstName} ${lastName} — ${topic}`;
    const deal = await pipedriveFetch('/deals', 'POST', {
      title: dealTitle,
      person_id: person.id,
      stage_id: 1, // Erste Stage der ersten Pipeline (wird nach Pipeline-Setup angepasst)
      visible_to: 3
    });

    console.log(`✓ Deal erstellt: ${deal.id} — ${dealTitle}`);

    // 3. Notiz am Deal hinterlegen (mit allen Details)
    if (message) {
      await pipedriveFetch('/notes', 'POST', {
        deal_id: deal.id,
        person_id: person.id,
        content: `<b>Anfrage über ${source}</b><br><br>` +
                 `<b>Thema:</b> ${topic}<br>` +
                 `<b>Nachricht:</b><br>${message.replace(/\n/g, '<br>')}<br><br>` +
                 `<i>Automatisch erstellt via ELEVO API</i>`
      });
      console.log(`✓ Notiz erstellt für Deal ${deal.id}`);
    }

    // 4. Aktivität anlegen (Follow-up heute)
    const today = new Date().toISOString().split('T')[0];
    await pipedriveFetch('/activities', 'POST', {
      subject: `Erstgespräch planen: ${firstName} ${lastName}`,
      type: 'call',
      deal_id: deal.id,
      person_id: person.id,
      due_date: today,
      due_time: '09:00',
      note: `Lead über ${source}. Thema: ${topic}. Heute kontaktieren!`,
      done: 0
    });

    console.log(`✓ Aktivität erstellt für Deal ${deal.id}`);

    // Erfolg
    jsonResponse(res, 200, {
      success: true,
      message: 'Anfrage erfolgreich übermittelt.'
    });

  } catch (error) {
    console.error('❌ Fehler:', error.message);
    jsonResponse(res, 500, {
      success: false,
      error: 'Es ist ein Fehler aufgetreten. Bitte versuche es erneut oder ruf uns direkt an.'
    });
  }
}

// ─── Server ───────────────────────────────────────────────────────

const server = http.createServer(async (req, res) => {
  setCORS(req, res);

  // Preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  // Routes
  if (req.method === 'GET' && req.url === '/api/health') {
    return jsonResponse(res, 200, { 
      status: 'ok', 
      service: 'ELEVO API Proxy',
      timestamp: new Date().toISOString()
    });
  }

  if (req.method === 'POST' && req.url === '/api/contact') {
    return handleContact(req, res);
  }

  // 404
  jsonResponse(res, 404, { error: 'Not found' });
});

server.listen(PORT, () => {
  console.log(`\n🚀 ELEVO API Proxy läuft auf Port ${PORT}`);
  console.log(`   Health: http://localhost:${PORT}/api/health`);
  console.log(`   Contact: POST http://localhost:${PORT}/api/contact\n`);
  
  if (!PIPEDRIVE_TOKEN) {
    console.warn('⚠️  PIPEDRIVE_API_TOKEN nicht gesetzt! Setze die Umgebungsvariable.');
  }
});
