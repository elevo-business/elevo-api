/**
 * ELEVO API Proxy
 * Verbindet elevo.solutions mit Pipedrive CRM + Meta Conversions API (CAPI)
 *
 * Endpoints:
 *   POST /api/contact  — Kontaktformular → Pipedrive (Person + Deal + Activity)
 *                        + server-seitiges Meta-Lead-Event (CAPI, dedupliziert
 *                          via event_id mit dem Browser-Pixel)
 *   POST /api/aachen-lead — Landingpage /webseite-aachen → monday.com-Board
 *                        "Website-Anfragen Aachen (Meta-Kampagne)" + Meta CAPI
 *   GET  /api/health    — Health Check
 */

const http = require('http');
const https = require('https');
const crypto = require('crypto');

// ─── Config ───────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const PIPEDRIVE_TOKEN = process.env.PIPEDRIVE_API_TOKEN;
const PIPEDRIVE_BASE = 'https://api.pipedrive.com/v1';

// Meta Conversions API (server-seitig). Token + Pixel-ID kommen aus der
// Umgebung (Coolify) — NIE im Code/Repo. Ohne beide Werte wird CAPI still
// übersprungen, der Rest funktioniert weiter.
// Alias-Namen werden unterstützt, da der neukunden-Referenz-Handler
// META_DATASET_ID / META_CAPI_ACCESS_TOKEN nutzt — so greift, was gesetzt ist.
const META_PIXEL_ID = process.env.META_PIXEL_ID || process.env.META_DATASET_ID;
const META_CAPI_TOKEN = process.env.META_CAPI_TOKEN || process.env.META_CAPI_ACCESS_TOKEN;
const META_API_VERSION = process.env.META_API_VERSION || 'v21.0';
const META_TEST_EVENT_CODE = process.env.META_TEST_EVENT_CODE; // optional, nur fürs Testing-Tool
// Optionaler Schutz für den Pipedrive-Webhook: wenn gesetzt, muss die
// Webhook-URL ?token=<wert> tragen, sonst 401. Verhindert gefälschte Leads.
const PIPEDRIVE_WEBHOOK_SECRET = process.env.PIPEDRIVE_WEBHOOK_SECRET;
const PIPEDRIVE_DOMAIN = process.env.PIPEDRIVE_COMPANY_DOMAIN || 'elevo';

// monday.com (Aachen-Kampagne). Token kommt aus der Umgebung (Coolify):
// monday → Profilbild → Entwickler → "Meine Access-Tokens". Ohne Token
// antwortet /api/aachen-lead mit 503, der Rest der API läuft weiter.
const MONDAY_TOKEN = process.env.MONDAY_API_TOKEN;
const MONDAY_AACHEN_BOARD_ID = process.env.MONDAY_AACHEN_BOARD_ID || '5100041969';
// Spalten-IDs des Boards "Website-Anfragen Aachen (Meta-Kampagne)"
// (vom WorkForm erzeugt, IDs entsprechen den Formular-Fragen).
const MONDAY_COLS = {
  company: 'short_texth64c4e6p',
  website: 'linku5raltic',
  timing: 'single_selectcuutq4m',
  email: 'emailvoy0oiac',
  phone: 'phoneptihnc14',
  utmCampaign: 'short_texttykp7cku',
  utmContent: 'short_text7j1mcvvv'
};
// Erlaubte Antworten der Zeitpunkt-Frage — müssen den Status-Labels auf dem
// Board exakt entsprechen (create_labels_if_missing ist bewusst aus).
const MONDAY_TIMING_LABELS = [
  'So schnell wie möglich',
  'In den nächsten 1–3 Monaten',
  'In 3–6 Monaten',
  'Ich schaue mich erst mal nur um'
];
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

// GET-Helfer für Pipedrive (z. B. Person nachladen, um an die E-Mail zu kommen).
function pipedriveGet(endpoint) {
  return new Promise((resolve, reject) => {
    const url = new URL(`${PIPEDRIVE_BASE}${endpoint}`);
    url.searchParams.set('api_token', PIPEDRIVE_TOKEN);
    https.get({ hostname: url.hostname, path: url.pathname + url.search }, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(body);
          resolve(parsed && parsed.success ? parsed.data : null);
        } catch (e) {
          reject(new Error('Pipedrive GET: Antwort nicht lesbar'));
        }
      });
    }).on('error', reject);
  });
}

// ─── monday.com API ───────────────────────────────────────────────

function mondayFetch(query, variables) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ query, variables });
    const options = {
      hostname: 'api.monday.com',
      path: '/v2',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        'Authorization': MONDAY_TOKEN,
        'API-Version': '2024-10'
      }
    };
    const r = https.request(options, (res) => {
      let b = '';
      res.on('data', chunk => b += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(b);
          if (parsed.errors && parsed.errors.length) {
            reject(new Error(`monday API: ${JSON.stringify(parsed.errors)}`));
          } else if (res.statusCode >= 200 && res.statusCode < 300 && parsed.data) {
            resolve(parsed.data);
          } else {
            reject(new Error(`monday API ${res.statusCode}: ${b.substring(0, 300)}`));
          }
        } catch (e) {
          reject(new Error(`monday API: Antwort nicht lesbar (${res.statusCode})`));
        }
      });
    });
    r.on('error', reject);
    r.write(body);
    r.end();
  });
}

// ─── Meta Conversions API (CAPI) ──────────────────────────────────
//
// Sendet ein server-seitiges Lead-Event an Meta. Personendaten werden
// laut Meta-Vorgabe normalisiert (trim + lowercase) und mit SHA-256
// gehasht. fbp/fbc, IP und User-Agent verbessern das Matching. Über das
// gemeinsame event_id (vom Browser-Pixel erzeugt) dedupliziert Meta das
// Server- und das Browser-Event.

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

// E-Mail / Name: trim + lowercase, dann hashen.
function hashNormalized(value) {
  if (!value) return null;
  const v = String(value).trim().toLowerCase();
  return v ? sha256(v) : null;
}

// Telefon: nur Ziffern, Ländervorwahl ohne '+'. Deutsche Nummern mit
// führender 0 werden auf 49 normalisiert (Best-Effort).
function hashPhone(value) {
  if (!value) return null;
  let d = String(value).replace(/[^0-9]/g, '');
  if (!d) return null;
  if (d.startsWith('00')) d = d.slice(2);
  else if (d.startsWith('0')) d = '49' + d.slice(1);
  return sha256(d);
}

function httpsPostJson(urlStr, payload) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlStr);
    const body = JSON.stringify(payload);
    const options = {
      hostname: url.hostname,
      path: url.pathname + url.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body)
      }
    };
    const r = https.request(options, (res) => {
      let b = '';
      res.on('data', chunk => b += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(b);
          if (res.statusCode >= 200 && res.statusCode < 300) resolve(parsed);
          else reject(new Error(`Meta API ${res.statusCode}: ${b}`));
        } catch (e) {
          reject(new Error(`Meta API: Antwort nicht lesbar (${res.statusCode})`));
        }
      });
    });
    r.on('error', reject);
    r.write(body);
    r.end();
  });
}

async function sendMetaConversion({ eventName = 'Lead', eventId, eventSourceUrl, clientIp, userAgent, user = {}, customData = {} }) {
  if (!META_PIXEL_ID || !META_CAPI_TOKEN) {
    console.warn('⚠️  Meta CAPI: META_PIXEL_ID / META_CAPI_TOKEN nicht gesetzt — Event übersprungen.');
    return;
  }

  const userData = {};
  const em = hashNormalized(user.email);     if (em) userData.em = [em];
  const ph = hashPhone(user.phone);          if (ph) userData.ph = [ph];
  const fn = hashNormalized(user.firstName); if (fn) userData.fn = [fn];
  const ln = hashNormalized(user.lastName);  if (ln) userData.ln = [ln];
  if (clientIp) userData.client_ip_address = clientIp;
  if (userAgent) userData.client_user_agent = userAgent;
  if (user.fbp) userData.fbp = user.fbp;
  if (user.fbc) userData.fbc = user.fbc;

  const event = {
    event_name: eventName,
    event_time: Math.floor(Date.now() / 1000),
    action_source: 'website',
    user_data: userData
  };
  if (eventId) event.event_id = eventId;
  if (eventSourceUrl) event.event_source_url = eventSourceUrl;
  if (customData && Object.keys(customData).length) event.custom_data = customData;

  const payload = { data: [event] };
  if (META_TEST_EVENT_CODE) payload.test_event_code = META_TEST_EVENT_CODE;

  const url = `https://graph.facebook.com/${META_API_VERSION}/${META_PIXEL_ID}/events?access_token=${encodeURIComponent(META_CAPI_TOKEN)}`;
  const result = await httpsPostJson(url, payload);
  console.log(`✓ Meta CAPI ${eventName} gesendet (event_id: ${eventId || '—'}, events_received: ${result.events_received ?? '?'})`);
  return result;
}

// ─── Validation ───────────────────────────────────────────────────

// Vollen Namen ("Max Mustermann") in Vor-/Nachname zerlegen.
function splitName(full) {
  const parts = String(full).trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return { firstName: '', lastName: '' };
  if (parts.length === 1) return { firstName: parts[0], lastName: '' };
  return { firstName: parts[0], lastName: parts.slice(1).join(' ') };
}

function validateContact(data) {
  const errors = [];

  // Vor-/Nachname: explizite Felder bevorzugen, sonst aus `name` ableiten.
  // (Das Kontaktformular sendet nur `name`, der Funnel-Check beides.)
  let firstName = (data.firstName || '').trim();
  let lastName = (data.lastName || '').trim();
  if ((!firstName || !lastName) && data.name) {
    const s = splitName(data.name);
    if (!firstName) firstName = s.firstName;
    if (!lastName) lastName = s.lastName;
  }

  if (!firstName) errors.push('Name fehlt');
  if (!data.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.email)) errors.push('Ungültige E-Mail');

  // Sanitize
  if (errors.length === 0) {
    return {
      valid: true,
      data: {
        firstName: firstName.substring(0, 100),
        lastName: lastName.substring(0, 100),
        email: data.email.trim().toLowerCase().substring(0, 200),
        phone: (data.phone || '').trim().substring(0, 50),
        topic: (data.topic || data.service || 'Allgemein').trim().substring(0, 200),
        message: (data.message || '').trim().substring(0, 2000),
        source: (data.source || 'Website').trim().substring(0, 100),
        // UTM Tracking
        utm_source: (data.utm_source || '').trim().substring(0, 200),
        utm_medium: (data.utm_medium || '').trim().substring(0, 200),
        utm_campaign: (data.utm_campaign || '').trim().substring(0, 200),
        utm_term: (data.utm_term || '').trim().substring(0, 200),
        // Meta-Tracking (Dedup-Parameter). event_id wird vom Browser-Pixel
        // erzeugt und nur gesetzt, wenn der Nutzer Marketing-Consent gegeben
        // hat — fehlt es, wird KEIN CAPI-Event gesendet.
        metaEventId: (data.metaEventId || data.event_id || '').trim().substring(0, 100),
        fbp: (data.fbp || '').trim().substring(0, 200),
        fbc: (data.fbc || '').trim().substring(0, 300),
        eventSourceUrl: (data.eventSourceUrl || '').trim().substring(0, 500)
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
  // Honeypot-Feld: das versteckte Feld `_hp` (für Menschen leer, Bots füllen es).
  // NICHT `company` — das ist in beiden Formularen ein legitimes Feld
  // (Coaching/Marke bzw. Website) und darf keine Anfrage verwerfen.
  if (data._hp && String(data._hp).trim().length > 0) return true;
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

    const { firstName, lastName, email, phone, topic, message, source, utm_source, utm_medium, utm_campaign, utm_term,
            metaEventId, fbp, fbc, eventSourceUrl } = validation.data;

    const fullName = `${firstName} ${lastName}`.trim();

    // 1. Person in Pipedrive anlegen
    const person = await pipedriveFetch('/persons', 'POST', {
      name: fullName,
      first_name: firstName,
      last_name: lastName,
      email: [{ value: email, primary: true }],
      ...(phone ? { phone: [{ value: phone, primary: true }] } : {}),
      visible_to: 3 // Für alle sichtbar
    });

    console.log(`✓ Person erstellt: ${person.id} — ${fullName}`);

    // 2. Deal anlegen mit UTM Custom Fields
    const dealTitle = `${fullName} — ${topic}`;
    const dealData = {
      title: dealTitle,
      person_id: person.id,
      stage_id: 1, // Erste Stage der ersten Pipeline (wird nach Pipeline-Setup angepasst)
      visible_to: 3,
      // Custom Fields — UTM Tracking
      '6a4546e5e0257a3b673d546ab78e9347775613e4': utm_source || source, // Lead Source
      'e1b0720182b50e2c8efab9bc7c3cbd1799bc7533': utm_campaign,         // UTM Campaign
      'aa1f6ab9866ce8a50a7f3fe9557cd8b1a6cc6d0f': utm_term,             // UTM Term
      '0430039ca8ed9f98fa242d5bb2f1d0cb8543af56': utm_medium            // UTM Medium
    };
    const deal = await pipedriveFetch('/deals', 'POST', dealData);

    console.log(`✓ Deal erstellt: ${deal.id} — ${dealTitle} [Source: ${utm_source || source}]`);

    // 3. Notiz am Deal hinterlegen (mit allen Details)
    const utmInfo = utm_source ? `<br><br><b>📊 Tracking:</b><br>Source: ${utm_source}<br>Medium: ${utm_medium}<br>Campaign: ${utm_campaign}<br>Keyword: ${utm_term}` : '';
    await pipedriveFetch('/notes', 'POST', {
      deal_id: deal.id,
      person_id: person.id,
      content: `<b>Anfrage über ${utm_source || source}</b><br><br>` +
               `<b>Thema:</b> ${topic}<br>` +
               (message ? `<b>Nachricht:</b><br>${message.replace(/\n/g, '<br>')}` : '') +
               utmInfo + `<br><br><i>Automatisch erstellt via ELEVO API</i>`
    });
    console.log(`✓ Notiz erstellt für Deal ${deal.id}`);

    // 4. Aktivität anlegen (Follow-up heute)
    const today = new Date().toISOString().split('T')[0];
    await pipedriveFetch('/activities', 'POST', {
      subject: `Erstgespräch planen: ${fullName}`,
      type: 'call',
      deal_id: deal.id,
      person_id: person.id,
      due_date: today,
      due_time: '09:00',
      note: `Lead über ${source}. Thema: ${topic}. Heute kontaktieren!`,
      done: 0
    });

    console.log(`✓ Aktivität erstellt für Deal ${deal.id}`);

    // Erfolg — Antwort sofort senden, bevor das CAPI-Event gefeuert wird,
    // damit Meta-Latenz die Formular-Antwort nicht ausbremst.
    jsonResponse(res, 200, {
      success: true,
      message: 'Anfrage erfolgreich übermittelt.'
    });

    // 5. Meta Conversions API — nur wenn der Client ein event_id mitschickt
    //    (= Marketing-Consent im Browser erteilt). Fehler hier dürfen die
    //    bereits erfolgreiche Anfrage nicht beeinflussen → fire-and-forget.
    if (metaEventId) {
      const clientIp = String(ip).split(',')[0].trim();
      sendMetaConversion({
        eventName: 'Lead',
        eventId: metaEventId,
        eventSourceUrl,
        clientIp,
        userAgent: req.headers['user-agent'],
        user: { email, phone, firstName, lastName, fbp, fbc },
        customData: { content_name: topic, lead_source: utm_source || source }
      }).catch(err => console.error('❌ Meta CAPI Fehler:', err.message));
    }

  } catch (error) {
    console.error('❌ Fehler:', error.message);
    jsonResponse(res, 500, {
      success: false,
      error: 'Es ist ein Fehler aufgetreten. Bitte versuche es erneut oder ruf uns direkt an.'
    });
  }
}

// ─── Aachen-Kampagne: Landingpage-Formular → monday.com ──────────
//
// Natives Formular auf /webseite-aachen (statt WorkForm-Embed). Legt den
// Lead als Item auf dem Kampagnen-Board an und feuert das server-seitige
// Meta-Lead-Event — gleiche Dedup-Mechanik wie /api/contact.

function validateAachenLead(data) {
  const errors = [];

  const name = (data.name || '').trim();
  const company = (data.company || '').trim();
  const email = (data.email || '').trim().toLowerCase();
  const phone = (data.phone || '').trim();

  if (!name) errors.push('Name fehlt');
  if (!company) errors.push('Unternehmen fehlt');
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) errors.push('Ungültige E-Mail');
  if (!phone || phone.replace(/[^0-9]/g, '').length < 6) errors.push('Ungültige Telefonnummer');

  if (errors.length > 0) return { valid: false, errors };

  // Website normalisieren (optional, Nutzer tippt oft ohne Protokoll).
  let website = (data.website || '').trim().substring(0, 300);
  if (website && !/^https?:\/\//i.test(website)) website = 'https://' + website;

  // Zeitpunkt gegen die Board-Labels whitelisten — unbekannte Werte fallen
  // still weg, statt die Item-Erstellung scheitern zu lassen.
  const timing = MONDAY_TIMING_LABELS.includes((data.timing || '').trim())
    ? data.timing.trim()
    : '';

  return {
    valid: true,
    data: {
      name: name.substring(0, 200),
      company: company.substring(0, 200),
      email: email.substring(0, 200),
      phone: phone.substring(0, 50),
      website,
      timing,
      utm_source: (data.utm_source || '').trim().substring(0, 200),
      utm_medium: (data.utm_medium || '').trim().substring(0, 200),
      utm_campaign: (data.utm_campaign || '').trim().substring(0, 200),
      utm_content: (data.utm_content || '').trim().substring(0, 200),
      utm_term: (data.utm_term || '').trim().substring(0, 200),
      metaEventId: (data.metaEventId || '').trim().substring(0, 100),
      fbp: (data.fbp || '').trim().substring(0, 200),
      fbc: (data.fbc || '').trim().substring(0, 300),
      eventSourceUrl: (data.eventSourceUrl || '').trim().substring(0, 500)
    }
  };
}

async function handleAachenLead(req, res) {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (isRateLimited(ip)) {
    return jsonResponse(res, 429, {
      success: false,
      error: 'Zu viele Anfragen. Bitte versuche es in einer Minute erneut.'
    });
  }

  if (!MONDAY_TOKEN) {
    console.error('❌ /api/aachen-lead: MONDAY_API_TOKEN nicht gesetzt.');
    return jsonResponse(res, 503, {
      success: false,
      error: 'Anfrage konnte nicht gespeichert werden. Schreib uns direkt: hallo@elevo.solutions'
    });
  }

  try {
    const rawData = await parseBody(req);

    // Spam Check (Honeypot + Zeitcheck) — Bots bekommen freundlich 200.
    if (isSpam(rawData)) {
      return jsonResponse(res, 200, { success: true });
    }

    const validation = validateAachenLead(rawData);
    if (!validation.valid) {
      return jsonResponse(res, 400, { success: false, errors: validation.errors });
    }

    const d = validation.data;

    const columnValues = {
      [MONDAY_COLS.company]: d.company,
      [MONDAY_COLS.email]: { email: d.email, text: d.email },
      [MONDAY_COLS.phone]: { phone: d.phone, countryShortName: 'DE' }
    };
    if (d.website) {
      columnValues[MONDAY_COLS.website] = { url: d.website, text: d.website.replace(/^https?:\/\//i, '') };
    }
    if (d.timing) columnValues[MONDAY_COLS.timing] = { label: d.timing };
    if (d.utm_campaign) columnValues[MONDAY_COLS.utmCampaign] = d.utm_campaign;
    if (d.utm_content) columnValues[MONDAY_COLS.utmContent] = d.utm_content;

    const result = await mondayFetch(
      `mutation ($board: ID!, $name: String!, $cols: JSON!) {
        create_item (board_id: $board, item_name: $name, column_values: $cols, create_labels_if_missing: false) { id }
      }`,
      { board: MONDAY_AACHEN_BOARD_ID, name: d.name, cols: JSON.stringify(columnValues) }
    );

    console.log(`✓ monday-Item erstellt: ${result.create_item.id} — ${d.name} (${d.company})`);

    // Erfolg sofort melden, CAPI danach (fire-and-forget wie bei /api/contact).
    jsonResponse(res, 200, { success: true, message: 'Anfrage erfolgreich übermittelt.' });

    if (d.metaEventId) {
      const clientIp = String(ip).split(',')[0].trim();
      const s = splitName(d.name);
      sendMetaConversion({
        eventName: 'Lead',
        eventId: d.metaEventId,
        eventSourceUrl: d.eventSourceUrl,
        clientIp,
        userAgent: req.headers['user-agent'],
        user: { email: d.email, phone: d.phone, firstName: s.firstName, lastName: s.lastName, fbp: d.fbp, fbc: d.fbc },
        customData: { content_name: 'webseite-aachen', lead_source: d.utm_source || 'webseite-aachen' }
      }).catch(err => console.error('❌ Meta CAPI Fehler (aachen-lead):', err.message));
    }

  } catch (error) {
    console.error('❌ Fehler (aachen-lead):', error.message);
    jsonResponse(res, 500, {
      success: false,
      error: 'Es ist ein Fehler aufgetreten. Bitte versuche es erneut oder schreib uns direkt: hallo@elevo.solutions'
    });
  }
}

// ─── Pipedrive-Webhook → Meta CAPI (Funnel-Check-Buchungen) ───────
//
// Schließt die Tracking-Lücke des Scheduler-iframes: Die Funnel-Check-LP
// bucht direkt im Pipedrive-Scheduler (kein Formular → kein Browser-Pixel).
// Pipedrive feuert bei der Buchung diesen Webhook, der server-seitig ein
// Meta-"Lead"-Event mit gehashter E-Mail/Telefon sendet.
//
// Pipedrive-Setup: Einstellungen → Tools & Apps → Webhooks → neuer Webhook
//   Event: added.deal (bzw. das Objekt, das die Buchung anlegt: lead/deal/activity)
//   URL:   https://api.elevo.solutions/api/pipedrive-webhook?token=<PIPEDRIVE_WEBHOOK_SECRET>
//
// Referenz: neukunden-Repo, capi-webhook/pipedrive-capi-webhook.js

async function handlePipedriveWebhook(req, res, url) {
  // Optionaler Schutz vor gefälschten Leads.
  if (PIPEDRIVE_WEBHOOK_SECRET && url.searchParams.get('token') !== PIPEDRIVE_WEBHOOK_SECRET) {
    return jsonResponse(res, 401, { error: 'unauthorized' });
  }

  try {
    const body = await parseBody(req);

    // v1: { event: 'added.deal', current: {...} }
    // v2: { meta: { action, object }, data: {...} }
    const ev = body.event || (body.meta ? `${body.meta.action}.${body.meta.object}` : '');
    const obj = body.current || body.data || {};

    if (!/added\.(lead|deal|activity|person)/.test(ev)) {
      return jsonResponse(res, 200, { ignored: true, ev });
    }

    // E-Mail/Telefon bestimmen — ggf. Person nachladen.
    let email = null, phone = null;
    if (obj.email) email = Array.isArray(obj.email) ? (obj.email[0] && obj.email[0].value) : obj.email;
    const personId = (obj.person_id && obj.person_id.value) || obj.person_id || (ev.endsWith('.person') ? obj.id : null);
    if ((!email || !phone) && personId) {
      const p = await pipedriveGet(`/persons/${personId}`);
      if (p) {
        email = email || (p.email && p.email[0] && p.email[0].value) || p.primary_email || null;
        phone = phone || (p.phone && p.phone[0] && p.phone[0].value) || null;
      }
    }

    if (!email) return jsonResponse(res, 200, { skipped: 'no_email', ev });

    // Idempotenz/Dedup bei Pipedrive-Retries und gegenüber etwaigen Browser-Events.
    const eventId = `pd_${ev}_${obj.id || personId}`;

    try {
      await sendMetaConversion({
        eventName: 'Lead',
        eventId,
        eventSourceUrl: 'https://elevo.solutions/funnel-check',
        clientIp: String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || undefined,
        userAgent: req.headers['user-agent'],
        user: { email, phone },
        customData: { content_name: 'funnel-check-booking' }
      });
      return jsonResponse(res, 200, { ok: true, ev, event_id: eventId });
    } catch (err) {
      console.error('❌ Meta CAPI (Webhook) Fehler:', err.message);
      return jsonResponse(res, 502, { ok: false, error: 'meta_capi_failed' });
    }

  } catch (error) {
    console.error('❌ Pipedrive-Webhook Fehler:', error.message);
    return jsonResponse(res, 400, { error: 'bad_request' });
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

  // Pfad ohne Query-String matchen (Webhook trägt ?token=…).
  const url = new URL(req.url, 'http://localhost');
  const path = url.pathname;

  // Routes
  if (req.method === 'GET' && path === '/api/health') {
    const payload = {
      status: 'ok',
      service: 'ELEVO API Proxy',
      integrations: {
        pipedrive: Boolean(PIPEDRIVE_TOKEN),
        metaCapi: Boolean(META_PIXEL_ID && META_CAPI_TOKEN),
        monday: Boolean(MONDAY_TOKEN)
      },
      timestamp: new Date().toISOString()
    };
    // ?deep=1 prüft den monday-Token aktiv (winzige me-Query) und meldet die
    // Fehlerklasse — hilft bei der Diagnose ohne Zugriff auf Container-Logs.
    // Es wird nie der Token selbst ausgegeben.
    if (url.searchParams.get('deep') === '1' && MONDAY_TOKEN) {
      try {
        const me = await mondayFetch('query { me { id } }', {});
        payload.mondayCheck = { ok: true, userId: me.me && me.me.id };
      } catch (err) {
        payload.mondayCheck = { ok: false, error: String(err.message).substring(0, 300) };
      }
    }
    return jsonResponse(res, 200, payload);
  }

  if (req.method === 'POST' && path === '/api/contact') {
    return handleContact(req, res);
  }

  if (req.method === 'POST' && path === '/api/aachen-lead') {
    return handleAachenLead(req, res);
  }

  if (req.method === 'POST' && path === '/api/pipedrive-webhook') {
    return handlePipedriveWebhook(req, res, url);
  }

  // 404
  jsonResponse(res, 404, { error: 'Not found' });
});

server.listen(PORT, () => {
  console.log(`\n🚀 ELEVO API Proxy läuft auf Port ${PORT}`);
  console.log(`   Health: http://localhost:${PORT}/api/health`);
  console.log(`   Contact: POST http://localhost:${PORT}/api/contact`);
  console.log(`   Pipedrive-Webhook: POST http://localhost:${PORT}/api/pipedrive-webhook\n`);
  
  if (!PIPEDRIVE_TOKEN) {
    console.warn('⚠️  PIPEDRIVE_API_TOKEN nicht gesetzt! Setze die Umgebungsvariable.');
  }
  if (!META_PIXEL_ID || !META_CAPI_TOKEN) {
    console.warn('⚠️  Meta CAPI deaktiviert — setze META_PIXEL_ID/META_DATASET_ID und META_CAPI_TOKEN/META_CAPI_ACCESS_TOKEN.');
  } else {
    console.log(`   Meta CAPI aktiv (Dataset ${META_PIXEL_ID}, ${META_API_VERSION})`);
  }
  if (!PIPEDRIVE_WEBHOOK_SECRET) {
    console.warn('⚠️  PIPEDRIVE_WEBHOOK_SECRET nicht gesetzt — /api/pipedrive-webhook ist ungeschützt.');
  }
  if (!MONDAY_TOKEN) {
    console.warn('⚠️  MONDAY_API_TOKEN nicht gesetzt — /api/aachen-lead antwortet mit 503.');
  } else {
    console.log(`   monday.com aktiv (Board ${MONDAY_AACHEN_BOARD_ID})`);
  }
});
