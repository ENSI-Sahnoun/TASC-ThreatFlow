// Shared local-model runtime. Every LM feature in ThreatFlow goes through this one client, so
// the retry, timeout and validation rules are written once and cannot drift between features.
//
// The single governing rule is **absence over fabrication**: any failure — connection refused,
// timeout, non-2xx, unparseable body, output that does not match the caller's schema — resolves
// to `null`, and every caller treats `null` as "write nothing". A wrong model answer that looks
// plausible is far worse here than a missing one, because the deterministic pipeline beside it
// is trusted.
//
// Nothing in this module ever throws past its own boundary.

const OLLAMA_HOST = process.env.OLLAMA_HOST || 'http://localhost:11434';
// EuroLLM-1.7B-Instruct: Horizon-Europe funded (Unbabel / Instituto Superior Técnico /
// Edinburgh), trained across the 24 EU official languages, ~1GB at Q4_K_M.
const DEFAULT_MODEL = process.env.OLLAMA_MODEL || 'hf.co/mradermacher/EuroLLM-1.7B-Instruct-GGUF:Q4_K_M';
const DEFAULT_TIMEOUT_MS = Number(process.env.OLLAMA_TIMEOUT_MS) || 20000;

function buildRequest(prompt, { model = DEFAULT_MODEL, temperature = 0.2 } = {}) {
  return {
    model,
    prompt,
    // Ollama's JSON mode. It constrains generation but does not guarantee schema conformance,
    // which is why parseReply validates independently rather than trusting the flag.
    format: 'json',
    stream: false,
    options: { temperature },
  };
}

// A small model will sometimes wrap its JSON in prose or a fenced block even in JSON mode.
// Recovering the object is fair; guessing at its contents is not.
function extractJson(text) {
  const trimmed = String(text).trim();
  try { return JSON.parse(trimmed); } catch { /* fall through to substring recovery */ }
  const start = trimmed.indexOf('{');
  const end = trimmed.lastIndexOf('}');
  if (start === -1 || end <= start) return null;
  try { return JSON.parse(trimmed.slice(start, end + 1)); } catch { return null; }
}

// Deliberately a tiny hand-rolled validator rather than a schema library: the shapes here are
// two or three fields wide, and a dependency would be more surface than the rules it checks.
// Supported per field: { type: 'string'|'number'|'boolean', enum, maxLength, optional }.
function validate(obj, schema) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return null;
  const out = {};
  for (const [key, rule] of Object.entries(schema)) {
    const value = obj[key];
    if (value === undefined || value === null) {
      if (rule.optional) continue;
      return null;
    }
    if (rule.type && typeof value !== rule.type) return null;
    if (rule.type === 'string') {
      const s = value.trim();
      // An empty string is not an answer — it is the model declining without saying so.
      if (!s) return null;
      if (rule.maxLength && s.length > rule.maxLength) return null;
      if (rule.enum && !rule.enum.includes(s)) return null;
      out[key] = s;
      continue;
    }
    if (rule.enum && !rule.enum.includes(value)) return null;
    out[key] = value;
  }
  return out;
}

function parseReply(body, schema) {
  if (typeof body !== 'string' || !body) return null;
  let envelope;
  try { envelope = JSON.parse(body); } catch { return null; }
  if (!envelope || typeof envelope.response !== 'string') return null;
  return validate(extractJson(envelope.response), schema);
}

async function postOnce(prompt, { model, temperature, timeoutMs, request }) {
  const payload = buildRequest(prompt, { model, temperature });
  if (request) return request(`${OLLAMA_HOST}/api/generate`, { method: 'POST', body: JSON.stringify(payload), timeoutMs });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${OLLAMA_HOST}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    return { status: res.status, body: await res.text() };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Ask the model a question whose answer must match `schema`.
 * Resolves to the validated object, or `null` on any failure whatsoever.
 */
async function judgeText(prompt, {
  schema,
  model = DEFAULT_MODEL,
  temperature = 0.2,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  retries = 1,
  request,
} = {}) {
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    let res;
    try {
      res = await postOnce(prompt, { model, temperature, timeoutMs, request });
    } catch {
      // Transport fault — worth one retry, since it says nothing about the model's competence.
      continue;
    }
    if (!res || typeof res.status !== 'number' || res.status < 200 || res.status >= 300) continue;

    // A well-formed HTTP response that fails validation is NOT retried. The model already
    // answered; asking again mostly produces different nonsense at double the cost.
    return parseReply(res.body, schema);
  }
  return null;
}

module.exports = { judgeText, buildRequest, parseReply, DEFAULT_MODEL, OLLAMA_HOST };
