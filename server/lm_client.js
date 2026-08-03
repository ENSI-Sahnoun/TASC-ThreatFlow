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
// Mistral 7B Instruct (Mistral AI, Paris) at q3_K_S, ~3.2GB.
//
// This replaced EuroLLM-1.7B, which could write passable prose but could not classify at all —
// it returned a single constant verdict for 100% of inputs across two prompt shapes, including
// headlines quoted verbatim in its own prompt as counter-examples. Anything smaller than ~7B
// should be re-verified against server/quality.js before being trusted, not assumed to work.
const DEFAULT_MODEL = process.env.OLLAMA_MODEL || 'mistral:7b-instruct-q3_K_S';
// Mixedbread AI (Berlin) mxbai-embed-large, 334M params, 1024 dimensions.
//
// A purpose-trained embedding model, not a generative one — `mistral:7b-instruct` has no
// embedding capability in Ollama, and Mistral's own `mistral-embed` is a cloud API with no local
// weights, which would mean shipping item text to a third party for what is meant to be a
// local-only feature.
const DEFAULT_EMBED_MODEL = process.env.OLLAMA_EMBED_MODEL || 'mxbai-embed-large';
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
      // An empty string on a REQUIRED field is not an answer — it is the model declining
      // without saying so, and the whole reply is rejected.
      //
      // On an OPTIONAL field it means exactly what omitting the key would have meant. Models
      // routinely emit {"sector":"","country":""} instead of {}, and treating that as a fatal
      // error discarded 20 of 25 otherwise-valid victim extractions.
      if (!s) {
        if (rule.optional) continue;
        return null;
      }
      if (rule.maxLength && s.length > rule.maxLength) return null;
      if (rule.enum) {
        // Match case-insensitively and return the canonical spelling. Models emit "Finance" or
        // "Technology-SaaS" for an enum written in lowercase, and rejecting those on casing
        // alone throws away answers that are correct in substance.
        const canonical = rule.enum.find((e) => e.toLowerCase() === s.toLowerCase());
        if (!canonical) return null;
        out[key] = canonical;
        continue;
      }
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

// A vector is only usable if every component is a finite number and at least one is non-zero.
// An all-zero vector is the dangerous case: cosine similarity divides by its magnitude, so it
// would either throw or — worse — silently produce NaN that compares false against every
// threshold, making a broken embedding look like "nothing is related".
function parseEmbedding(body) {
  if (typeof body !== 'string' || !body) return null;
  let envelope;
  try { envelope = JSON.parse(body); } catch { return null; }
  if (!envelope || typeof envelope !== 'object') return null;

  // /api/embed returns { embeddings: [[...]] } for a batch of one; the older /api/embeddings
  // returned { embedding: [...] }. Accept either so the client is not pinned to one Ollama
  // version, and reject anything that is not one of those two shapes.
  const raw = Array.isArray(envelope.embedding)
    ? envelope.embedding
    : (Array.isArray(envelope.embeddings) ? envelope.embeddings[0] : null);

  if (!Array.isArray(raw) || !raw.length) return null;
  if (!raw.every((v) => typeof v === 'number' && Number.isFinite(v))) return null;
  if (raw.every((v) => v === 0)) return null;
  return raw;
}

async function postEmbedOnce(text, { model, timeoutMs, request }) {
  const payload = { model, input: text };
  if (request) return request(`${OLLAMA_HOST}/api/embed`, { method: 'POST', body: JSON.stringify(payload), timeoutMs });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${OLLAMA_HOST}/api/embed`, {
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
 * Embed a single text. Resolves to `number[]`, or `null` on any failure whatsoever —
 * the caller writes nothing and retries on the next pass.
 */
async function embed(text, {
  model = DEFAULT_EMBED_MODEL,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  retries = 1,
  request,
} = {}) {
  const input = typeof text === 'string' ? text.trim() : '';
  // Embedding the empty string returns a vector that is mathematically valid and semantically
  // meaningless — it would sit at some fixed point every other empty item also lands on, and
  // link them all to each other at similarity 1.0.
  if (!input) return null;

  for (let attempt = 0; attempt <= retries; attempt += 1) {
    let res;
    try {
      res = await postEmbedOnce(input, { model, timeoutMs, request });
    } catch {
      continue;   // transport fault — worth one retry
    }
    if (!res || typeof res.status !== 'number' || res.status < 200 || res.status >= 300) continue;
    return parseEmbedding(res.body);
  }
  return null;
}

module.exports = {
  judgeText, buildRequest, parseReply,
  embed, parseEmbedding,
  DEFAULT_MODEL, DEFAULT_EMBED_MODEL, OLLAMA_HOST,
};
