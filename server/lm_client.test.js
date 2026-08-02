const test = require('node:test');
const assert = require('node:assert');
const { judgeText, buildRequest, parseReply } = require('./lm_client');

const SCHEMA = {
  sentence: { type: 'string', maxLength: 200 },
};

test('buildRequest forces a JSON reply and pins the model', () => {
  const req = buildRequest('say something', { model: 'test-model' });
  assert.strictEqual(req.model, 'test-model');
  assert.strictEqual(req.format, 'json');
  assert.strictEqual(req.stream, false);
  assert.match(JSON.stringify(req), /say something/);
});

test('parseReply extracts and validates the JSON payload', () => {
  const body = JSON.stringify({ response: '{"sentence":"You run FortiOS."}' });
  assert.deepStrictEqual(parseReply(body, SCHEMA), { sentence: 'You run FortiOS.' });
});

// Ollama sometimes wraps JSON in prose or a fenced block even with format:json.
test('parseReply recovers JSON wrapped in prose or a code fence', () => {
  const fenced = JSON.stringify({ response: 'Sure!\n```json\n{"sentence":"ok"}\n```' });
  assert.deepStrictEqual(parseReply(fenced, SCHEMA), { sentence: 'ok' });
});

// Absence over fabrication: every failure mode must be null, never a coerced default.
test('parseReply returns null for malformed or non-conforming output', () => {
  const cases = [
    JSON.stringify({ response: 'not json at all' }),
    JSON.stringify({ response: '{"sentence": 42}' }),          // wrong type
    JSON.stringify({ response: '{"other":"field"}' }),          // missing required key
    JSON.stringify({ response: '{"sentence":""}' }),            // empty string is not an answer
    JSON.stringify({}),                                          // no response field
    'this is not json',                                          // body itself unparseable
    '',
  ];
  for (const body of cases) {
    assert.strictEqual(parseReply(body, SCHEMA), null, `expected null for: ${body.slice(0, 40)}`);
  }
});

test('parseReply rejects a string longer than maxLength rather than truncating it', () => {
  const long = 'x'.repeat(500);
  assert.strictEqual(parseReply(JSON.stringify({ response: JSON.stringify({ sentence: long }) }), SCHEMA), null);
});

test('parseReply validates enum fields', () => {
  const schema = { tier: { type: 'string', enum: ['low', 'high'] } };
  const ok = JSON.stringify({ response: '{"tier":"high"}' });
  const bad = JSON.stringify({ response: '{"tier":"URGENT"}' });
  assert.deepStrictEqual(parseReply(ok, schema), { tier: 'high' });
  assert.strictEqual(parseReply(bad, schema), null);
});

test('judgeText returns the validated object on a good reply', async () => {
  const request = async () => ({ status: 200, body: JSON.stringify({ response: '{"sentence":"fine"}' }) });
  assert.deepStrictEqual(await judgeText('prompt', { schema: SCHEMA, request }), { sentence: 'fine' });
});

test('judgeText returns null when the model is unreachable', async () => {
  const request = async () => { throw new Error('connect ECONNREFUSED'); };
  assert.strictEqual(await judgeText('prompt', { schema: SCHEMA, request, retries: 0 }), null);
});

test('judgeText returns null on a non-2xx status', async () => {
  const request = async () => ({ status: 500, body: 'boom' });
  assert.strictEqual(await judgeText('prompt', { schema: SCHEMA, request, retries: 0 }), null);
});

test('judgeText retries once, then gives up with null', async () => {
  let calls = 0;
  const request = async () => { calls += 1; throw new Error('timeout'); };
  assert.strictEqual(await judgeText('prompt', { schema: SCHEMA, request }), null);
  assert.strictEqual(calls, 2, 'one initial attempt plus one retry');
});

test('judgeText succeeds on the retry when the first attempt failed', async () => {
  let calls = 0;
  const request = async () => {
    calls += 1;
    if (calls === 1) throw new Error('transient');
    return { status: 200, body: JSON.stringify({ response: '{"sentence":"second try"}' }) };
  };
  assert.deepStrictEqual(await judgeText('p', { schema: SCHEMA, request }), { sentence: 'second try' });
});

// A malformed reply is a per-call failure, not a retryable transport fault — retrying a model
// that just produced nonsense mostly produces different nonsense at double the cost.
test('judgeText does not retry a well-formed response that fails validation', async () => {
  let calls = 0;
  const request = async () => { calls += 1; return { status: 200, body: JSON.stringify({ response: 'garbage' }) }; };
  assert.strictEqual(await judgeText('p', { schema: SCHEMA, request }), null);
  assert.strictEqual(calls, 1);
});

test('judgeText never throws past the client', async () => {
  for (const request of [
    async () => { throw new Error('x'); },
    async () => ({ status: 200, body: null }),
    async () => ({ status: 200 }),
    async () => null,
  ]) {
    assert.strictEqual(await judgeText('p', { schema: SCHEMA, request, retries: 0 }), null);
  }
});

// Models routinely emit {"a":""} instead of {} — on an optional field that means "absent",
// and treating it as fatal threw away 20 of 25 valid extractions in the victim job.
test('an empty string on an optional field means absent, not failure', () => {
  const schema = { sector: { type: 'string', optional: true }, region: { type: 'string', optional: true } };
  assert.deepStrictEqual(parseReply(JSON.stringify({ response: '{"sector":"","region":""}' }), schema), {});
  assert.deepStrictEqual(
    parseReply(JSON.stringify({ response: '{"sector":"finance","region":""}' }), schema),
    { sector: 'finance' });
});

test('an empty string on a required field still rejects the whole reply', () => {
  const schema = { sentence: { type: 'string' } };
  assert.strictEqual(parseReply(JSON.stringify({ response: '{"sentence":""}' }), schema), null);
});

// Models return an enum value in whatever casing they like; rejecting on case alone discards
// answers that are correct in substance.
test('enum matching is case-insensitive and returns the canonical spelling', () => {
  const schema = { sector: { type: 'string', enum: ['finance', 'technology-saas'] } };
  assert.deepStrictEqual(parseReply(JSON.stringify({ response: '{"sector":"Finance"}' }), schema), { sector: 'finance' });
  assert.deepStrictEqual(parseReply(JSON.stringify({ response: '{"sector":"Technology-SaaS"}' }), schema), { sector: 'technology-saas' });
  assert.strictEqual(parseReply(JSON.stringify({ response: '{"sector":"banking"}' }), schema), null);
});
