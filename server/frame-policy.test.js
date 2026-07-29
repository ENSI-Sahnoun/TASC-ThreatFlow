const test = require('node:test');
const assert = require('node:assert');
const { frameVerdict, frameAncestorsOf } = require('./frame-policy');

const VIEWER = 'http://localhost:4200';
const TARGET = 'https://www.theregister.com/2026/01/01/story/';
const ctx = { viewerOrigin: VIEWER, targetUrl: TARGET };

test('no framing headers at all means frameable', () => {
  assert.deepStrictEqual(frameVerdict({}, ctx), { frameable: true });
});

test('X-Frame-Options DENY blocks', () => {
  const v = frameVerdict({ 'x-frame-options': 'DENY' }, ctx);
  assert.strictEqual(v.frameable, false);
  assert.strictEqual(v.reason, 'x-frame-options');
});

test('X-Frame-Options SAMEORIGIN blocks a cross-origin viewer', () => {
  assert.strictEqual(frameVerdict({ 'x-frame-options': 'sameorigin' }, ctx).frameable, false);
});

test('X-Frame-Options SAMEORIGIN allows the target framing itself', () => {
  const v = frameVerdict({ 'x-frame-options': 'SAMEORIGIN' }, {
    viewerOrigin: 'https://www.theregister.com', targetUrl: TARGET,
  });
  assert.strictEqual(v.frameable, true);
});

// Browsers dropped ALLOW-FROM; an unparseable value imposes no restriction, so neither do we.
test('X-Frame-Options ALLOW-FROM is ignored, not treated as a block', () => {
  assert.strictEqual(frameVerdict({ 'x-frame-options': 'ALLOW-FROM https://example.com' }, ctx).frameable, true);
});

test("frame-ancestors 'none' blocks", () => {
  const v = frameVerdict({ 'content-security-policy': "default-src 'self'; frame-ancestors 'none'" }, ctx);
  assert.strictEqual(v.frameable, false);
  assert.strictEqual(v.reason, 'frame-ancestors');
  assert.match(v.detail, /frame-ancestors 'none'/);
});

test('frame-ancestors * allows anyone', () => {
  assert.strictEqual(frameVerdict({ 'content-security-policy': 'frame-ancestors *' }, ctx).frameable, true);
});

test("frame-ancestors 'self' blocks a cross-origin viewer", () => {
  assert.strictEqual(frameVerdict({ 'content-security-policy': "frame-ancestors 'self'" }, ctx).frameable, false);
});

test('frame-ancestors host match allows the listed origin', () => {
  const headers = { 'content-security-policy': "frame-ancestors 'self' http://localhost:4200" };
  assert.strictEqual(frameVerdict(headers, ctx).frameable, true);
});

test('frame-ancestors port mismatch blocks', () => {
  const headers = { 'content-security-policy': 'frame-ancestors http://localhost:9999' };
  assert.strictEqual(frameVerdict(headers, ctx).frameable, false);
});

test('frame-ancestors wildcard subdomain matches', () => {
  const headers = { 'content-security-policy': 'frame-ancestors *.example.com' };
  const v = frameVerdict(headers, { viewerOrigin: 'https://app.example.com', targetUrl: TARGET });
  assert.strictEqual(v.frameable, true);
});

test('frame-ancestors wildcard subdomain does not match the bare apex', () => {
  const headers = { 'content-security-policy': 'frame-ancestors *.example.com' };
  const v = frameVerdict(headers, { viewerOrigin: 'https://example.com', targetUrl: TARGET });
  assert.strictEqual(v.frameable, false);
});

test('scheme-source matches any host on that scheme', () => {
  const headers = { 'content-security-policy': 'frame-ancestors https:' };
  assert.strictEqual(frameVerdict(headers, { viewerOrigin: 'https://anything.test', targetUrl: TARGET }).frameable, true);
  assert.strictEqual(frameVerdict(headers, ctx).frameable, false); // viewer is http:
});

// CSP Level 3: frame-ancestors supersedes X-Frame-Options when both are present.
test('frame-ancestors * wins over a legacy X-Frame-Options: DENY', () => {
  const headers = { 'x-frame-options': 'DENY', 'content-security-policy': 'frame-ancestors *' };
  assert.strictEqual(frameVerdict(headers, ctx).frameable, true);
});

test('a repeated CSP header blocks if any single policy blocks', () => {
  const headers = { 'content-security-policy': ['frame-ancestors *', "frame-ancestors 'none'"] };
  assert.strictEqual(frameVerdict(headers, ctx).frameable, false);
});

test('comma-joined policies in one header are split apart', () => {
  const headers = { 'content-security-policy': "frame-ancestors *, default-src 'self'; frame-ancestors 'none'" };
  assert.strictEqual(frameVerdict(headers, ctx).frameable, false);
});

test('a CSP without frame-ancestors falls through to X-Frame-Options', () => {
  const headers = { 'content-security-policy': "default-src 'self'", 'x-frame-options': 'DENY' };
  assert.strictEqual(frameVerdict(headers, ctx).frameable, false);
});

test('frame-ancestors with no sources is treated as none', () => {
  assert.strictEqual(frameVerdict({ 'content-security-policy': 'frame-ancestors' }, ctx).frameable, false);
});

test('frameAncestorsOf returns null when the directive is absent', () => {
  assert.strictEqual(frameAncestorsOf("default-src 'self'; script-src 'none'"), null);
});
