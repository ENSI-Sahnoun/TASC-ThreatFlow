const test = require('node:test');
const assert = require('node:assert');
const { runEval, loadSplit } = require('./quality.eval');

function alwaysCorrectJudge(items) {
  return async (prompt) => {
    const match = prompt.match(/Now classify: "([\s\S]*?)"/);
    const title = match ? match[1] : null;
    const item = items.find((x) => x.title === title);
    return item ? { verdict: item.verdict } : { verdict: 'intel' };
  };
}

test('runEval: a judge that is always right scores 100% with zero conservative failures', async () => {
  const items = loadSplit('tune');
  const result = await runEval('tune', { judge: alwaysCorrectJudge(items), shots: 1 });

  assert.strictEqual(result.total, items.length);
  assert.strictEqual(result.correct, items.length);
  assert.strictEqual(result.accuracy, 1);
  assert.strictEqual(result.conservativeFailures, 0);
});

test('runEval: a judge that always answers roundup scores conservative failures for every true-intel item', async () => {
  const items = loadSplit('tune');
  const trueIntelCount = items.filter((x) => x.verdict === 'intel').length;

  const result = await runEval('tune', { judge: async () => ({ verdict: 'roundup' }), shots: 1 });

  assert.strictEqual(result.conservativeFailures, trueIntelCount);
  assert.ok(result.accuracy < 1);
});

test('loadSplit rejects an unknown split name', () => {
  assert.throws(() => loadSplit('bogus'));
});
