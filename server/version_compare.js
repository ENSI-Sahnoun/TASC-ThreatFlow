// Pure dotted-numeric version comparison. This is the one part of the remediation feature that
// can hurt someone directly — a comparator bug that says "you're patched" when you are not is
// worse than no comparator at all — so it abstains (returns null) the moment it meets anything
// it has no business ordering, rather than guessing. Do not "improve" this into a semver/RPM/
// dpkg-aware comparator without a spec of its own — three comparator implementations with three
// test suites is a different project, and abstaining is safe where guessing is not.
//
// No I/O, no throw. Every public function returns a value, never an exception, for any input.

// Splits a version string into its numeric segments, or null the moment any segment is not a
// bare run of digits. '1.02' and '1.2' compare equal (Number() strips the leading zero); '1.0.0-rc1',
// '1:2.4.1', '2.4.1-3.el9' and 'v7.4.5' all fail on their first non-numeric segment.
function segmentsOf(v) {
  if (typeof v !== 'string' || v === '') return null;
  const parts = v.split('.');
  const nums = [];
  for (const p of parts) {
    if (!/^\d+$/.test(p)) return null;
    nums.push(Number(p));
  }
  return nums;
}

// -1 | 0 | 1 when both sides are confidently ordered, null the moment either side is not a
// plain dotted-numeric version. Shorter operands are treated as zero-padded ('2.0' == '2.0.0'),
// and comparison is numeric per segment, not lexical ('7.4.10' > '7.4.9' — a string compare
// gets this backwards, which is the classic version-compare bug).
function compareVersions(a, b) {
  const sa = segmentsOf(a);
  const sb = segmentsOf(b);
  if (sa === null || sb === null) return null;
  const len = Math.max(sa.length, sb.length);
  for (let i = 0; i < len; i += 1) {
    const x = sa[i] ?? 0;
    const y = sb[i] ?? 0;
    if (x < y) return -1;
    if (x > y) return 1;
  }
  return 0;
}

// One affected_versions entry, already selected by the caller for the asset's vendor/product
// (playbook.js's confirmStep does the same match). `installed` is the version a reader told us
// they run — null/absent means "not asked, or asked and declined", and must read as unknown,
// never as evidence of safety.
//
// Two asymmetries are load-bearing:
//  - `not_covered` requires every comparison actually attempted to have resolved (non-null). The
//    moment any comparison the entry's bounds require returns null, the result is 'unknown', full
//    stop — never falls through to a not_covered verdict built on a partial answer.
//  - A `pinned` mismatch is 'unknown', never 'not_covered'. An exact-pin CPE match usually
//    reflects how the CNA filed the record, not an assertion that neighbouring builds are safe.
function affectedStatus(installed, entry) {
  if (!entry) return 'unknown';
  if (installed == null || installed === '') return 'unknown';

  const { startIncluding, startExcluding, endIncluding, endExcluding, pinned } = entry;
  const hasBound = Boolean(startIncluding || startExcluding || endIncluding || endExcluding);

  if (hasBound) {
    let lowerOk = true;
    if (startIncluding) {
      const c = compareVersions(installed, startIncluding);
      if (c === null) return 'unknown';
      lowerOk = c !== -1;
    } else if (startExcluding) {
      const c = compareVersions(installed, startExcluding);
      if (c === null) return 'unknown';
      lowerOk = c === 1;
    }

    let upperOk = true;
    if (endIncluding) {
      const c = compareVersions(installed, endIncluding);
      if (c === null) return 'unknown';
      upperOk = c !== 1;
    } else if (endExcluding) {
      const c = compareVersions(installed, endExcluding);
      if (c === null) return 'unknown';
      upperOk = c === -1;
    }

    return lowerOk && upperOk ? 'affected' : 'not_covered';
  }

  if (pinned) {
    return installed === pinned ? 'affected' : 'unknown';
  }

  return 'unknown';
}

module.exports = { compareVersions, affectedStatus };
