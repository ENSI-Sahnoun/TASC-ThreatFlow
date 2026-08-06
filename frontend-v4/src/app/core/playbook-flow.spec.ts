import { describe, it, expect } from 'vitest';
import { FLOW_TEMPLATES, hasFlow, resolveFlow } from './playbook-flow';
import type { Playbook, PlaybookStep } from './models';

const step = (key: string): PlaybookStep => ({ key, title: 't', detail: 'd', source: 's', link: null });

describe('hasFlow', () => {
  it('is true for phishing', () => {
    expect(hasFlow('phishing')).toBe(true);
  });

  it('is false for any category without a template, including cve', () => {
    expect(hasFlow('cve')).toBe(false);
    expect(hasFlow('malware')).toBe(false);
    expect(hasFlow(null)).toBe(false);
    expect(hasFlow(undefined)).toBe(false);
  });
});

describe('resolveFlow (phishing)', () => {
  const template = FLOW_TEMPLATES['phishing'];

  it('resolves every optional node false when the item has no indicators', () => {
    const pb: Playbook = { steps: [step('phishing:confirm'), step('phishing:check-clicked')], done: [] };
    const resolved = resolveFlow(template, pb);

    const hasIndicators = resolved.find((n) => n.type === 'decision' && n.gates === 'phishing:block-iocs');
    expect(hasIndicators?.taken).toBe(false);

    const hasUrl = resolved.find((n) => n.type === 'decision' && n.gates === 'phishing:report-phishing-url');
    expect(hasUrl?.taken).toBe(false);

    const blockIocs = resolved.find((n) => n.type === 'action' && n.key === 'phishing:block-iocs');
    expect(blockIocs?.resolved).toBe(false);
  });

  it('resolves the indicators decision true but the URL decision false when indicators exist with no URL type', () => {
    const pb: Playbook = {
      steps: [step('phishing:confirm'), step('phishing:block-iocs'), step('phishing:check-clicked')],
      done: [],
    };
    const resolved = resolveFlow(template, pb);

    expect(resolved.find((n) => n.type === 'decision' && n.gates === 'phishing:block-iocs')?.taken).toBe(true);
    expect(resolved.find((n) => n.type === 'action' && n.key === 'phishing:block-iocs')?.resolved).toBe(true);
    expect(resolved.find((n) => n.type === 'decision' && n.gates === 'phishing:report-phishing-url')?.taken).toBe(false);
  });

  it('resolves both decisions true when a URL indicator is present', () => {
    const pb: Playbook = {
      steps: [
        step('phishing:confirm'), step('phishing:block-iocs'),
        step('phishing:report-phishing-url'), step('phishing:check-clicked'),
      ],
      done: [],
    };
    const resolved = resolveFlow(template, pb);

    expect(resolved.find((n) => n.type === 'decision' && n.gates === 'phishing:block-iocs')?.taken).toBe(true);
    expect(resolved.find((n) => n.type === 'decision' && n.gates === 'phishing:report-phishing-url')?.taken).toBe(true);
  });

  it('reflects done[] on resolved action nodes', () => {
    const pb: Playbook = {
      steps: [step('phishing:confirm'), step('phishing:check-clicked')],
      done: ['phishing:confirm'],
    };
    const resolved = resolveFlow(template, pb);
    expect(resolved.find((n) => n.type === 'action' && n.key === 'phishing:confirm')?.done).toBe(true);
    expect(resolved.find((n) => n.type === 'action' && n.key === 'phishing:check-clicked')?.done).toBe(false);
  });

  it('leaves start/end nodes unchanged and never throws on a null playbook', () => {
    const resolved = resolveFlow(template, null);
    expect(resolved[0]).toEqual(template[0]);
    expect(resolved.every((n) => n.type !== 'action' || n.resolved === false)).toBe(true);
  });
});
