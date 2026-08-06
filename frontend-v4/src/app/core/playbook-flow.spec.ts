import { describe, it, expect } from 'vitest';
import { FLOW_TEMPLATES, hasFlow, resolveFlow, layoutFlow } from './playbook-flow';
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

describe('layoutFlow', () => {
  it('positions one row per template node, all sharing the same width center', () => {
    const template = FLOW_TEMPLATES['phishing'];
    const pb: Playbook = {
      steps: [
        step('phishing:confirm'), step('phishing:block-iocs'),
        step('phishing:report-phishing-url'), step('phishing:check-clicked'),
      ],
      done: [],
    };
    const layout = layoutFlow(resolveFlow(template, pb));

    expect(layout.nodes).toHaveLength(template.length);
    // No two nodes may overlap vertically: each node's y must be >= the previous node's bottom.
    for (let i = 1; i < layout.nodes.length; i++) {
      expect(layout.nodes[i].y).toBeGreaterThanOrEqual(layout.nodes[i - 1].y + layout.nodes[i - 1].height);
    }
    expect(layout.height).toBeGreaterThan(0);
  });

  it('draws no rail edges when every decision is taken', () => {
    const pb: Playbook = {
      steps: [
        step('phishing:confirm'), step('phishing:block-iocs'),
        step('phishing:report-phishing-url'), step('phishing:check-clicked'),
      ],
      done: [],
    };
    const layout = layoutFlow(resolveFlow(FLOW_TEMPLATES['phishing'], pb));
    expect(layout.edges.some((e) => e.dashed)).toBe(false);
  });

  it('draws a 3-segment dashed rail around a skipped action, and gives the skipped box no edges', () => {
    const pb: Playbook = { steps: [step('phishing:confirm'), step('phishing:check-clicked')], done: [] };
    const layout = layoutFlow(resolveFlow(FLOW_TEMPLATES['phishing'], pb));

    const railEdges = layout.edges.filter((e) => e.dashed);
    // Two skipped decisions (has-indicators, has-url) x 3 rail segments each.
    expect(railEdges).toHaveLength(6);

    const blockIocsKey = 'phishing:block-iocs';
    expect(layout.edges.some((e) => e.key.includes(blockIocsKey))).toBe(false);
  });
});
