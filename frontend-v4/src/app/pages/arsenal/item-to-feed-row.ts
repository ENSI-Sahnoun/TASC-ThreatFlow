import type { Item, FeedRow } from '../../core/models';

// Every dossier-page item belongs to exactly this one source, so the "cluster" the story drawer
// (Task 10, `StoryDrawerComponent`) expects collapses to a cluster of one: cluster_id mirrors
// item_id, source_count is always 1, and first/last_seen both fall back to the item's own
// published_at. sourceName/sourceStatus come from the page's already-loaded `stats().source`
// rather than the item itself, since `Item` carries no source_status field. This is a
// one-source-context mapping, not a general clustering algorithm — kept in its own
// framework-free module (no Angular imports) purely so it's importable and testable without
// pulling in the whole component's Router/HttpClient dependency graph.
export function itemToFeedRow(
  item: Item, sourceName: string, sourceStatus: string | null, sourceFetchKind: string,
): FeedRow {
  return {
    cluster_id: item.id,
    title: item.title,
    first_seen: item.published_at,
    last_seen: item.published_at,
    source_count: 1,
    item_id: item.id,
    category: item.category,
    summary: item.summary,
    severity: item.severity,
    link: item.link,
    confidence: item.confidence,
    source_name: sourceName,
    source_status: sourceStatus,
    source_fetch_kind: sourceFetchKind,
  };
}
