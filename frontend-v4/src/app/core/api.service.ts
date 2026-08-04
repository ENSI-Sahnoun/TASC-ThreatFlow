import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable, map } from 'rxjs';
import { toQueryParams, type IntelFilters } from './filters';
import type {
  DashboardStats, FeedRow, Source, SourceStats, Item, ItemDetail,
  CveIntel, CveDetail, EntityProfile, SearchResults, Facets, ClusterMember, IocRow, IocCheckResult,
  PreviewCheck, Profile, ProfilePayload, Sector, CpeFacet, DomainOption, RelatedStory,
} from './models';

// One method per endpoint and nothing else. No caching, no state — stores own that.
@Injectable({ providedIn: 'root' })
export class ApiService {
  private http = inject(HttpClient);

  dashboard(): Observable<DashboardStats> {
    return this.http.get<DashboardStats>('/api/stats/dashboard');
  }

  health(): Observable<{ ok: boolean }> {
    return this.http.get<{ ok: boolean }>('/api/health');
  }

  feed(since?: string, limit = 50): Observable<FeedRow[]> {
    let params = new HttpParams().set('limit', limit);
    if (since) params = params.set('since', since);
    return this.http.get<FeedRow[]>('/api/feed', { params });
  }

  items(filters: IntelFilters, limit = 50, offset = 0): Observable<{ rows: Item[]; total: number }> {
    const params = new HttpParams({ fromObject: { ...toQueryParams(filters), limit: String(limit), offset: String(offset) } });
    return this.http.get<Item[]>('/api/items', { params, observe: 'response' }).pipe(
      map((res) => ({ rows: res.body ?? [], total: Number(res.headers.get('X-Total-Count') ?? 0) })));
  }

  item(id: number): Observable<ItemDetail> {
    return this.http.get<ItemDetail>(`/api/items/${id}`);
  }

  clusterItems(clusterId: number): Observable<ClusterMember[]> {
    return this.http.get<ClusterMember[]>(`/api/clusters/${clusterId}/items`);
  }

  relatedStories(clusterId: number): Observable<RelatedStory[]> {
    return this.http.get<RelatedStory[]>(`/api/clusters/${clusterId}/related`);
  }

  sources(): Observable<Source[]> {
    return this.http.get<Source[]>('/api/sources');
  }

  sourceStats(id: number): Observable<SourceStats> {
    return this.http.get<SourceStats>(`/api/sources/${id}/stats`);
  }

  syncSource(id: number): Observable<unknown> {
    return this.http.post(`/api/sources/${id}/sync`, {});
  }

  syncAll(): Observable<{ results: { id: number; name: string; error?: string }[]; consolidation: unknown; consolidationError: string | null }> {
    return this.http.post<{ results: { id: number; name: string; error?: string }[]; consolidation: unknown; consolidationError: string | null }>('/api/sources/sync-all', {});
  }

  updateSource(id: number, patch: {
    name?: string; category?: string; url?: string; notes?: string; auth_required?: string; active?: boolean;
  }): Observable<Source> {
    return this.http.patch<Source>(`/api/sources/${id}`, patch);
  }

  cves(opts: { q?: string; severity?: string; kev?: boolean; min_cvss?: number; limit?: number; offset?: number } = {}):
    Observable<{ rows: CveIntel[]; total: number }> {
    let params = new HttpParams().set('limit', opts.limit ?? 50).set('offset', opts.offset ?? 0);
    if (opts.q) params = params.set('q', opts.q);
    if (opts.severity) params = params.set('severity', opts.severity);
    if (opts.kev) params = params.set('kev', 'true');
    if (opts.min_cvss != null) params = params.set('min_cvss', opts.min_cvss);
    return this.http.get<CveIntel[]>('/api/cves', { params, observe: 'response' }).pipe(
      map((res) => ({ rows: res.body ?? [], total: Number(res.headers.get('X-Total-Count') ?? 0) })));
  }

  cve(cveId: string): Observable<CveDetail> {
    return this.http.get<CveDetail>(`/api/cves/${encodeURIComponent(cveId)}`);
  }

  actor(name: string): Observable<EntityProfile> {
    return this.http.get<EntityProfile>(`/api/actors/${encodeURIComponent(name)}`);
  }

  malware(family: string): Observable<EntityProfile> {
    return this.http.get<EntityProfile>(`/api/malware/${encodeURIComponent(family)}`);
  }

  search(q: string): Observable<SearchResults> {
    return this.http.get<SearchResults>('/api/search', { params: new HttpParams().set('q', q) });
  }

  facets(): Observable<Facets> {
    return this.http.get<Facets>('/api/facets');
  }

  checkIoc(url: string): Observable<IocCheckResult> {
    return this.http.get<IocCheckResult>('/api/ioc-check', { params: new HttpParams().set('url', url) });
  }

  // Asked before an article preview iframe is created — see the endpoint's comment in
  // server/index.js for why framing permission can only be determined server-side.
  previewCheck(url: string): Observable<PreviewCheck> {
    return this.http.get<PreviewCheck>('/api/preview-check', { params: new HttpParams().set('url', url) });
  }

  iocExportUrl(filters: IntelFilters): string {
    const qs = new URLSearchParams(toQueryParams(filters)).toString();
    return `/api/export/iocs${qs ? `?${qs}` : ''}`;
  }

  // Backs "Copy all IOCs" — same filtered rows the CSV export produces, as JSON so the
  // clipboard text doesn't need to re-parse quoted CSV (IOC values legitimately contain commas).
  iocRows(filters: IntelFilters): Observable<IocRow[]> {
    const params = new HttpParams({ fromObject: { ...toQueryParams(filters), format: 'json' } });
    return this.http.get<IocRow[]>('/api/export/iocs', { params });
  }

  profiles(): Observable<Profile[]> {
    return this.http.get<Profile[]>('/api/profiles');
  }

  createProfile(payload: ProfilePayload): Observable<Profile> {
    return this.http.post<Profile>('/api/profiles', payload);
  }

  updateProfile(id: number, payload: ProfilePayload): Observable<Profile> {
    return this.http.put<Profile>(`/api/profiles/${id}`, payload);
  }

  deleteProfile(id: number): Observable<unknown> {
    return this.http.delete(`/api/profiles/${id}`);
  }

  // Deterministic, ~1s over the whole corpus — the route awaits it before responding, so this
  // observable only completes once every item's tier is actually current for the profile.
  recomputeProfileRelevance(id: number): Observable<unknown> {
    return this.http.post(`/api/profiles/${id}/relevance/recompute`, {});
  }

  // Needs Ollama, takes minutes, and — unlike recompute — the route returns 202 immediately and
  // writes in the background: fire this and move on, never await it for correctness.
  generateProfileProse(id: number): Observable<unknown> {
    return this.http.post(`/api/profiles/${id}/relevance/prose`, {});
  }

  tickPlaybookStep(itemId: number, key: string): Observable<unknown> {
    return this.http.post(`/api/items/${itemId}/playbook/steps/${encodeURIComponent(key)}`, {});
  }

  untickPlaybookStep(itemId: number, key: string): Observable<unknown> {
    return this.http.delete(`/api/items/${itemId}/playbook/steps/${encodeURIComponent(key)}`);
  }

  // Same posture as generateProfileProse: needs Ollama, runs in the background, fire and move on.
  wordProfilePlaybooks(id: number): Observable<unknown> {
    return this.http.post(`/api/profiles/${id}/playbooks/word`, {});
  }

  sectors(): Observable<Sector[]> {
    return this.http.get<Sector[]>('/api/sectors');
  }

  domainOptions(): Observable<DomainOption[]> {
    return this.http.get<DomainOption[]>('/api/domains');
  }

  // Autocomplete for the survey's tech-stack step. Reads item_cpes, so the suggestions are
  // slugs that can actually match an item.
  cpeFacets(q: string, kind: 'vendor' | 'product'): Observable<CpeFacet[]> {
    const params = new HttpParams().set('q', q).set('kind', kind);
    return this.http.get<CpeFacet[]>('/api/cpe-facets', { params });
  }
}
