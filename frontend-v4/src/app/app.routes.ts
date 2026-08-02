import { Routes } from '@angular/router';

export const routes: Routes = [
  { path: '', loadComponent: () => import('./pages/dashboard/dashboard.component').then((m) => m.DashboardComponent) },
  { path: 'arsenal', loadComponent: () => import('./pages/arsenal/arsenal-index.component').then((m) => m.ArsenalIndexComponent) },
  { path: 'arsenal/:id', loadComponent: () => import('./pages/arsenal/arsenal-dossier.component').then((m) => m.ArsenalDossierComponent) },
  { path: 'live', loadComponent: () => import('./pages/live/live-feed-page.component').then((m) => m.LiveFeedPageComponent) },
  { path: 'intel', loadComponent: () => import('./pages/intel/explorer.component').then((m) => m.ExplorerComponent) },
  { path: 'intel/:id', loadComponent: () => import('./pages/intel/item-detail.component').then((m) => m.ItemDetailComponent) },
  { path: 'check', loadComponent: () => import('./pages/check/url-check-page.component').then((m) => m.UrlCheckPageComponent) },
  { path: 'cve/:id', loadComponent: () => import('./pages/entity/cve.component').then((m) => m.CveComponent) },
  { path: 'actor/:name', loadComponent: () => import('./pages/entity/actor.component').then((m) => m.ActorComponent) },
  { path: 'malware/:family', loadComponent: () => import('./pages/entity/malware.component').then((m) => m.MalwareComponent) },
  { path: '**', redirectTo: '' },
];
