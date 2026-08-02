import { inject } from '@angular/core';
import type { HttpInterceptorFn } from '@angular/common/http';
import { ProfileService } from './profile.service';

// Carries the active profile on every API call so relevance scoring has a subject.
// Kept out of the query string so it does not pollute every filter URL.
//
// Sending no header is valid — the API treats it as "no profile selected". Only an unknown or
// malformed id is an error (400), which is why the id always comes from a loaded profile
// rather than straight from storage.
export const profileInterceptor: HttpInterceptorFn = (req, next) => {
  const active = inject(ProfileService).active();
  if (!active || !req.url.startsWith('/api/')) return next(req);
  return next(req.clone({ setHeaders: { 'X-Profile-Id': String(active.id) } }));
};
