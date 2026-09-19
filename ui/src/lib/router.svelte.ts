export interface Route {
  path: string;
  title: string;
  group: string;
}

// The route table doubles as the sidebar model, so navigation and the pages
// can never drift apart.
export const routes: Route[] = [
  { path: '/peers', title: 'Peers', group: 'Control Center' },
  { path: '/policies', title: 'Policies', group: 'Access Control' },
  { path: '/groups', title: 'Groups', group: 'Access Control' },
  { path: '/setup-keys', title: 'Setup Keys', group: 'Access Control' },
  { path: '/routes', title: 'Routes', group: 'Network Routing' },
  { path: '/budgets', title: 'Traffic Budgets', group: 'Network Routing' },
  { path: '/dns/nameservers', title: 'Nameservers', group: 'DNS' },
  { path: '/dns/zones', title: 'Zones', group: 'DNS' },
  { path: '/dns/settings', title: 'DNS Settings', group: 'DNS' },
  { path: '/committee', title: 'Committee', group: 'BFT' },
  { path: '/activity', title: 'Activity', group: 'BFT' },
  { path: '/settings', title: 'Settings', group: 'Settings' },
];

export const defaultPath = '/peers';

const listeners = new Set<() => void>();

export const router = $state<{ path: string }>({ path: currentPath() });

function currentPath(): string {
  const path = globalThis.location?.pathname ?? defaultPath;
  return path === '/' ? defaultPath : path;
}

function notify() {
  router.path = currentPath();
  for (const listener of listeners) listener();
}

export function startRouter() {
  globalThis.addEventListener?.('popstate', notify);
  if (currentPath() !== globalThis.location?.pathname) {
    history.replaceState(null, '', currentPath());
  }
  return () => globalThis.removeEventListener?.('popstate', notify);
}

export function navigate(path: string) {
  if (path === router.path) return;
  history.pushState(null, '', path);
  notify();
}

export function onChange(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function routeTitle(path: string): string {
  return routes.find((route) => route.path === path)?.title ?? 'Console';
}
