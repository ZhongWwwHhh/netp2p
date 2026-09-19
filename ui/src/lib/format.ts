export function shortPeerId(peerId: string, length = 12): string {
  if (!peerId) return '';
  if (peerId.length <= length) return peerId;
  return `${peerId.slice(0, length)}…`;
}

export function shortHash(hash: string, length = 12): string {
  if (!hash) return '';
  return hash.length <= length ? hash : `${hash.slice(0, length)}…`;
}

// relativeTime renders "just now" / "3 minutes ago" style timestamps, matching
// the freshness language NetBird uses in its peer table.
export function relativeTime(value: string | number | Date | undefined, now = Date.now()): string {
  if (!value) return 'never';
  const timestamp = value instanceof Date ? value.getTime() : new Date(value).getTime();
  if (Number.isNaN(timestamp)) return 'never';
  const seconds = Math.round((now - timestamp) / 1000);
  if (seconds < 5) return 'just now';
  if (seconds < 60) return `${seconds} seconds ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} ${minutes === 1 ? 'minute' : 'minutes'} ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} ${hours === 1 ? 'hour' : 'hours'} ago`;
  const days = Math.round(hours / 24);
  return `${days} ${days === 1 ? 'day' : 'days'} ago`;
}

export function bytesLabel(value: number): string {
  if (!value) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const exponent = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
  const scaled = value / 1024 ** exponent;
  return `${scaled >= 10 || exponent === 0 ? Math.round(scaled) : scaled.toFixed(1)} ${units[exponent]}`;
}

export function bitrateLabel(bitsPerSecond: number): string {
  if (!bitsPerSecond) return 'unlimited';
  const units = ['bps', 'Kbps', 'Mbps', 'Gbps'];
  const exponent = Math.min(Math.floor(Math.log(bitsPerSecond) / Math.log(1000)), units.length - 1);
  const scaled = bitsPerSecond / 1000 ** exponent;
  return `${scaled >= 10 || exponent === 0 ? Math.round(scaled) : scaled.toFixed(1)} ${units[exponent]}`;
}

export function percent(used: number, limit: number): number {
  if (!limit) return 0;
  return Math.min(100, Math.round((used / limit) * 100));
}

export function truncate(value: string, length = 60): string {
  if (!value) return '';
  return value.length <= length ? value : `${value.slice(0, length)}…`;
}
