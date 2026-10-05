// The backend stores times in UTC. Older rows come back without a "+00:00" ending,
// so add "Z" (UTC) before parsing, otherwise the browser would treat them as local time.
export function formatDate(isoString) {
  const hasZone = /([+-]\d\d:\d\d|Z)$/.test(isoString);
  return new Date(hasZone ? isoString : `${isoString}Z`).toLocaleString();
}
