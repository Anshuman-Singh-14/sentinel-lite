// The backend stores times in UTC. Older rows come back without a "+00:00" ending,
// so add "Z" (UTC) before parsing, otherwise the browser would treat them as local time.
function parseDate(isoString) {
  const hasZone = /([+-]\d\d:\d\d|Z)$/.test(isoString);
  return new Date(hasZone ? isoString : `${isoString}Z`);
}

export function formatDate(isoString) {
  return parseDate(isoString).toLocaleString();
}

// A compact form for tables, e.g. "16 Nov, 04:38".
export function formatShortDate(isoString) {
  return parseDate(isoString).toLocaleString("en-GB", {
    day: "numeric",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  });
}
