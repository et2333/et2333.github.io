import { sign } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const tokenUrl = "https://oauth2.googleapis.com/token";

export function createAssertion(credentials, now = new Date()) {
  if (credentials.type !== "service_account" || !credentials.client_email || !credentials.private_key) {
    throw new Error("GA4_SERVICE_ACCOUNT_JSON must contain a service-account key.");
  }
  const issued = Math.floor(now.getTime() / 1000);
  const encode = value => Buffer.from(JSON.stringify(value)).toString("base64url");
  const payload = `${encode({ alg: "RS256", typ: "JWT" })}.${encode({
    iss: credentials.client_email,
    scope: "https://www.googleapis.com/auth/analytics.readonly",
    aud: tokenUrl,
    iat: issued,
    exp: issued + 3600,
  })}`;
  return `${payload}.${sign("RSA-SHA256", Buffer.from(payload), credentials.private_key).toString("base64url")}`;
}

function validDate(value) {
  return typeof value === "string" && /^\d{4}-\d{2}-\d{2}$/.test(value)
    && Number.isFinite(Date.parse(`${value}T00:00:00Z`))
    && new Date(`${value}T00:00:00Z`).toISOString().slice(0, 10) === value;
}

function dateInZone(now, timeZone) {
  const parts = Object.fromEntries(new Intl.DateTimeFormat("en-US", {
    timeZone, year: "numeric", month: "2-digit", day: "2-digit",
  }).formatToParts(now).map(part => [part.type, part.value]));
  return `${parts.year}-${parts.month}-${parts.day}`;
}

export function buildSummary(report, startedAt, now = new Date()) {
  const today = dateInZone(now, report.metadata?.timeZone || "Asia/Shanghai");
  const throughDate = new Date(Date.parse(`${today}T00:00:00Z`) - 86400000).toISOString().slice(0, 10);
  if (!validDate(startedAt) || startedAt > throughDate) {
    throw new Error("GA4_START_DATE must be a valid date no later than yesterday.");
  }
  if (report.rows?.length > 1) throw new Error("Expected one aggregate row, not daily user counts.");
  const metric = name => {
    const index = report.metricHeaders?.findIndex(header => header.name === name);
    if (index === undefined || index < 0) throw new Error(`Missing metric: ${name}`);
    const value = report.rows?.[0]?.metricValues?.[index]?.value ?? (report.rows?.length ? undefined : "0");
    if (typeof value !== "string" || !/^\d+$/.test(value) || !Number.isSafeInteger(Number(value))) {
      throw new Error(`Invalid metric: ${name}`);
    }
    return Number(value);
  };
  return {
    schemaVersion: 1,
    status: "ready",
    visitors: metric("totalUsers"),
    pageViews: metric("screenPageViews"),
    startedAt,
    throughDate,
    updatedAt: now.toISOString(),
    source: "GA4",
  };
}

export async function fetchSummary({ credentials, propertyId, startedAt, hostname }, fetchImpl = fetch) {
  if (!/^\d+$/.test(propertyId || "")) throw new Error("Set GA4_PROPERTY_ID to the numeric property ID, not the stream or measurement ID.");
  if (!validDate(startedAt)) throw new Error("Set GA4_START_DATE to the tracking start date (YYYY-MM-DD).");
  if (!hostname || !/^[a-z0-9.-]+$/i.test(hostname)) throw new Error("Set GA4_HOSTNAME to the public website hostname.");

  const tokenResponse = await fetchImpl(tokenUrl, {
    method: "POST",
    signal: AbortSignal.timeout(30000),
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: createAssertion(credentials),
    }),
  });
  if (!tokenResponse.ok) throw new Error(`Google authentication failed (HTTP ${tokenResponse.status}). Check the service-account key.`);
  const token = await tokenResponse.json();
  if (typeof token.access_token !== "string" || !token.access_token) throw new Error("Google did not return an access token.");
  const response = await fetchImpl(`https://analyticsdata.googleapis.com/v1beta/properties/${propertyId}:runReport`, {
    method: "POST",
    signal: AbortSignal.timeout(30000),
    headers: { Authorization: `Bearer ${token.access_token}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      dateRanges: [{ startDate: startedAt, endDate: "yesterday" }],
      metrics: [{ name: "totalUsers" }, { name: "screenPageViews" }],
      dimensionFilter: { filter: { fieldName: "hostName", stringFilter: { matchType: "EXACT", value: hostname } } },
      keepEmptyRows: false,
    }),
  });
  if (!response.ok) throw new Error(`GA4 report failed (HTTP ${response.status}). Check Data API activation, property ID and Viewer access.`);
  return buildSummary(await response.json(), startedAt);
}

async function main() {
  let credentials;
  try { credentials = JSON.parse(process.env.GA4_SERVICE_ACCOUNT_JSON || ""); }
  catch { throw new Error("Set GA4_SERVICE_ACCOUNT_JSON in GitHub Actions Secrets."); }
  const summary = await fetchSummary({
    credentials,
    propertyId: process.env.GA4_PROPERTY_ID,
    startedAt: process.env.GA4_START_DATE,
    hostname: process.env.GA4_HOSTNAME || "et2333.github.io",
  });
  const output = resolve(process.env.VISIT_SUMMARY_OUTPUT || "tmp/analytics-summary.json");
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${JSON.stringify(summary, null, 2)}\n`);
  console.log("GA4 public summary generated successfully.");
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}
