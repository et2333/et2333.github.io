import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, verify } from "node:crypto";
import { buildSummary, createAssertion, fetchSummary } from "./update-visit-summary.mjs";

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const credentials = { type: "service_account", client_email: "test@example.invalid", private_key: privateKey };
const now = new Date("2026-10-16T04:23:00Z");
const report = {
  metricHeaders: [{ name: "screenPageViews" }, { name: "totalUsers" }],
  rows: [{ metricValues: [{ value: "356" }, { value: "128" }] }],
  metadata: { timeZone: "Asia/Shanghai" },
};

test("service-account assertion is signed and limited to read-only Analytics", () => {
  const [header, payload, signature] = createAssertion(credentials, now).split(".");
  assert.ok(verify("RSA-SHA256", Buffer.from(`${header}.${payload}`), publicKey, Buffer.from(signature, "base64url")));
  const claims = JSON.parse(Buffer.from(payload, "base64url"));
  assert.equal(claims.scope, "https://www.googleapis.com/auth/analytics.readonly");
  assert.equal(claims.exp - claims.iat, 3600);
  assert.equal(claims.aud, "https://oauth2.googleapis.com/token");
});

test("maps aggregate metrics by name, with the reporting property's date boundary", () => {
  const summary = buildSummary(report, "2026-10-14", now);
  assert.equal(summary.visitors, 128);
  assert.equal(summary.pageViews, 356);
  assert.equal(summary.throughDate, "2026-10-15");
  const localMidnight = buildSummary(report, "2026-10-14", new Date("2026-10-15T18:00:00Z"));
  assert.equal(localMidnight.throughDate, "2026-10-15");
  assert.deepEqual(Object.keys(summary).sort(), ["schemaVersion", "status", "visitors", "pageViews", "startedAt", "throughDate", "updatedAt", "source"].sort());
});

test("zero data is valid, but malformed or daily rows are never published", () => {
  assert.equal(buildSummary({ ...report, rows: [] }, "2026-10-14", now).visitors, 0);
  assert.throws(() => buildSummary({ ...report, rows: [...report.rows, ...report.rows] }, "2026-10-14", now));
  assert.throws(() => buildSummary({ ...report, rows: [{ metricValues: [{ value: "NaN" }, { value: "128" }] }] }, "2026-10-14", now));
  assert.throws(() => buildSummary(report, "2026-99-99", now));
  assert.throws(() => buildSummary(report, "2026-10-17", now));
});

test("requests full-range, hostname-filtered totals without breaking users into days", async () => {
  let requests = 0;
  const fetchImpl = async (url, options) => {
    requests++;
    if (url.includes("oauth2")) return Response.json({ access_token: "test-token" });
    assert.equal(url, "https://analyticsdata.googleapis.com/v1beta/properties/123:runReport");
    assert.equal(options.headers.Authorization, "Bearer test-token");
    const body = JSON.parse(options.body);
    assert.equal(body.dateRanges[0].endDate, "yesterday");
    assert.equal(body.dimensionFilter.filter.stringFilter.value, "et2333.github.io");
    assert.equal(body.dimensions, undefined);
    return Response.json(report);
  };
  const summary = await fetchSummary({ credentials, propertyId: "123", startedAt: "2020-01-01", hostname: "et2333.github.io" }, fetchImpl);
  assert.equal(requests, 2);
  assert.equal(summary.visitors, 128);
});

test("HTTP failures stop generation instead of replacing valid totals with zero", async () => {
  const config = { credentials, propertyId: "123", startedAt: "2020-01-01", hostname: "et2333.github.io" };
  await assert.rejects(fetchSummary(config, async () => new Response("private details", { status: 403 })), /authentication failed/);
  await assert.rejects(fetchSummary(config, async url => url.includes("oauth2")
    ? Response.json({ access_token: "test-token" })
    : new Response("private details", { status: 403 })), /report failed/);
});
