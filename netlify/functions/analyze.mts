import type { Context, Config } from "@netlify/functions";
import { promises as dns } from "node:dns";
import net from "node:net";

// ---------- Config ----------
const FETCH_TIMEOUT_MS = 6000;
const MAX_REDIRECTS = 5;

const KNOWN_SHORTENERS = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
  "rebrand.ly", "cutt.ly", "shorte.st", "s.id", "rb.gy", "tiny.cc", "v.gd",
];

const SUSPICIOUS_TLDS = [
  "zip", "mov", "top", "xyz", "gq", "tk", "ml", "cf", "ga", "work", "click",
  "loan", "kim", "men", "review", "country", "science", "party",
];

const SENSITIVE_KEYWORDS = [
  "login", "verify", "secure", "account", "update", "confirm", "signin",
  "banking", "password", "unlock", "wallet", "gift", "invoice",
];

// A short list of frequently-impersonated brand/domain roots used only to
// flag look-alike spelling (e.g. "paypa1.com", "go0gle-mail.com").
const WATCHED_BRANDS = [
  "paypal", "google", "microsoft", "apple", "amazon", "netflix", "facebook",
  "instagram", "whatsapp", "bankofamerica", "chase", "wellsfargo", "steam",
  "outlook", "office365", "binance", "coinbase", "dhl", "fedex", "ups",
];

// ---------- Small helpers (no dependencies) ----------
function levenshtein(a: string, b: string): number {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) => [i, ...Array(n).fill(0)]);
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j - 1], dp[i][j - 1], dp[i - 1][j]);
    }
  }
  return dp[m][n];
}

function isPrivateOrReservedIp(ip: string): boolean {
  if (net.isIP(ip) === 4) {
    const [a, b] = ip.split(".").map(Number);
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 0) return true;
    return false;
  }
  if (net.isIP(ip) === 6) {
    const low = ip.toLowerCase();
    return low === "::1" || low.startsWith("fc") || low.startsWith("fd") ||
      low.startsWith("fe80");
  }
  return false;
}

function extractTag(html: string, re: RegExp): string | null {
  const m = html.match(re);
  return m ? m[1].trim().slice(0, 300) : null;
}

// ---------- Main handler ----------
export default async (req: Request, _context: Context) => {
  if (req.method !== "POST") {
    return new Response(JSON.stringify({ error: "POST only" }), { status: 405 });
  }

  const steps: { id: string; label: string; ok: boolean; detail?: string }[] = [];
  let body: { url?: string };
  try {
    body = await req.json();
  } catch {
    return new Response(JSON.stringify({ error: "invalid_json" }), { status: 400 });
  }

  const raw = (body.url || "").trim();
  if (!raw) {
    return new Response(JSON.stringify({ error: "missing_url" }), { status: 400 });
  }

  // --- Step 1: parse ---
  let target: URL;
  try {
    target = new URL(/^https?:\/\//i.test(raw) ? raw : `http://${raw}`);
  } catch {
    return new Response(JSON.stringify({ error: "invalid_url" }), { status: 400 });
  }
  steps.push({ id: "parse", label: "parse_url()", ok: true, detail: target.hostname });

  let score = 0; // 0 = clean, higher = riskier
  const flags: { severity: "info" | "warn" | "high"; message_ar: string; message_en: string }[] = [];

  // --- Structural heuristics ---
  const host = target.hostname.toLowerCase();
  const labels = host.split(".");
  const tld = labels[labels.length - 1];

  if (target.protocol !== "https:") {
    score += 15;
    flags.push({
      severity: "warn",
      message_ar: "الرابط لا يستخدم HTTPS، البيانات قد تُرسل بدون تشفير.",
      message_en: "Link does not use HTTPS — data may be sent unencrypted.",
    });
  }

  if (net.isIP(host)) {
    score += 25;
    flags.push({
      severity: "high",
      message_ar: "العنوان عبارة عن رقم IP مباشر بدل اسم نطاق، وهذا أسلوب شائع للتمويه.",
      message_en: "The address is a raw IP instead of a domain name — a common obfuscation trick.",
    });
  }

  if (host.startsWith("xn--") || host.includes(".xn--")) {
    score += 20;
    flags.push({
      severity: "high",
      message_ar: "النطاق مكتوب بترميز Punycode، قد يُستخدم لتقليد أحرف مألوفة.",
      message_en: "Domain uses Punycode encoding — can be used to mimic familiar characters.",
    });
  }

  if (raw.includes("@")) {
    score += 20;
    flags.push({
      severity: "high",
      message_ar: "الرابط يحتوي على رمز @ الذي يمكن استخدامه لإخفاء الوجهة الحقيقية.",
      message_en: "The URL contains an '@' symbol, which can hide the real destination.",
    });
  }

  if (labels.length > 4) {
    score += 10;
    flags.push({
      severity: "warn",
      message_ar: "عدد كبير من النطاقات الفرعية، أسلوب شائع لإخفاء النطاق الحقيقي.",
      message_en: "Unusually many subdomains — often used to disguise the real domain.",
    });
  }

  if ((host.match(/-/g) || []).length >= 3) {
    score += 8;
    flags.push({
      severity: "warn",
      message_ar: "عدد كبير من الشرطات في اسم النطاق.",
      message_en: "High number of hyphens in the domain name.",
    });
  }

  if (SUSPICIOUS_TLDS.includes(tld)) {
    score += 10;
    flags.push({
      severity: "warn",
      message_ar: `النطاق العلوي ".${tld}" يُستغل كثيرًا في حملات التصيّد.`,
      message_en: `The top-level domain ".${tld}" is frequently abused in phishing campaigns.`,
    });
  }

  if (KNOWN_SHORTENERS.includes(host)) {
    score += 12;
    flags.push({
      severity: "warn",
      message_ar: "هذا رابط مختصر، الوجهة النهائية غير معروفة قبل الفحص.",
      message_en: "This is a shortened link — the final destination is hidden until resolved.",
    });
  }

  const hasSensitiveKeyword = SENSITIVE_KEYWORDS.some((k) => host.includes(k) || target.pathname.toLowerCase().includes(k));
  if (hasSensitiveKeyword) {
    score += 6;
    flags.push({
      severity: "info",
      message_ar: "الرابط يحتوي كلمات حساسة مثل تسجيل الدخول أو التحقق.",
      message_en: "The link contains sensitive wording like login or verify.",
    });
  }

  const rootDomain = labels.length >= 2 ? labels[labels.length - 2] : host;
  let brandLookalike: string | null = null;
  for (const brand of WATCHED_BRANDS) {
    if (rootDomain === brand) { brandLookalike = null; break; }
    const dist = levenshtein(rootDomain, brand);
    if (dist > 0 && dist <= 2 && rootDomain.length >= brand.length - 2) {
      brandLookalike = brand;
      break;
    }
  }
  if (brandLookalike) {
    score += 30;
    flags.push({
      severity: "high",
      message_ar: `اسم النطاق "${rootDomain}" يشبه بشدة "${brandLookalike}" لكنه ليس مطابقًا — احتمال انتحال هوية.`,
      message_en: `The domain "${rootDomain}" closely resembles "${brandLookalike}" but does not match it — possible impersonation.`,
    });
  }
  steps.push({ id: "heuristics", label: "run_structural_checks()", ok: true, detail: `${flags.length} flags` });

  // --- Step: DNS resolution (real network call) ---
  let resolvedIps: string[] = [];
  let dnsOk = false;
  try {
    const records = await Promise.race([
      dns.lookup(host, { all: true, verbatim: false }),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("dns_timeout")), 4000)),
    ]);
    resolvedIps = records.map((r) => r.address);
    dnsOk = true;
    if (resolvedIps.some(isPrivateOrReservedIp)) {
      score += 40;
      flags.push({
        severity: "high",
        message_ar: "النطاق يشير إلى عنوان شبكة داخلي/محجوز، وهذا غير طبيعي لموقع عام.",
        message_en: "Domain resolves to a private/reserved network address — abnormal for a public site.",
      });
    }
  } catch {
    score += 20;
    flags.push({
      severity: "warn",
      message_ar: "تعذّر إيجاد النطاق عبر DNS، قد يكون غير موجود أو معطّل.",
      message_en: "DNS lookup failed — the domain may not exist or is offline.",
    });
  }
  steps.push({ id: "dns", label: "dns.lookup(hostname)", ok: dnsOk, detail: resolvedIps.join(", ") || "unresolved" });

  // --- Step: live HTTP fetch with manual redirect trace (real network call) ---
  let httpOk = false;
  let finalUrl = target.toString();
  let statusCode: number | null = null;
  let redirectChain: string[] = [];
  let title: string | null = null;
  let description: string | null = null;
  let favicon: string | null = null;
  let ogImage: string | null = null;
  let serverHeader: string | null = null;

  const blockedByDns = resolvedIps.some(isPrivateOrReservedIp);

  if (dnsOk && !blockedByDns) {
    let currentUrl = target.toString();
    for (let i = 0; i <= MAX_REDIRECTS; i++) {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
        const res = await fetch(currentUrl, {
          redirect: "manual",
          signal: controller.signal,
          headers: { "User-Agent": "Misbar-LinkProbe/1.0 (+security-scan)" },
        });
        clearTimeout(timer);
        statusCode = res.status;
        serverHeader = res.headers.get("server");

        if ([301, 302, 303, 307, 308].includes(res.status)) {
          const loc = res.headers.get("location");
          if (!loc) break;
          const next = new URL(loc, currentUrl).toString();
          redirectChain.push(next);
          currentUrl = next;
          continue;
        }

        finalUrl = currentUrl;
        httpOk = res.ok;
        if (res.ok) {
          const contentType = res.headers.get("content-type") || "";
          if (contentType.includes("text/html")) {
            const html = (await res.text()).slice(0, 200_000);
            title = extractTag(html, /<title[^>]*>([^<]*)<\/title>/i);
            description = extractTag(html, /<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)["']/i);
            ogImage = extractTag(html, /<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']*)["']/i);
            const iconHref = extractTag(html, /<link[^>]+rel=["'](?:shortcut icon|icon)["'][^>]+href=["']([^"']*)["']/i);
            favicon = iconHref ? new URL(iconHref, finalUrl).toString() : new URL("/favicon.ico", finalUrl).toString();
          }
        }
        break;
      } catch (err) {
        flags.push({
          severity: "warn",
          message_ar: "تعذّر الاتصال المباشر بالموقع (قد يكون بطيئًا أو يمنع الفحص الآلي).",
          message_en: "Could not connect to the site directly (it may be slow or block automated checks).",
        });
        break;
      }
    }

    if (redirectChain.length >= 3) {
      score += 12;
      flags.push({
        severity: "warn",
        message_ar: `الرابط مر بسلسلة من ${redirectChain.length} تحويلات قبل الوصول للوجهة النهائية.`,
        message_en: `The link passed through ${redirectChain.length} redirects before reaching its final destination.`,
      });
    }
    if (!httpOk && statusCode) {
      score += 5;
      flags.push({
        severity: "info",
        message_ar: `الخادم أعاد رمز الحالة ${statusCode}.`,
        message_en: `The server returned status code ${statusCode}.`,
      });
    }
  } else if (blockedByDns) {
    flags.push({
      severity: "info",
      message_ar: "تم تخطي الاتصال المباشر لأن النطاق يشير لعنوان شبكة داخلي.",
      message_en: "Live connection skipped because the domain resolves to an internal network address.",
    });
  }
  steps.push({ id: "fetch", label: "fetch(target, {redirect:'manual'})", ok: httpOk, detail: statusCode ? String(statusCode) : "no_response" });
  steps.push({ id: "parse_html", label: "extract_meta(title, description, favicon)", ok: !!title, detail: title || "n/a" });

  score = Math.max(0, Math.min(100, score));
  let verdict: "safe" | "caution" | "danger";
  if (score >= 45) verdict = "danger";
  else if (score >= 18) verdict = "caution";
  else verdict = "safe";

  const result = {
    input: raw,
    parsed: { protocol: target.protocol, hostname: host, path: target.pathname },
    finalUrl,
    redirectChain,
    statusCode,
    resolvedIps,
    serverHeader,
    metadata: { title, description, favicon, ogImage },
    score,
    verdict,
    flags,
    steps,
    scannedAt: new Date().toISOString(),
  };

  return new Response(JSON.stringify(result), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
};

export const config: Config = {
  path: "/api/analyze",
};
