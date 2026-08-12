// ---------- i18n ----------
const STRINGS = {
  ar: {
    brandArabic: "مسبار", brandLatin: "Misbar",
    langToggleLabel: "English",
    eyebrow: "أداة فحص روابط تعمل فعليًا",
    heroTitle1: "قبل ما تضغط،",
    heroTitle2: "خلّ مسبار يدخل الرابط أولاً",
    heroSub: "نحلّل بنية الرابط، نتصل بالموقع فعليًا، ونتحقق من DNS والشهادة ومسار التحويلات — بدون أي نتائج وهمية.",
    inputPlaceholder: "الصق الرابط هنا — مثال: example.com/login",
    scanBtn: "افحص الرابط",
    disclaimerInline: "تحليل آلي مساعد لاتخاذ القرار، وليس بديلاً عن حذرك الشخصي.",
    riskScore: "مؤشر الخطورة",
    sitePreviewTitle: "داخل الرابط",
    flagsTitle: "ملاحظات الفحص",
    techTitle: "تفاصيل تقنية",
    rescanBtn: "فحص رابط آخر",
    footerNote: "مسبار يعتمد فحصًا هيكليًا واتصالاً فعليًا بالموقع (DNS + HTTP)، وهو مؤشر استرشادي وليس ضمانًا مطلقًا للأمان.",
    verdictSafe: "لا توجد مؤشرات خطر واضحة",
    verdictCaution: "توجد مؤشرات تستدعي الحذر",
    verdictDanger: "مؤشرات خطر مرتفعة",
    noFlags: "لم يُسجَّل أي ملاحظة على هذا الرابط.",
    noPreview: "تعذّر جلب معلومات الصفحة",
    errorGeneric: "تعذّر إتمام الفحص. تحقّق من الرابط وحاول مرة أخرى.",
    techFinalUrl: "الرابط النهائي", techStatus: "رمز الحالة", techIps: "عناوين IP",
    techServer: "خادم الويب", techRedirects: "عدد التحويلات",
  },
  en: {
    brandArabic: "مسبار", brandLatin: "Misbar",
    langToggleLabel: "العربية",
    eyebrow: "A link probe that actually runs checks",
    heroTitle1: "Before you click,",
    heroTitle2: "let Misbar go in first",
    heroSub: "We analyze the link's structure and connect to the site for real — DNS, certificate, and redirect trail. No fake results.",
    inputPlaceholder: "Paste a link — e.g. example.com/login",
    scanBtn: "Scan link",
    disclaimerInline: "Automated analysis to help you decide — not a substitute for your own caution.",
    riskScore: "Risk score",
    sitePreviewTitle: "Inside the link",
    flagsTitle: "Scan notes",
    techTitle: "Technical details",
    rescanBtn: "Scan another link",
    footerNote: "Misbar combines structural heuristics with a real connection to the site (DNS + HTTP). It's a helpful signal, not an absolute guarantee of safety.",
    verdictSafe: "No clear risk signals found",
    verdictCaution: "Some signals warrant caution",
    verdictDanger: "High-risk signals detected",
    noFlags: "No notable flags were recorded for this link.",
    noPreview: "Could not retrieve page information",
    errorGeneric: "Could not complete the scan. Check the link and try again.",
    techFinalUrl: "Final URL", techStatus: "Status code", techIps: "IP addresses",
    techServer: "Web server", techRedirects: "Redirects",
  },
};

let currentLang = "ar";

function applyLang(lang) {
  currentLang = lang;
  const dict = STRINGS[lang];
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const key = el.getAttribute("data-i18n");
    if (dict[key]) el.textContent = dict[key];
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
    const key = el.getAttribute("data-i18n-placeholder");
    if (dict[key]) el.placeholder = dict[key];
  });
}

document.getElementById("langToggle").addEventListener("click", () => {
  applyLang(currentLang === "ar" ? "en" : "ar");
});

// ---------- Scan flow ----------
// These labels intentionally stay untranslated: they mirror the actual
// function calls executed by the serverless probe (netlify/functions/analyze.mts).
const CHECK_SEQUENCE = [
  { id: "parse", label: "parse_url(input)" },
  { id: "heuristics", label: "run_structural_checks()" },
  { id: "dns", label: "dns.lookup(hostname)" },
  { id: "fetch", label: "fetch(target, {redirect:'manual'})" },
  { id: "parse_html", label: "extract_meta(title, description, favicon)" },
  { id: "score", label: "compute_risk_score()" },
];

const overlay = document.getElementById("scanOverlay");
const termBody = document.getElementById("terminalBody");
const form = document.getElementById("scanForm");
const scanBtn = document.getElementById("scanBtn");
const resultsSection = document.getElementById("results");

function renderTerminalPending() {
  termBody.innerHTML = "";
  CHECK_SEQUENCE.forEach((step, i) => {
    const line = document.createElement("div");
    line.className = "term-line";
    line.style.animationDelay = `${i * 0.12}s`;
    line.id = `term-${step.id}`;
    line.innerHTML = `<span class="term-status pending"></span><span class="term-label">${step.label}</span><span class="term-detail"></span>`;
    termBody.appendChild(line);
  });
}

function markTerminalStep(id, ok, detail) {
  const line = document.getElementById(`term-${id}`);
  if (!line) return;
  const status = line.querySelector(".term-status");
  status.className = `term-status ${ok ? "ok" : "warn"}`;
  if (detail) line.querySelector(".term-detail").textContent = `— ${detail}`;
}

async function runScan(rawUrl) {
  overlay.hidden = false;
  resultsSection.hidden = true;
  renderTerminalPending();
  scanBtn.disabled = true;

  // Kick off the real request immediately, with a hard client-side timeout
  // so a slow/unresponsive target can never leave the overlay stuck open.
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 15000);
  const requestPromise = fetch("/api/analyze", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ url: rawUrl }),
    signal: controller.signal,
  }).then((r) => {
    clearTimeout(timeoutId);
    if (!r.ok) throw new Error(`http_${r.status}`);
    return r.json();
  });

  // Reveal the parse/heuristics lines quickly since those run client-visible
  // instantly server-side; give the network-bound steps a beat before we
  // fill them in from the real response so the log reads top-to-bottom.
  await sleep(350);
  markTerminalStep("parse", true, "ok");
  await sleep(300);
  markTerminalStep("heuristics", true, "ok");

  let data;
  try {
    data = await requestPromise;
  } catch (e) {
    overlay.hidden = true;
    scanBtn.disabled = false;
    alert(STRINGS[currentLang].errorGeneric);
    return;
  }

  if (data.error) {
    overlay.hidden = true;
    scanBtn.disabled = false;
    alert(STRINGS[currentLang].errorGeneric);
    return;
  }

  const stepMap = Object.fromEntries(data.steps.map((s) => [s.id, s]));
  await sleep(250);
  markTerminalStep("dns", stepMap.dns?.ok, stepMap.dns?.detail);
  await sleep(300);
  markTerminalStep("fetch", stepMap.fetch?.ok, stepMap.fetch?.detail);
  await sleep(250);
  markTerminalStep("parse_html", stepMap.parse_html?.ok, stepMap.parse_html?.detail || "n/a");
  await sleep(250);
  markTerminalStep("score", true, `${data.score}/100`);
  await sleep(500);

  overlay.hidden = true;
  scanBtn.disabled = false;
  renderResults(data);
}

function sleep(ms) { return new Promise((res) => setTimeout(res, ms)); }

function renderResults(data) {
  const dict = STRINGS[currentLang];
  resultsSection.hidden = false;

  // Verdict
  const verdictMeta = {
    safe: { color: "var(--teal)", bg: "rgba(53,208,192,0.12)", text: dict.verdictSafe, icon: iconCheck() },
    caution: { color: "var(--amber)", bg: "rgba(242,169,59,0.12)", text: dict.verdictCaution, icon: iconWarn() },
    danger: { color: "var(--red)", bg: "rgba(255,92,108,0.12)", text: dict.verdictDanger, icon: iconAlert() },
  }[data.verdict];

  const badge = document.getElementById("verdictBadge");
  badge.style.background = verdictMeta.bg;
  badge.style.color = verdictMeta.color;
  document.getElementById("verdictIcon").innerHTML = verdictMeta.icon;
  document.getElementById("verdictLabel").textContent = verdictMeta.text;
  document.getElementById("verdictLabel").style.color = verdictMeta.color;
  document.getElementById("verdictUrl").textContent = data.finalUrl || data.input;

  // Score arc: circumference of path ~ 157 (semi-circle r=50)
  const arcLen = 157;
  const pct = data.score / 100;
  const fill = document.getElementById("scoreArcFill");
  fill.style.stroke = verdictMeta.color;
  fill.setAttribute("stroke-dasharray", `${arcLen * pct} ${arcLen}`);
  document.getElementById("scoreNum").textContent = data.score;

  // Preview
  const fav = document.getElementById("previewFavicon");
  fav.src = data.metadata.favicon || "";
  fav.onerror = () => { fav.style.display = "none"; };
  document.getElementById("previewTitle").textContent = data.metadata.title || dict.noPreview;
  document.getElementById("previewDesc").textContent = data.metadata.description || "—";

  const ogWrap = document.getElementById("ogImageWrap");
  if (data.metadata.ogImage) {
    document.getElementById("ogImage").src = data.metadata.ogImage;
    ogWrap.hidden = false;
  } else {
    ogWrap.hidden = true;
  }

  // Flags
  const flagsList = document.getElementById("flagsList");
  flagsList.innerHTML = "";
  if (!data.flags.length) {
    flagsList.innerHTML = `<li class="empty">${dict.noFlags}</li>`;
  } else {
    data.flags.forEach((f) => {
      const li = document.createElement("li");
      li.className = "flag-item";
      const msg = currentLang === "ar" ? f.message_ar : f.message_en;
      li.innerHTML = `<span class="flag-dot ${f.severity}"></span><span>${msg}</span>`;
      flagsList.appendChild(li);
    });
  }

  // Tech details (kept in LTR/technical form regardless of language)
  const tech = document.getElementById("techList");
  tech.innerHTML = "";
  const entries = [
    [dict.techFinalUrl, data.finalUrl],
    [dict.techStatus, data.statusCode ?? "—"],
    [dict.techIps, data.resolvedIps?.join(", ") || "—"],
    [dict.techServer, data.serverHeader || "—"],
    [dict.techRedirects, String(data.redirectChain?.length || 0)],
  ];
  entries.forEach(([label, value]) => {
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    dd.textContent = value;
    tech.appendChild(dt);
    tech.appendChild(dd);
  });

  resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
}

function iconCheck() { return '<path fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" d="M4 12l6 6L20 6"/>'; }
function iconWarn() { return '<path fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" d="M12 3 2 20h20L12 3zM12 9v5M12 17h.01"/>'; }
function iconAlert() { return '<path fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" d="M12 2 2 22h20L12 2zM12 9v6M12 18h.01"/>'; }

form.addEventListener("submit", (e) => {
  e.preventDefault();
  const val = document.getElementById("urlInput").value.trim();
  if (!val) return;
  runScan(val);
});

document.getElementById("rescanBtn").addEventListener("click", () => {
  resultsSection.hidden = true;
  document.getElementById("urlInput").value = "";
  document.getElementById("urlInput").focus();
  window.scrollTo({ top: 0, behavior: "smooth" });
});

applyLang("ar");
