/**
 * backend/script.js
 * ------------------
 * Caido Backend Plugin: "BugBounty AI Bridge"
 *
 * GÖREVİ:
 *   Caido proxy'sinden geçen HER istek/cevap çiftini yakalar (onInterceptResponse)
 *   ve bizim FastAPI Merkezi Omurga'mızın /ingest endpoint'ine POST eder.
 *
 * NEDEN onInterceptResponse (onInterceptRequest DEĞİL)?
 *   Sadece isteği değil, status_code ve response_size'ı da yakalamak istiyoruz.
 *   Bu bilgiler Local AI triyaj katmanında (Katman 3) "bu endpoint gerçekten
 *   ilginç mi?" kararında kritik rol oynayacak (örn. 200 dönen ama boş body'li
 *   cevaplar genelde IDOR false-positive'idir).
 *
 * ÖNEMLİ - SDK VERSİYON NOTU:
 *   Request/Response nesnesindeki getHeaders()/getBody() imzaları Caido SDK
 *   sürümüne göre küçük farklılıklar gösterebilir. Bu dosyayı kurarken
 *   Caido Devtools konsolunda `console.log(request)` ile mevcut sürümdeki
 *   gerçek metod isimlerini doğrula.
 */

import { Request as FetchRequest, fetch } from "caido:http";

// ---- YAPILANDIRMA -----------------------------------------------------
// FastAPI Merkezi Omurga'nın çalıştığı adres. Aynı makinede çalışıyorsa
// localhost yeterli; Telegram bot / AI ayrı bir makinedeyse burayı güncelle.
const INGEST_URL = "http://127.0.0.1:8000/ingest";

// Gürültüyü daha kaynakta azaltmak için: sadece bu host'lara (ve alt
// domain'lerine) ait trafiği ilet. Boş bırakılırsa HER ŞEY iletilir
// (tavsiye edilmez — kendi hesabına, CDN'lere vs. giden trafik de yakalanır).
const TARGET_HOSTS = [
  "whatnot.com",
  "api.whatnot.com",
  "live-service.whatnot.com",
  "auction-service.whatnot.com",
];
// -------------------------------------------------------------------------

/**
 * @param {string} host
 * @returns {boolean}
 */
function isInScope(host) {
  if (TARGET_HOSTS.length === 0) return true;
  return TARGET_HOSTS.some((allowed) => host === allowed || host.endsWith(`.${allowed}`));
}

/**
 * Header nesnesini (Map veya obje olabilir) düz bir JS objesine çevirir.
 * @param {any} rawHeaders
 * @returns {Record<string, string>}
 */
function normalizeHeaders(rawHeaders) {
  const result = {};
  try {
    if (!rawHeaders) return result;
    // Caido bazı sürümlerde headers'ı { key: string[] } olarak döndürür.
    for (const [key, value] of Object.entries(rawHeaders)) {
      result[key] = Array.isArray(value) ? value.join("; ") : String(value);
    }
  } catch (err) {
    // Header parse hatası tüm akışı durdurmasın.
    console.log(`[bugbounty-bridge] header normalize hatası: ${err}`);
  }
  return result;
}

/**
 * @param {import("caido:utils").Request} request
 * @param {import("caido:utils").Response} response
 * @param {import("caido:plugin").SDK} sdk
 */
async function forwardToIngest(request, response, sdk) {
  const host = request.getHost();

  if (!isInScope(host)) {
    return;
  }

  let bodyText = "";
  try {
    const rawBody = request.getBody ? request.getBody() : null;
    bodyText = rawBody ? sdk.asString(rawBody) : "";
  } catch (err) {
    console.log(`[bugbounty-bridge] body okunamadı (${host}): ${err}`);
  }

  let headers = {};
  try {
    headers = normalizeHeaders(request.getHeaders ? request.getHeaders() : {});
  } catch (err) {
    console.log(`[bugbounty-bridge] header okunamadı (${host}): ${err}`);
  }

  const payload = {
    method: request.getMethod(),
    url: typeof request.getUrl === "function"
      ? request.getUrl()
      : `https://${host}${request.getPath()}${request.getQuery() || ""}`,
    host,
    headers,
    body: bodyText,
    status_code: response ? response.getCode() : null,
    response_size: response && response.getBody ? (response.getBody()?.length ?? null) : null,
    source_program: null, // TODO: aktif Caido projesi adına göre otomatik doldurulabilir
  };

  try {
    const fetchReq = new FetchRequest(INGEST_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const res = await fetch(fetchReq);

    if (!res.ok) {
      console.log(`[bugbounty-bridge] ingest HTTP ${res.status}: ${host}${request.getPath()}`);
    }
  } catch (err) {
    // FastAPI kapalıysa (örn. henüz başlatılmadıysa) Caido'yu ASLA kilitlemesin.
    console.log(`[bugbounty-bridge] ingest'e ulaşılamadı (${host}): ${err}`);
  }
}

/** @param {import("caido:plugin").SDK} sdk */
export function init(sdk) {
  sdk.events.onInterceptResponse((sdk, request, response) => {
    // Async işlemi bilerek "fire and forget" yapıyoruz — proxy trafiğini
    // FastAPI'nin yanıt hızına bağımlı kılmamak için await ETMİYORUZ.
    forwardToIngest(request, response, sdk).catch((err) => {
      console.log(`[bugbounty-bridge] beklenmeyen hata: ${err}`);
    });
  });

  sdk.console.log("[bugbounty-bridge] plugin yüklendi, ingest hedefi: " + INGEST_URL);
}
