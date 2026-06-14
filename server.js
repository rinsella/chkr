import express from 'express';
import { config, originBase } from './src/config.js';
import {
  rewriteHtml,
  rewriteText,
  isRewritableText,
  isHtml,
} from './src/rewrite.js';

const app = express();
app.disable('x-powered-by');

// Cache in-memory sederhana untuk static asset (kurangi hit ke origin -> hindari 429).
const assetCache = new Map(); // key -> { status, headers, body, expires }
const ASSET_TTL_MS = 1000 * 60 * 10; // 10 menit
const ASSET_CACHE_MAX = 500;

function cacheableAssetPath(path) {
  return /\.(css|js|mjs|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|eot|map|json|mp4|webm|avif)(\?|$)/i.test(
    path
  );
}

function getCache(key) {
  const hit = assetCache.get(key);
  if (!hit) return null;
  if (Date.now() > hit.expires) {
    assetCache.delete(key);
    return null;
  }
  return hit;
}

function setCache(key, value) {
  if (assetCache.size >= ASSET_CACHE_MAX) {
    // Buang entri terlama.
    const firstKey = assetCache.keys().next().value;
    assetCache.delete(firstKey);
  }
  assetCache.set(key, { ...value, expires: Date.now() + ASSET_TTL_MS });
}

// Header response dari origin yang tidak boleh diteruskan apa adanya.
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'content-encoding', // undici sudah men-decode body; jangan teruskan.
  'content-length', // akan dihitung ulang.
  'content-security-policy', // agar script injeksi & resource mirror tidak diblok.
  'content-security-policy-report-only',
  'strict-transport-security',
  'public-key-pins',
  'report-to',
  'nel',
]);

// Tentukan host & protokol mirror dari env atau dari request.
function mirrorContext(req) {
  let mirrorHost;
  let mirrorProtocol;
  if (config.publicUrl) {
    const u = new URL(config.publicUrl);
    mirrorHost = u.host;
    mirrorProtocol = u.protocol.replace(':', '');
  } else {
    mirrorHost = req.headers['x-forwarded-host'] || req.headers.host;
    mirrorProtocol =
      (req.headers['x-forwarded-proto'] || '').split(',')[0].trim() ||
      (req.secure ? 'https' : 'http');
  }
  const canonicalUrl = `${mirrorProtocol}://${mirrorHost}${req.originalUrl.split('?')[0]}`;
  return {
    originHost: config.originHost,
    mirrorHost,
    mirrorProtocol,
    canonicalUrl,
  };
}

// Bangun headers untuk request ke origin.
function buildOriginHeaders(req, ctx) {
  const headers = {};
  for (const [key, value] of Object.entries(req.headers)) {
    const k = key.toLowerCase();
    // Header yang tidak boleh diteruskan / akan kita set ulang.
    if (
      [
        'host',
        'connection',
        'content-length',
        'x-forwarded-host',
        'x-forwarded-proto',
        'x-forwarded-for',
        'forwarded',
        'cf-connecting-ip',
        'cf-ipcountry',
        'cf-ray',
        'cf-visitor',
        'x-real-ip',
      ].includes(k)
    ) {
      continue;
    }
    // Tukar referer/origin agar menunjuk ke origin asli (banyak API memvalidasi ini).
    if (k === 'referer' || k === 'origin') {
      headers[key] = String(value).replaceAll(ctx.mirrorHost, config.originHost);
      continue;
    }
    headers[key] = value;
  }
  headers['host'] = config.originHost;
  // Pastikan API yang butuh konteks browser tidak menolak request.
  if (!headers['user-agent'] && !headers['User-Agent']) {
    headers['user-agent'] =
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36';
  }
  if (!headers['accept'] && !headers['Accept']) {
    headers['accept'] = '*/*';
  }
  headers['accept-encoding'] = 'gzip, deflate, br';
  return headers;
}

// Tulis-ulang header Set-Cookie agar cookie/sesi tersimpan di domain mirror.
// - Domain=hchk.cards -> dibuang (cookie otomatis berlaku untuk host saat ini).
// - SameSite=None tetap, tapi pastikan Secure ada bila mirror https.
function rewriteSetCookie(cookieStr, ctx) {
  let out = cookieStr
    // Buang atribut Domain agar cookie melekat ke domain mirror.
    .replace(/;\s*Domain=[^;]*/gi, '')
    // Ganti sisa referensi host origin di value cookie (jarang, tapi aman).
    .replaceAll(config.originHost, ctx.mirrorHost);

  if (ctx.mirrorProtocol === 'https') {
    if (/SameSite=None/i.test(out) && !/;\s*Secure/i.test(out)) {
      out += '; Secure';
    }
  } else {
    // Di http, cookie Secure tidak akan tersimpan -> buang flag Secure.
    out = out.replace(/;\s*Secure/gi, '');
  }
  return out;
}

// Tulis-ulang header Location & Link agar menunjuk ke domain mirror.
function rewriteHeaderValue(value, ctx) {
  return value
    .replaceAll(
      `${config.originProtocol}://${config.originHost}`,
      `${ctx.mirrorProtocol}://${ctx.mirrorHost}`
    )
    .replaceAll(`//${config.originHost}`, `//${ctx.mirrorHost}`)
    .replaceAll(config.originHost, ctx.mirrorHost);
}

// Fetch ke origin dengan retry & backoff saat origin membatasi (429/503).
async function fetchWithRetry(url, init, maxRetries = 3) {
  let attempt = 0;
  let lastRes;
  while (attempt <= maxRetries) {
    const res = await fetch(url, init);
    if (res.status !== 429 && res.status !== 503) return res;
    lastRes = res;
    if (attempt === maxRetries) break;
    // Hormati Retry-After bila ada, jika tidak pakai backoff eksponensial.
    const retryAfter = Number(res.headers.get('retry-after'));
    const waitMs =
      Number.isFinite(retryAfter) && retryAfter > 0
        ? Math.min(retryAfter * 1000, 5000)
        : 300 * Math.pow(2, attempt);
    try {
      await res.arrayBuffer(); // bebaskan koneksi sebelum retry.
    } catch {
      /* ignore */
    }
    await new Promise((r) => setTimeout(r, waitMs));
    attempt += 1;
  }
  return lastRes;
}

// Ambil teks dari origin (dipakai handler robots/sitemap).
async function fetchOriginText(path, req, ctx) {
  const res = await fetch(`${originBase()}${path}`, {
    method: 'GET',
    headers: buildOriginHeaders(req, ctx),
    redirect: 'follow',
  });
  return { status: res.status, text: await res.text() };
}

// robots.txt: proxy origin, lalu pastikan baris Sitemap menunjuk ke mirror.
app.get('/robots.txt', async (req, res) => {
  const ctx = mirrorContext(req);
  const base = `${ctx.mirrorProtocol}://${ctx.mirrorHost}`;
  try {
    const { status, text } = await fetchOriginText('/robots.txt', req, ctx);
    let body = status >= 200 && status < 300 && text.trim()
      ? rewriteText(text, ctx)
      : 'User-agent: *\nAllow: /\n';
    if (!/^sitemap:/im.test(body)) {
      body = body.trimEnd() + `\nSitemap: ${base}/sitemap.xml\n`;
    }
    res.type('text/plain').send(body);
  } catch {
    res
      .type('text/plain')
      .send(`User-agent: *\nAllow: /\nSitemap: ${base}/sitemap.xml\n`);
  }
});

// sitemap.xml: proxy origin & rewrite; fallback minimal bila origin tidak punya.
app.get(['/sitemap.xml', '/sitemap_index.xml'], async (req, res) => {
  const ctx = mirrorContext(req);
  const base = `${ctx.mirrorProtocol}://${ctx.mirrorHost}`;
  try {
    const { status, text } = await fetchOriginText(req.path, req, ctx);
    if (status >= 200 && status < 300 && text.includes('<')) {
      res.type('application/xml').send(rewriteText(text, ctx));
      return;
    }
  } catch {
    /* fallback di bawah */
  }
  const now = new Date().toISOString();
  res.type('application/xml').send(
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n` +
      `  <url><loc>${base}/</loc><lastmod>${now}</lastmod><changefreq>daily</changefreq><priority>1.0</priority></url>\n` +
      `</urlset>\n`
  );
});

app.use(async (req, res) => {
  const ctx = mirrorContext(req);
  const targetUrl = `${originBase()}${req.originalUrl}`;

  // Layani static asset dari cache bila tersedia (kurangi beban ke origin).
  const isCacheableAsset =
    req.method === 'GET' && cacheableAssetPath(req.originalUrl);
  if (isCacheableAsset) {
    const cached = getCache(targetUrl);
    if (cached) {
      res.status(cached.status);
      for (const [k, v] of Object.entries(cached.headers)) res.setHeader(k, v);
      res.setHeader('x-mirror-cache', 'HIT');
      res.end(cached.body);
      return;
    }
  }

  try {
    const reqHeaders = buildOriginHeaders(req, ctx);

    const init = {
      method: req.method,
      headers: reqHeaders,
      redirect: 'manual', // tangani redirect manual agar bisa di-rewrite.
    };

    if (!['GET', 'HEAD'].includes(req.method)) {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      if (chunks.length) init.body = Buffer.concat(chunks);
    }

    const originRes = await fetchWithRetry(targetUrl, init);

    // Salin header (kecuali hop-by-hop), rewrite Location/Link & Set-Cookie.
    const outHeaders = {};
    originRes.headers.forEach((value, key) => {
      const k = key.toLowerCase();
      if (HOP_BY_HOP.has(k)) return;
      if (k === 'set-cookie') return; // ditangani khusus di bawah.
      if (config.forceIndexable && k === 'x-robots-tag') return; // buang noindex.
      if (k === 'location' || k === 'link') {
        outHeaders[key] = rewriteHeaderValue(value, ctx);
        return;
      }
      outHeaders[key] = value;
    });
    for (const [k, v] of Object.entries(outHeaders)) res.setHeader(k, v);

    // Set-Cookie: ambil semua cookie (jangan tergabung), rewrite domain agar sesi jalan.
    const setCookies =
      typeof originRes.headers.getSetCookie === 'function'
        ? originRes.headers.getSetCookie()
        : [];
    if (setCookies.length) {
      res.setHeader(
        'set-cookie',
        setCookies.map((c) => rewriteSetCookie(c, ctx))
      );
    }

    res.status(originRes.status);

    const contentType = originRes.headers.get('content-type') || '';
    let bodyBuf;

    if (isRewritableText(contentType)) {
      const text = await originRes.text();
      const body = isHtml(contentType)
        ? rewriteHtml(text, ctx)
        : rewriteText(text, ctx);
      bodyBuf = Buffer.from(body);
    } else {
      bodyBuf = Buffer.from(await originRes.arrayBuffer());
    }

    res.setHeader('content-length', bodyBuf.length);

    // Simpan asset (teks ter-rewrite maupun biner) ke cache bila sukses & bukan HTML.
    if (isCacheableAsset && originRes.status === 200 && !isHtml(contentType)) {
      setCache(targetUrl, {
        status: 200,
        headers: { ...outHeaders, 'content-length': bodyBuf.length },
        body: bodyBuf,
      });
    }

    res.end(bodyBuf);
  } catch (err) {
    console.error(`[mirror] ${req.method} ${targetUrl} ->`, err.message);
    res.status(502).type('text/plain').send('Mirror upstream error.');
  }
});

app.listen(config.port, () => {
  console.log(
    `Mirror aktif di port ${config.port} -> origin ${originBase()}` +
      (config.publicUrl ? ` (public: ${config.publicUrl})` : '')
  );
});
