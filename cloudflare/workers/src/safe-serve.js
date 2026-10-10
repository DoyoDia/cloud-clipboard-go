// 「安全地吐出用户上传字节」的统一规则 —— 与 Go 端 serveUploadedFile（cloud-clip/lib/handler.go）
// 一一对应，两边保持一致。
//
// ⚠️ 用户上传的字节不可信：若按上传文件名（或上传时声明的 Content-Type）推出
// text/html、application/xhtml+xml、image/svg+xml 或 JS 这类类型再 inline，浏览器会在
// **本站可信源**里把它当页面/脚本执行 —— 这就是存储型 XSS。
// 所以服务端**绝不**相信上传侧给的类型，只认下面这张「内联也不会执行脚本」的白名单，
// 不在表里的一律 application/octet-stream + attachment；并统一加 nosniff + 最严 CSP。

const SAFE_INLINE_CONTENT_TYPES = new Set([
  'image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/bmp',
  'image/x-icon', 'image/vnd.microsoft.icon',
  'text/plain',
  'audio/mpeg', 'audio/ogg', 'audio/wav', 'audio/x-wav', 'audio/webm',
  'video/mp4', 'video/webm', 'video/ogg',
  'application/pdf',
]);

// 只映射白名单里的扩展名；其余（含 html/htm/svg/xml/js/mjs/csv/md/json…）一律落到
// application/octet-stream，也就是「不内联、当附件下载」。
const EXT_CONTENT_TYPE = {
  png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif',
  webp: 'image/webp', bmp: 'image/bmp', ico: 'image/x-icon',
  txt: 'text/plain',
  mp3: 'audio/mpeg', ogg: 'audio/ogg', oga: 'audio/ogg', wav: 'audio/wav', weba: 'audio/webm',
  mp4: 'video/mp4', m4v: 'video/mp4', webm: 'video/webm', ogv: 'video/ogg',
  pdf: 'application/pdf',
};

export function safeContentTypeForName(filename = '') {
  const ext = String(filename || '').split('.').pop()?.toLowerCase() || '';
  const ct = EXT_CONTENT_TYPE[ext];
  if (ct && SAFE_INLINE_CONTENT_TYPES.has(ct)) {
    return { contentType: ct, inlineAllowed: true };
  }
  return { contentType: 'application/octet-stream', inlineAllowed: false };
}

function toSafeAsciiFilename(filename = '') {
  const normalized = String(filename || '')
    .replace(/[\r\n]/g, ' ')
    .replace(/["\\]/g, '_')
    .replace(/[^\x20-\x7E]/g, '_')
    .trim();
  return normalized || 'file';
}

function buildContentDisposition(filename, disposition) {
  const safeFallback = toSafeAsciiFilename(filename);
  const encodedFilename = encodeURIComponent(String(filename || safeFallback));
  return `${disposition}; filename="${safeFallback}"; filename*=UTF-8''${encodedFilename}`;
}

// safeFileHeaders 返回一份可以直接铺进 Response headers 的对象：安全的 Content-Type、
// inline/attachment 的 Content-Disposition，以及 nosniff + CSP。
export function safeFileHeaders(filename = '', { forceDownload = false } = {}) {
  const { contentType, inlineAllowed } = safeContentTypeForName(filename);
  const disposition = inlineAllowed && !forceDownload ? 'inline' : 'attachment';
  return {
    'Content-Type': contentType,
    'Content-Disposition': buildContentDisposition(filename, disposition),
    // 禁止浏览器无视我们给的类型去「嗅探」成 text/html 再执行。
    'X-Content-Type-Options': 'nosniff',
    // 即便某类型被内联，也用最严的 CSP + sandbox 把它和本站源完全隔开。
    'Content-Security-Policy': "default-src 'none'; sandbox",
  };
}
