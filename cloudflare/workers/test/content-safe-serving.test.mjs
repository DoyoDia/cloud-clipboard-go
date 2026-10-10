// 存储型 XSS 回归（Worker 侧，与 Go 的 TestUploadedFilesNotServedAsRenderableInline 同一份契约）。
//
// 上传的字节不可信：服务端**绝不**按上传文件名/上传时声明的 Content-Type 把它当
// text/html / image/svg+xml 之类内联渲染 —— 否则 .html/.svg 一传，受害者访问
// /file/<uuid>/<name> 或 /content/<id> 就会在本站可信源里执行脚本。
// 覆盖两条取字节的路径：FileHandler.download 和 ContentHandler.getById（raw 文件分支）。
import { ContentHandler } from './.build/content.mjs';
import { FileHandler } from './.build/file.mjs';
import { makeEnv, makeChecker, getJson } from './harness.mjs';

const { check, summary } = makeChecker();

const PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

const DANGEROUS_INLINE = new Set([
  'text/html', 'application/xhtml+xml', 'image/svg+xml',
  'text/xml', 'application/xml',
  'application/javascript', 'text/javascript', 'application/x-javascript',
]);

async function uploadNamed(env, name, bytes, type) {
  const form = new FormData();
  form.append('file', new Blob([bytes], { type }), name);
  await FileHandler.upload(new Request('http://worker.local/upload?room=default', {
    method: 'POST', headers: { Authorization: 'Bearer ' }, body: form,
  }), env);
  const latest = await getJson(ContentHandler.getLatest, env, '/content/latest?room=default&json=1', { auth: 'Bearer ' });
  return { id: String(latest.json.id), uuid: String(latest.json.uuid) };
}

function ct(res) {
  return String(res.headers.get('Content-Type') || '').split(';')[0].trim().toLowerCase();
}

console.log('\n── 上传的 .html/.svg 不能以可渲染类型内联 ──');
{
  const { env } = makeEnv();
  env.AUTH_PASSWORD = '';

  const evils = [
    { name: 'evil.html', bytes: Buffer.from('<script>alert(document.domain)</script>'), type: 'text/html' },
    { name: 'evil.svg', bytes: Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'), type: 'image/svg+xml' },
  ];

  for (const e of evils) {
    const { id, uuid } = await uploadNamed(env, e.name, e.bytes, e.type);

    const viaFile = await FileHandler.download(
      Object.assign(new Request(`http://worker.local/file/${uuid}/${e.name}`), { params: { uuid, filename: e.name } }),
      env,
    );
    const viaContent = await ContentHandler.getById(
      Object.assign(new Request(`http://worker.local/content/${id}`), { params: { id } }),
      env,
    );

    for (const [label, res] of [[`/file ${e.name}`, viaFile], [`/content ${e.name}`, viaContent]]) {
      check(`${label}: 不是危险可渲染类型`, DANGEROUS_INLINE.has(ct(res)), false);
      check(`${label}: Content-Disposition=attachment`, String(res.headers.get('Content-Disposition') || '').toLowerCase().startsWith('attachment'), true);
      check(`${label}: X-Content-Type-Options=nosniff`, String(res.headers.get('X-Content-Type-Options') || '').toLowerCase(), 'nosniff');
      check(`${label}: 有 Content-Security-Policy`, (res.headers.get('Content-Security-Policy') || '') !== '', true);
    }
  }
}

console.log('\n── 正例：png 仍可内联（防护不能把正常图片也打成附件）──');
{
  const { env } = makeEnv();
  env.AUTH_PASSWORD = '';
  const { id, uuid } = await uploadNamed(env, 'ok.png', PNG, 'image/png');

  const viaFile = await FileHandler.download(
    Object.assign(new Request(`http://worker.local/file/${uuid}/ok.png`), { params: { uuid, filename: 'ok.png' } }),
    env,
  );
  const viaContent = await ContentHandler.getById(
    Object.assign(new Request(`http://worker.local/content/${id}`), { params: { id } }),
    env,
  );
  for (const [label, res] of [['/file png', viaFile], ['/content png', viaContent]]) {
    check(`${label}: Content-Type=image/png`, ct(res), 'image/png');
    check(`${label}: inline`, String(res.headers.get('Content-Disposition') || '').toLowerCase().startsWith('inline'), true);
    check(`${label}: nosniff`, String(res.headers.get('X-Content-Type-Options') || '').toLowerCase(), 'nosniff');
  }
}

summary('上传文件的安全类型 / 处置 / 头部');
