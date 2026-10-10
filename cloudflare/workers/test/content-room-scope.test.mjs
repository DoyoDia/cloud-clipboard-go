// 按 id 定位一条内容的接口，不带 `?room=` 时只看**默认房间**，不再「哪个房间有就用哪个」。
//
// 与 Go 侧 TestContentLookupDoesNotCrossRooms 是同一份契约。以前不带 room 会按 id 跨房间查，
// 而 id 是自增的：没配密码的部署上，从 1 开始挨个 GET /content/<id> 就能读到所有开放房间的历史。
import { ContentHandler } from './.build/content.mjs';
import { TextHandler } from './.build/text.mjs';
import { ShareHandler } from './.build/share.mjs';
import { makeEnv, makeChecker, postJson } from './harness.mjs';

const { check, summary } = makeChecker();

async function call(handler, env, path, { method = 'GET', body = null, params = {} } = {}) {
  const headers = {};
  if (body !== null) headers['Content-Type'] = 'application/json';
  const req = Object.assign(
    new Request(`http://worker.local${path}`, { method, headers, body }),
    { params },
  );
  const res = await handler(req, env);
  return { status: res.status, text: await res.text() };
}

console.log('\n── 没配密码的部署：不带 room 的按 id 访问不能跨房间 ──');
{
  const { env } = makeEnv();
  env.AUTH_PASSWORD = '';

  const defaultId = (await postJson(TextHandler.create, env, '/text?room=default', '默认房间的内容', { auth: '' })).json.id;
  const secretId = (await postJson(TextHandler.create, env, '/text?room=secret-room', '别的房间里的一次性登录链接', { auth: '' })).json.id;

  let r = await call(ContentHandler.getById, env, `/content/${secretId}?json=1`, { params: { id: String(secretId) } });
  check('不带 room 读别的房间的 id → 404', r.status, 404);
  check('不带 room 读不到别的房间的正文', r.text.includes('一次性登录链接'), false);

  r = await call(ContentHandler.getById, env, `/content/${secretId}?room=secret-room&json=1`, { params: { id: String(secretId) } });
  check('带对 room 照常能读', r.status, 200);

  r = await call(ContentHandler.getById, env, `/content/${defaultId}?json=1`, { params: { id: String(defaultId) } });
  check('不带 room 读默认房间的 id 照常能读', r.status, 200);

  r = await call(ContentHandler.setColumn, env, `/content/${secretId}/column`, {
    method: 'POST', body: JSON.stringify({ column: 'done' }), params: { id: String(secretId) },
  });
  check('不带 room 挪别的房间的列 → 404', r.status, 404);

  r = await call(ShareHandler.create, env, '/share', {
    method: 'POST', body: JSON.stringify({ type: 'content', id: String(secretId) }),
  });
  check('不带 room 分享别的房间的内容 → 404', r.status, 404);
}

summary('不带 room 的按 id 访问不跨房间');
