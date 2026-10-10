package lib

// 存储型 XSS 回归：上传的字节是不可信的，服务端**绝不**按上传文件名的扩展名把它当
// text/html / image/svg+xml / application/xhtml+xml / JS 内联渲染 —— 否则 `.html`/`.svg`
// 一传上去，受害者一访问 /file/<uuid>/<name> 或 /content/<id> 就会在本站可信源里执行脚本。
//
// 这里打在**真路由**上，同时覆盖两条取文件字节的路径：
//   · GET /file/<uuid>/<name>
//   · GET /content/<id>          （raw，文件分支）
// 并顺带验一条安全类型（.png）仍然可以内联（别把防护做成「全部当附件」把正常图片也废了）。

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
)

// uploadNamedFile 以指定文件名上传一份字节，返回它的 content id 与 cache uuid。
func uploadNamedFile(t *testing.T, base, filename string, data []byte) (id, uuid string) {
	t.Helper()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("构造 multipart 失败: %v", err)
	}
	if _, err := fw.Write(data); err != nil {
		t.Fatalf("写入 multipart 失败: %v", err)
	}
	mw.Close()

	status, _ := shortcutDo(t, http.MethodPost, base+"/upload?room=default", buf.String(), mw.FormDataContentType())
	shortcutWant(t, "上传 "+filename, status, http.StatusOK)

	// id / uuid 都从「接收最新」里取（/upload 的响应体在不同路径下形状不一，latest 是稳定的）。
	latest := shortcutLatest(t, base, "")
	// id 在 JSON 里历史上可能是字符串或数字，%v 拼进 URL 两种都对（与 shortcutTextFlow 同）。
	if v, ok := latest["id"]; ok {
		id = fmt.Sprintf("%v", v)
	}
	if v, ok := latest["uuid"]; ok {
		uuid = fmt.Sprintf("%v", v)
	}
	if id == "" || uuid == "" {
		t.Fatalf("拿不到上传文件的 id/uuid: id=%q uuid=%q (latest=%v)", id, uuid, latest)
	}
	return id, uuid
}

func headersOf(t *testing.T, url string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s 失败: %v", url, err)
	}
	resp.Body.Close()
	return resp
}

func TestUploadedFilesNotServedAsRenderableInline(t *testing.T) {
	srv := newShortcutServer(t, "", RoomAuthConfig{})

	// 浏览器一旦把这些类型当页面渲染，脚本就在本站源里跑起来了。
	dangerousInline := map[string]bool{
		"text/html":                true,
		"application/xhtml+xml":    true,
		"image/svg+xml":            true,
		"text/xml":                 true,
		"application/xml":          true,
		"application/javascript":   true,
		"text/javascript":          true,
		"application/x-javascript": true,
	}

	cases := []struct {
		name  string
		bytes []byte
	}{
		{"evil.html", []byte(`<script>alert(document.domain)</script>`)},
		{"evil.svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)},
	}

	for _, tc := range cases {
		id, uuid := uploadNamedFile(t, srv.URL, tc.name, tc.bytes)

		paths := map[string]string{
			"GET /file/<uuid>/<name>": srv.URL + "/file/" + uuid + "/" + tc.name,
			"GET /content/<id>":       srv.URL + "/content/" + id,
		}
		for label, url := range paths {
			resp := headersOf(t, url)
			ct := strings.ToLower(strings.TrimSpace(strings.SplitN(resp.Header.Get("Content-Type"), ";", 2)[0]))
			disp := strings.ToLower(resp.Header.Get("Content-Disposition"))

			if dangerousInline[ct] {
				t.Errorf("%s (%s): 用危险的可渲染类型发出去了: Content-Type=%q", label, tc.name, ct)
			}
			if !strings.HasPrefix(disp, "attachment") {
				t.Errorf("%s (%s): 非白名单类型必须 attachment，实际 Content-Disposition=%q", label, tc.name, disp)
			}
			if got := resp.Header.Get("X-Content-Type-Options"); !strings.EqualFold(got, "nosniff") {
				t.Errorf("%s (%s): 缺少 X-Content-Type-Options: nosniff（实际 %q）", label, tc.name, got)
			}
			if csp := resp.Header.Get("Content-Security-Policy"); csp == "" {
				t.Errorf("%s (%s): 缺少 Content-Security-Policy", label, tc.name)
			}
		}
	}
}

// 正例：安全类型（png）仍然内联，且带上 nosniff/CSP —— 防护不能把正常图片也打成附件。
func TestUploadedPNGStillInline(t *testing.T) {
	srv := newShortcutServer(t, "", RoomAuthConfig{})

	id, uuid := uploadNamedFile(t, srv.URL, "ok.png", shortcutPNG)

	for _, url := range []string{
		srv.URL + "/file/" + uuid + "/ok.png",
		srv.URL + "/content/" + id,
	} {
		resp := headersOf(t, url)
		ct := strings.ToLower(strings.TrimSpace(strings.SplitN(resp.Header.Get("Content-Type"), ";", 2)[0]))
		if ct != "image/png" {
			t.Errorf("%s: png 应以 image/png 发出，实际 %q", url, ct)
		}
		if disp := strings.ToLower(resp.Header.Get("Content-Disposition")); !strings.HasPrefix(disp, "inline") {
			t.Errorf("%s: png 应当 inline，实际 %q", url, disp)
		}
		if got := resp.Header.Get("X-Content-Type-Options"); !strings.EqualFold(got, "nosniff") {
			t.Errorf("%s: png 也要带 nosniff，实际 %q", url, got)
		}
	}
}
