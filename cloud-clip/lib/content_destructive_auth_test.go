package lib

// 三个**破坏性** DELETE 端点必须和读取一样过「房间归属 + 房间访问」两道闸，缺任一就应 401：
//   · DELETE /revoke/{id}        —— 只能撤销**本房间**的条目，且要有本房间访问权
//   · DELETE /revoke/all?room=   —— 清空某房间要有该房间访问权
//   · DELETE /file/{cache}       —— 删文件要先定位文件**自己记录的房间**，光有 cache UUID 不够
//
// 以前部署版里这三条要么完全不校验、要么只认客户端传的 ?room=，于是拿着一个 id / cache
// 就能删到受保护房间里的东西。这里用一个带密码的房间 vault 把「没权就拒、有权才成」钉死。

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"testing"
)

func newVaultServer(t *testing.T) *vaultFixture {
	t.Helper()
	srv := newShortcutServer(t, "", RoomAuthConfig{
		"vault": RoomAuthEntry{Password: "vault-pass"},
	})
	return &vaultFixture{t: t, base: srv.URL}
}

type vaultFixture struct {
	t    *testing.T
	base string
}

// postText 往 vault 发一条文本（带正确密码），返回 content id。
func (f *vaultFixture) postText(text string) string {
	f.t.Helper()
	status, body := shortcutDo(f.t, http.MethodPost, f.base+"/text?room=vault&auth=vault-pass", text, "text/plain")
	shortcutWant(f.t, "向 vault 发文本", status, http.StatusOK)
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		f.t.Fatalf("解析 /text 响应失败: %v (%s)", err, body)
	}
	return created.ID
}

// uploadFile 往 vault 传一个文件（带正确密码），返回 (contentID, cacheUUID)。
func (f *vaultFixture) uploadFile(name string, data []byte) (id, uuid string) {
	f.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", name)
	if err != nil {
		f.t.Fatalf("构造 multipart 失败: %v", err)
	}
	fw.Write(data)
	mw.Close()

	status, body := shortcutDo(f.t, http.MethodPost, f.base+"/upload?room=vault&auth=vault-pass", buf.String(), mw.FormDataContentType())
	shortcutWant(f.t, "向 vault 传文件", status, http.StatusOK)
	var up struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &up); err != nil {
		f.t.Fatalf("解析 /upload 响应失败: %v (%s)", err, body)
	}
	// uuid 从 /content/<id>?format=json 里取（带正确密码）
	status, cbody := shortcutDo(f.t, http.MethodGet, f.base+"/content/"+up.ID+"?room=vault&auth=vault-pass&format=json", "", "")
	shortcutWant(f.t, "读 vault 文件信息", status, http.StatusOK)
	var meta struct {
		UUID string `json:"uuid"`
	}
	if err := json.Unmarshal(cbody, &meta); err != nil {
		f.t.Fatalf("解析文件信息失败: %v (%s)", err, cbody)
	}
	if meta.UUID == "" {
		f.t.Fatalf("没拿到文件 uuid: %s", cbody)
	}
	return up.ID, meta.UUID
}

func TestRevokeRequiresRoomAccess(t *testing.T) {
	f := newVaultServer(t)
	id := f.postText("vault 里的机密")

	// 没密码撤销受保护房间的条目 → 401，而且东西还在
	status, _ := shortcutDo(t, http.MethodDelete, f.base+"/revoke/"+id+"?room=vault", "", "")
	if status != http.StatusUnauthorized && status != http.StatusForbidden {
		t.Fatalf("无密码撤销应 401/403，实际 %d", status)
	}
	status, _ = shortcutDo(t, http.MethodGet, f.base+"/content/"+id+"?room=vault&auth=vault-pass&format=json", "", "")
	shortcutWant(t, "撤销被拒后条目还在", status, http.StatusOK)

	// 带正确密码才能撤销
	status, _ = shortcutDo(t, http.MethodDelete, f.base+"/revoke/"+id+"?room=vault&auth=vault-pass", "", "")
	shortcutWant(t, "有密码撤销成功", status, http.StatusOK)
}

func TestClearAllRequiresRoomAccess(t *testing.T) {
	f := newVaultServer(t)
	id := f.postText("vault 里不该被别人一键清空的东西")

	status, _ := shortcutDo(t, http.MethodDelete, f.base+"/revoke/all?room=vault", "", "")
	if status != http.StatusUnauthorized && status != http.StatusForbidden {
		t.Fatalf("无密码清空应 401/403，实际 %d", status)
	}
	status, _ = shortcutDo(t, http.MethodGet, f.base+"/content/"+id+"?room=vault&auth=vault-pass&format=json", "", "")
	shortcutWant(t, "清空被拒后条目还在", status, http.StatusOK)

	status, _ = shortcutDo(t, http.MethodDelete, f.base+"/revoke/all?room=vault&auth=vault-pass", "", "")
	shortcutWant(t, "有密码清空成功", status, http.StatusOK)
}

func TestDeleteFileRequiresRoomAccess(t *testing.T) {
	f := newVaultServer(t)
	_, uuid := f.uploadFile("secret.bin", []byte("vault 文件字节"))

	// 光有 cache UUID、没有房间密码 → 不能删（服务端按文件自己记录的房间 vault 鉴权）
	status, _ := shortcutDo(t, http.MethodDelete, f.base+"/file/"+uuid, "", "")
	if status != http.StatusUnauthorized && status != http.StatusForbidden {
		t.Fatalf("无密码删文件应 401/403，实际 %d", status)
	}
	// 文件仍可用（带密码能读到）
	status, _ = shortcutDo(t, http.MethodGet, f.base+"/file/"+uuid+"/secret.bin?auth=vault-pass", "", "")
	shortcutWant(t, "删除被拒后文件还在", status, http.StatusOK)

	// 带正确密码才能删
	status, _ = shortcutDo(t, http.MethodDelete, f.base+"/file/"+uuid+"?auth=vault-pass", "", "")
	shortcutWant(t, "有密码删文件成功", status, http.StatusOK)
}
