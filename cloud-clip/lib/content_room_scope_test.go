package lib

import (
	"encoding/json"
	"strings"
	"testing"
)

// 按 id 定位一条内容的接口，不带 `?room=` 时只看**默认房间**，不再「哪个房间有就用哪个」。
//
// 以前不带 room 会扫全部房间，而 id 是自增的：在没配密码的实例上，
// 从 1 开始挨个 GET /content/<id> 就能读到所有开放房间的历史（房间名本身就成了唯一的门槛，
// 而这一招连房间名都不用知道）。/content/latest 同理，会返回「全站最新」那条。
func TestContentLookupDoesNotCrossRooms(t *testing.T) {
	srv := newShortcutServer(t, "", RoomAuthConfig{})

	post := func(room, text string) string {
		t.Helper()
		status, body := shortcutDo(t, "POST", srv.URL+"/text?room="+room, text, "text/plain")
		if status != 200 {
			t.Fatalf("POST /text?room=%s 失败: %d %s", room, status, body)
		}
		var created struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &created); err != nil {
			t.Fatalf("解析 /text 响应失败: %v (%s)", err, body)
		}
		return created.ID
	}

	defaultID := post("default", "默认房间的内容")
	secretID := post("secret-room", "别的房间里的一次性登录链接")

	// 不带 room = 默认房间：别的房间的 id 一律当不存在
	status, body := shortcutDo(t, "GET", srv.URL+"/content/"+secretID+"?format=json", "", "")
	shortcutWant(t, "不带 room 读别的房间的 id", status, 404)
	if strings.Contains(string(body), "一次性登录链接") {
		t.Fatalf("不带 room 读到了别的房间的内容: %s", body)
	}

	// 带对 room 照常能读
	status, body = shortcutDo(t, "GET", srv.URL+"/content/"+secretID+"?room=secret-room&format=json", "", "")
	shortcutWant(t, "带对 room 读", status, 200)
	if !strings.Contains(string(body), "一次性登录链接") {
		t.Fatalf("带对 room 应当读到内容: %s", body)
	}

	// 默认房间的 id 不带 room 照常能读（老客户端 / 快捷指令的默认房间用法不变）
	status, _ = shortcutDo(t, "GET", srv.URL+"/content/"+defaultID+"?format=json", "", "")
	shortcutWant(t, "不带 room 读默认房间的 id", status, 200)

	// latest 不带 room 只看默认房间，哪怕别的房间那条更新
	status, body = shortcutDo(t, "GET", srv.URL+"/content/latest?format=json", "", "")
	shortcutWant(t, "不带 room 的 latest", status, 200)
	if strings.Contains(string(body), "一次性登录链接") || !strings.Contains(string(body), "默认房间的内容") {
		t.Fatalf("不带 room 的 latest 应当是默认房间那条: %s", body)
	}

	// 写操作同理：挪列、分享、撤销都不能不带 room 就够到别的房间
	status, _ = shortcutDo(t, "POST", srv.URL+"/content/"+secretID+"/column", `{"column":"done"}`, "application/json")
	shortcutWant(t, "不带 room 挪别的房间的列", status, 404)

	status, body = shortcutDo(t, "POST", srv.URL+"/share", `{"type":"content","id":"`+secretID+`"}`, "application/json")
	shortcutWant(t, "不带 room 分享别的房间的内容", status, 404)
	if strings.Contains(string(body), "token") {
		t.Fatalf("不带 room 给别的房间的内容签出了分享令牌: %s", body)
	}

	status, _ = shortcutDo(t, "DELETE", srv.URL+"/revoke/"+secretID, "", "")
	shortcutWant(t, "不带 room 撤销别的房间的内容", status, 404)
	status, _ = shortcutDo(t, "GET", srv.URL+"/content/"+secretID+"?room=secret-room", "", "")
	shortcutWant(t, "撤销被拒后内容还在", status, 200)
}
