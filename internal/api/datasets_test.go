package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-analyzer/internal/store"
)

func TestDatasetDeletionScopeConfirmationAndDurableResult(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	d, release, e := s.BeginMessages(ctx, store.NetworkKey{ChainID: "8", GenesisHash: "0x" + strings.Repeat("a", 64)}, "synthetic-delete", json.RawMessage(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	release()
	c := client{t, (&Server{Store: s}).Handler()}
	path := fmt.Sprintf("/v1/networks/%d/datasets/%d", d.NetworkID, d.ID)
	var info store.DatasetInputStorage
	if c.do("GET", path+"/input-storage", nil, &info) != 200 || info.State != "empty" {
		t.Fatal(info)
	}
	for _, body := range []string{`{}`, `{"confirm_name":"synthetic-delete","extra":true}`, `{"confirm_name":"synthetic-delete"} {}`} {
		if code := c.do("DELETE", path, []byte(body), nil); code != 400 {
			t.Fatal(body, code)
		}
	}
	if code := c.do("DELETE", path, []byte(`{"confirm_name":"wrong"}`), nil); code != 409 {
		t.Fatal(code)
	}
	wrong := fmt.Sprintf("/v1/networks/%d/datasets/%d", d.NetworkID+1, d.ID)
	if code := c.do("DELETE", wrong, []byte(`{"confirm_name":"synthetic-delete"}`), nil); code != 404 {
		t.Fatal(code)
	}
	if code := c.do("DELETE", path+"?force=1", []byte(`{"confirm_name":"synthetic-delete"}`), nil); code != 400 {
		t.Fatal(code)
	}
	var result store.DatasetDeletion
	if c.do("DELETE", path, []byte(`{"confirm_name":"synthetic-delete"}`), &result) != 200 || result.Status != "deleted" || result.Files != 0 {
		t.Fatal(result)
	}
	var saved store.DatasetDeletion
	if c.do("GET", path+"/deletion", nil, &saved) != 200 || saved.Dataset != d.ID || saved.Status != "deleted" {
		t.Fatal(saved)
	}
	b, _ := json.Marshal(saved)
	for _, secret := range []string{"root", "token", "owner", "path"} {
		if strings.Contains(string(b), `"`+secret+`"`) {
			t.Fatal("private storage identity exposed", string(b))
		}
	}
	if code := c.do("GET", path+"/input-storage", nil, nil); code != 404 {
		t.Fatal(code)
	}
	if c.do("DELETE", path, []byte(`{"confirm_name":"synthetic-delete"}`), &saved) != 200 {
		t.Fatal(saved)
	}
}
