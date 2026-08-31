package channels

import (
	"encoding/json"
	"os"
	"testing"
)

func TestProtocolRegistry(t *testing.T) {
	registry := ProtocolRegistry()
	if len(registry) != 4 {
		t.Fatalf("协议注册数量错误: got %d, want 4", len(registry))
	}
	if registry[0].Identifier != HashRequestChannel || registry[1].Identifier != InboxChannelPrefix+"<public_key_hex>" {
		t.Fatal("频道注册表与 V1 文档不一致")
	}
	if registry[2].Identifier != WebRTCSignalProtocol || registry[3].Identifier != AppMessageProtocol {
		t.Fatal("收件箱子协议注册表与 V1 文档不一致")
	}

	registry[0].Identifier = "mutated"
	if ProtocolRegistry()[0].Identifier != HashRequestChannel {
		t.Fatal("ProtocolRegistry 返回值与内部状态共享可变内存")
	}
}

func TestProtocolRegistryMatchesMachineReadableMapping(t *testing.T) {
	data, err := os.ReadFile("protocols.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Protocols []struct {
			Identifier       string `json:"identifier"`
			DescriptionZH    string `json:"description_zh"`
			GoPackage        string `json:"go_package"`
			TypeScriptExport string `json:"typescript_export"`
		} `json:"protocols"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	registry := ProtocolRegistry()
	if len(document.Protocols) != len(registry) {
		t.Fatalf("机器可读注册数量错误: got %d want %d", len(document.Protocols), len(registry))
	}
	for index, item := range document.Protocols {
		actual := registry[index]
		if actual.Identifier != item.Identifier || actual.DescriptionZH != item.DescriptionZH || actual.GoPackage != item.GoPackage || actual.TypeScriptExport != item.TypeScriptExport {
			t.Fatalf("注册表第 %d 项不一致: %#v vs %#v", index, actual, item)
		}
	}
}
