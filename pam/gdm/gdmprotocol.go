package gdm

var ProtoName = "authd-json"
var ProtoVersion = int(1)
var ProtoWireVersion = int(1)

type Field = map[string]any
type DataType = string

type Data struct {
	Type DataType `json:"type"`
	Data Field    `json:"data,omitempty"`
}
