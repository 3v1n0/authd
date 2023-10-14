package main

import "github.com/msteinert/pam"

// PamModuleTransaction is an interface that a pam module transaction
// implementation should have so that it's possible to mock it.
type PamModuleTransaction interface {
	SetItem(pam.Item, string) error
	GetItem(pam.Item) (string, error)
	PutEnv(nameval string) error
	GetEnv(name string) string
	GetEnvList() (map[string]string, error)
	GetUser(prompt string) (string, error)
	SetData(key string, data any) error
	GetData(key string) (any, error)
	StartStringConv(style pam.Style, prompt string) (
		pam.StringConvResponse, error)
	StartStringConvf(style pam.Style, format string, args ...interface{}) (
		pam.StringConvResponse, error)
	StartBinaryConv([]byte) (pam.BinaryConvResponse, error)
	StartConv(pam.ConvRequest) (pam.ConvResponse, error)
	StartConvMulti([]pam.ConvRequest) ([]pam.ConvResponse, error)
}
