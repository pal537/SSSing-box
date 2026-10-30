package server

import (
	"github.com/skip2/go-qrcode"
)

func qrcodeEncode(content string) ([]byte, error) {
	return qrcode.Encode(content, qrcode.Medium, 256)
}
