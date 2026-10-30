package version

// Version 是面板自身版本号。发布时由构建命令注入：
//
//	go build -ldflags "-X yizhan/internal/version.Version=v1.0.0"
//
// 未注入时为 dev（本地构建）。
// 一键更新就认这个值：更新前后调 /api/version 对比即知是否生效。
var Version = "dev"
