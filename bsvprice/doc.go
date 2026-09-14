// Package bsvprice 实现 bsv8.bsv-price.v1 BSV 多市场价格频道。
//
// 价格消息使用 ChannelProtocol 的通用公开消息壳签名；本包只负责固定频道
// 和价格快照正文的强类型校验。广播服务器不需要理解 markets 内容。
package bsvprice
