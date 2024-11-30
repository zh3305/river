using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace River.Socks
{
	public enum SocksError : byte
	{
		OK = 0,
		GeneralSOCKSServerFailure = 1,
		ConnectionNotAllowedByRuleset = 2,
		NetworkUnreachable = 3,
		HostUnreachable = 4,
		ConnectionRefused = 5,
		TTLExpired = 6,
		CommandNotSupported = 7,
		AddressTypeNotSupported = 8,
	}

    /// <summary>
    /// SOCKS 错误代码扩展方法
    /// </summary>
    public static class SocksErrorExtensions
    {
        /// <summary>
        /// 获取错误描述
        /// </summary>
        public static string GetDescription(this SocksError error)
        {
            return error switch
            {
                SocksError.OK => "成功",
                SocksError.GeneralSOCKSServerFailure => "常规故障",
                SocksError.ConnectionNotAllowedByRuleset => "规则集不允许连接",
                SocksError.NetworkUnreachable => "网络不可达",
                SocksError.HostUnreachable => "主机不可达",
                SocksError.ConnectionRefused => "连接被拒绝",
                SocksError.TTLExpired => "TTL已过期",
                SocksError.CommandNotSupported => "不支持的命令",
                SocksError.AddressTypeNotSupported => "不支持的地址类型",
                _ => $"未知错误 (0x{(byte)error:X2})"
            };
        }
    }
}
