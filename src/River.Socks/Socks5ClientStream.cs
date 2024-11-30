using River.Common;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace River.Socks
{
    /// <summary>
    /// SOCKS5 客户端流实现
    /// 支持 IPv4、IPv6 和域名解析 
    /// 支持无认证和用户名密码认证
    /// </summary>
    public class Socks5ClientStream : SocksClientStream
    {
        private static readonly Trace Trace = River.Trace.Default;

        // SOCKS5 协议常量
        private const byte SOCKS_VERSION = 0x05;
        private const byte AUTH_VERSION = 0x01;
        private const byte NO_AUTHENTICATION = 0x00;
        private const byte USERNAME_PASSWORD_AUTH = 0x02;
        private const byte STREAM_COMMAND = 0x01;

        // 地址类型常量
        private const byte ADDR_TYPE_IPV4 = 0x01;
        private const byte ADDR_TYPE_DOMAIN = 0x03;
        private const byte ADDR_TYPE_IPV6 = 0x04;

        // 认证标志
        private bool _useAuthentication => !string.IsNullOrEmpty(ProxyUsername) && !string.IsNullOrEmpty(ProxyPassword);

        /// <summary>
        /// 创建新的 SOCKS5 客户端流实例
        /// </summary>
        public Socks5ClientStream()
        {
            Trace.WriteLine(TraceCategory.NetworkingData, "创建新的 SOCKS5 客户端流实例");
        }

        /// <summary>
        /// 使用指定参数创建并初始化 SOCKS5 客户端流（无认证）
        /// </summary>
        public Socks5ClientStream(string proxyHost, int proxyPort, string targetHost, int targetPort, bool? proxyDns = null)
            : this(proxyHost, proxyPort, targetHost, targetPort, null, null, proxyDns)
        {
        }

        /// <summary>
        /// 使用指定参数和认证信息创建并初始化 SOCKS5 客户端流
        /// </summary>
        public Socks5ClientStream(string proxyHost, int proxyPort, string targetHost, int targetPort,
            string username, string password, bool? proxyDns = null)
        {
            Trace.WriteLine(TraceCategory.NetworkingData,
                $"初始化 SOCKS5 连接 - 代理: {proxyHost}:{proxyPort}, 目标: {targetHost}:{targetPort}, 认证: {(string.IsNullOrEmpty(username) ? "无" : "有")}");

            ProxyUsername = username;
            ProxyPassword = password;
            try
            {
                Plug(proxyHost, proxyPort);
                Route(targetHost, targetPort, proxyDns);
                Trace.WriteLine(TraceCategory.NetworkingData, "SOCKS5 连接成功建立");
            }
            catch (Exception ex)
            {
                Trace.WriteLine(TraceCategory.NetworkingError, $"SOCKS5 连接失败: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// 连接到代理服务器
        /// </summary>
        public void Plug(string proxyHost, int proxyPort)
        {
            Trace.WriteLine(TraceCategory.NetworkingData, $"连接到代理服务器 {proxyHost}:{proxyPort}");
            ClientStreamExtensions.Plug(this, proxyHost, proxyPort);
        }

        /// <summary>
        /// 路由请求到目标URI
        /// </summary>
        public override void Route(Uri uri)
        {
            Trace.WriteLine(TraceCategory.NetworkingData, $"路由请求到 {uri}");
            Route(uri.Host, uri.Port, null);
        }

        /// <summary>
        /// 路由请求到目标
        /// </summary>
        public void Route(string targetHost, int targetPort, bool? proxyDns = null)
        {
            if (targetHost == null)
            {
                throw new ArgumentNullException(nameof(targetHost));
            }

            Trace.WriteLine(TraceCategory.NetworkingData, $"开始路由到 {targetHost}:{targetPort}");

            var stream = Stream;
            var buffer = new byte[1024];
            int offset = 0;

            try
            {
                // 1. 认证协商
                SendAuthenticationRequest(stream, buffer, ref offset);
                var authMethod = VerifyAuthenticationResponse(stream, buffer);

                // 2. 如果需要，执行用户名密码认证
                if (authMethod == USERNAME_PASSWORD_AUTH)
                {
                    PerformUsernamePasswordAuth(stream, buffer);
                }

                // 3. 发送连接请求
                SendConnectionRequest(stream, buffer, targetHost, targetPort, proxyDns);

                // 4. 处理服务器响应
                ProcessServerResponse(stream, buffer);

                Trace.WriteLine(TraceCategory.NetworkingData, "路由成功建立");
            }
            catch (Exception ex)
            {
                Trace.WriteLine(TraceCategory.NetworkingError, $"路由失败: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// 发送认证请求
        /// </summary>
        private void SendAuthenticationRequest(Stream stream, byte[] buffer, ref int offset)
        {
            Trace.WriteLine(TraceCategory.NetworkingData, "发送认证协商请求");

            offset = 0;
            buffer[offset++] = SOCKS_VERSION;    // SOCKS5 版本

            if (_useAuthentication)
            {
                buffer[offset++] = 0x02;  // 支持两种认证方法
                buffer[offset++] = NO_AUTHENTICATION;        // 无认证
                buffer[offset++] = USERNAME_PASSWORD_AUTH;   // 用户名密码认证
            }
            else
            {
                buffer[offset++] = 0x01;  // 支持一种认证方法
                buffer[offset++] = NO_AUTHENTICATION;  // 无认证
            }

            stream.Write(buffer, 0, offset);
            stream.Flush();
        }

        /// <summary>
        /// 验证服务器的认证响应
        /// </summary>
        private byte VerifyAuthenticationResponse(Stream stream, byte[] buffer)
        {
            var count = stream.Read(buffer, 0, 2);

            if (count != 2)
            {
                throw new IOException("认证响应不完整");
            }
            if (buffer[0] != SOCKS_VERSION)
            {
                throw new IOException("服务器不支持 SOCKS5");
            }

            var authMethod = buffer[1];
            if (authMethod == 0xFF)
            {
                throw new IOException("服务器拒绝所有认证方法");
            }

            if (authMethod != NO_AUTHENTICATION && authMethod != USERNAME_PASSWORD_AUTH)
            {
                throw new IOException($"服务器要求不支持的认证方法: {authMethod}");
            }

            Trace.WriteLine(TraceCategory.NetworkingData,
                $"服务器选择的认证方法: {(authMethod == NO_AUTHENTICATION ? "无认证" : "用户名密码认证")}");

            return authMethod;
        }

        /// <summary>
        /// 执行用户名密码认证
        /// </summary>
        private void PerformUsernamePasswordAuth(Stream stream, byte[] buffer)
        {
            if (!_useAuthentication)
            {
                throw new InvalidOperationException("服务器要求认证，但未提供认证信息");
            }

            Trace.WriteLine(TraceCategory.NetworkingData, "开始用户名密码认证");

            int offset = 0;
            // 认证子协商版本
            buffer[offset++] = AUTH_VERSION;

            // 用户名长度和用户名
            byte usernameLength = (byte)Encoding.ASCII.GetByteCount(ProxyUsername);
            buffer[offset++] = usernameLength;
            offset += Encoding.ASCII.GetBytes(ProxyUsername, 0, ProxyUsername.Length, buffer, offset);

            // 密码长度和密码
            byte passwordLength = (byte)Encoding.ASCII.GetByteCount(ProxyPassword);
            buffer[offset++] = passwordLength;
            offset += Encoding.ASCII.GetBytes(ProxyPassword, 0, ProxyPassword.Length, buffer, offset);

            // 发送认证信息
            stream.Write(buffer, 0, offset);
            stream.Flush();

            // 读取认证响应
            var count = stream.Read(buffer, 0, 2);
            if (count != 2)
            {
                throw new IOException("认证响应不完整");
            }

            if (buffer[0] != AUTH_VERSION)
            {
                throw new IOException("认证协议版本错误");
            }

            if (buffer[1] != 0x00)
            {
                Trace.WriteLine(TraceCategory.NetworkingError, "用户名密码认证失败");
                throw new IOException("认证失败：用户名或密码错误");
            }

            Trace.WriteLine(TraceCategory.NetworkingData, "用户名密码认证成功");
        }

        /// <summary>
        /// 发送连接请求
        /// </summary>
        private void SendConnectionRequest(Stream stream, byte[] buffer, string targetHost, int targetPort, bool? proxyDns)
        {
            Trace.WriteLine(TraceCategory.NetworkingData, $"发送连接请求到 {targetHost}:{targetPort}");

            int offset = 0;
            buffer[offset++] = SOCKS_VERSION;  // SOCKS5 版本
            buffer[offset++] = STREAM_COMMAND; // 请求类型：建立TCP连接
            buffer[offset++] = 0x00;          // 保留字节

            // 处理地址
            bool isIpAddress = IPAddress.TryParse(targetHost, out var ipAddress);

            if (!isIpAddress)
            {
                var addresses = Dns.GetHostAddresses(targetHost);
                ipAddress = addresses.FirstOrDefault(x => x.AddressFamily == AddressFamily.InterNetwork)
                           ?? addresses.FirstOrDefault(x => x.AddressFamily == AddressFamily.InterNetworkV6);
            }

            // 根据地址类型设置不同的请求格式
            if (!isIpAddress && (proxyDns != false))
            {
                WriteDomainAddress(buffer, ref offset, targetHost);
            }
            else if (ipAddress != null)
            {
                WriteIpAddress(buffer, ref offset, ipAddress);
            }
            else
            {
                throw new IOException($"无法解析主机名: {targetHost}");
            }

            // 写入端口
            buffer[offset++] = (byte)(targetPort >> 8);
            buffer[offset++] = (byte)(targetPort);

            stream.Write(buffer, 0, offset);
            stream.Flush();
        }

        /// <summary>
        /// 写入域名地址
        /// </summary>
        private void WriteDomainAddress(byte[] buffer, ref int offset, string domain)
        {
            buffer[offset++] = ADDR_TYPE_DOMAIN;
            buffer[offset++] = checked((byte)domain.Length);
            Utils.Ascii.GetBytes(domain, 0, domain.Length, buffer, offset);
            offset += domain.Length;

            Trace.WriteLine(TraceCategory.NetworkingData, $"使用域名方式: {domain}");
        }

        /// <summary>
        /// 写入IP地址
        /// </summary>
        private void WriteIpAddress(byte[] buffer, ref int offset, IPAddress ipAddress)
        {
            if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6)
            {
                buffer[offset++] = ADDR_TYPE_IPV6;
                ipAddress.GetAddressBytes().CopyTo(buffer, offset);
                offset += 16;
                Trace.WriteLine(TraceCategory.NetworkingData, $"使用 IPv6 地址: {ipAddress}");
            }
            else
            {
                buffer[offset++] = ADDR_TYPE_IPV4;
                var addressBytes = ipAddress.GetAddressBytes();
                Buffer.BlockCopy(addressBytes, 0, buffer, offset, 4);
                offset += 4;
                Trace.WriteLine(TraceCategory.NetworkingData, $"使用 IPv4 地址: {ipAddress}");
            }
        }

        /// <summary>
        /// 处理服务器响应
        /// </summary>
        private void ProcessServerResponse(Stream stream, byte[] buffer)
        {
            var count = stream.Read(buffer, 0, 4);
            if (count < 4)
            {
                throw new IOException("服务器响应不完整");
            }

            // 检查版本号
            if (buffer[0] != SOCKS_VERSION)
            {
                throw new IOException("服务器返回了错误的SOCKS版本");
            }

            // 检查响应状态
            if (buffer[1] != 0x00)
            {
                var errorCode = buffer[1];
                var errorMessage = GetResponseErrorMessage(errorCode);
                throw new IOException($"代理服务器返回错误: 0x{errorCode:X2} - {errorMessage}");
            }

            // 读取绑定地址
            ReadBoundAddress(stream, buffer, count);
        }

        /// <summary>
        /// 读取服务器绑定地址
        /// </summary>
        private void ReadBoundAddress(Stream stream, byte[] buffer, int initialCount)
        {
            int count = initialCount;
            switch (buffer[3]) // 地址类型
            {
                case ADDR_TYPE_IPV4:
                    count += stream.Read(buffer, count, 4);
                    Trace.WriteLine(TraceCategory.NetworkingData, "读取服务器返回的 IPv4 绑定地址");
                    break;

                case ADDR_TYPE_DOMAIN:
                    count += stream.Read(buffer, count, 1);
                    count += stream.Read(buffer, count, buffer[count - 1]);
                    Trace.WriteLine(TraceCategory.NetworkingData, "读取服务器返回的域名绑定地址");
                    break;

                case ADDR_TYPE_IPV6:
                    count += stream.Read(buffer, count, 16);
                    Trace.WriteLine(TraceCategory.NetworkingData, "读取服务器返回的 IPv6 绑定地址");
                    break;

                default:
                    throw new IOException($"服务器返回了不支持的地址类型: {buffer[3]}");
            }

            // 读取端口（2字节）
            var portBytes = new byte[2];
            stream.Read(portBytes, 0, 2);
            var port = (ushort)((portBytes[0] << 8) | portBytes[1]);

            Trace.WriteLine(TraceCategory.NetworkingData, $"服务器绑定端口: {port}");
        }

        /// <summary>
        /// 获取服务器响应错误消息
        /// </summary>
        private string GetResponseErrorMessage(byte responseCode)
        {
            var error = (SocksError)responseCode;
            return $"{error.GetDescription()} ({error})";
        }

        /// <summary>
        /// 获取或设置连接超时时间（毫秒）
        /// </summary>
        public int ConnectionTimeout { get; set; } = 30000;

        /// <summary>
        /// 销毁资源
        /// </summary>
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                try
                {
                    Stream?.Dispose();
                }
                catch (Exception ex)
                {
                    Trace.WriteLine(TraceCategory.NetworkingError, $"关闭流时发生错误: {ex.Message}");
                }
            }
            base.Dispose(disposing);
        }
    }
}