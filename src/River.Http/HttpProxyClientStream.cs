using River.Internal;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace River.Http
{
    /// <summary>
    /// HTTP代理客户端流实现
    /// 支持HTTP CONNECT方法
    /// 支持Basic认证
    /// 支持IPv4、IPv6
    /// </summary>
    public class HttpProxyClientStream : ClientStream
    {

        private static readonly Trace Trace = River.Trace.Default;
        private const string HTTP_VERSION = "HTTP/1.1";// HTTP版本
       

        // Basic认证前缀
        private const string BASIC_AUTH_PREFIX = "Basic ";


        /// <summary>
        /// 认证标志
        /// </summary>
        private bool _useAuthentication => !string.IsNullOrEmpty(ProxyUsername) && !string.IsNullOrEmpty(ProxyPassword);



        // 读取缓冲区大小
        // private const int BUFFER_SIZE = 16 * 1024;
        private const int BUFFER_SIZE = 8192;  // 减小缓冲区大小以优化内存使用
        private readonly byte[] _readBuffer = new byte[BUFFER_SIZE];
        private readonly byte[] _buffer = new byte[BUFFER_SIZE];

        /// <summary>
        /// 创建新的HTTP代理客户端流实例
        /// </summary>
        public HttpProxyClientStream()
        {
            Trace.WriteLine(TraceCategory.NetworkingData, "创建新的HTTP代理客户端流实例");
        }

        /// <summary>
        /// 使用指定参数创建并初始化HTTP代理客户端流（无认证）
        /// </summary>
        public HttpProxyClientStream(string proxyHost, int proxyPort, string targetHost, int targetPort)
            : this(proxyHost, proxyPort, targetHost, targetPort, null, null)
        {
        }

        /// <summary>
        /// 使用指定参数和认证信息创建并初始化HTTP代理客户端流
        /// </summary>
        public HttpProxyClientStream(string proxyHost, int proxyPort, string targetHost, int targetPort,
            string username, string password)
        {
            if (string.IsNullOrEmpty(proxyHost))
                throw new ArgumentNullException(nameof(proxyHost));
            if (string.IsNullOrEmpty(targetHost))
                throw new ArgumentNullException(nameof(targetHost));

            Trace.WriteLine(TraceCategory.NetworkingData,
                $"初始化HTTP代理连接 - 代理: {proxyHost}:{proxyPort}, 目标: {targetHost}:{targetPort}, 认证: {(string.IsNullOrEmpty(username) ? "无" : "有")}");

            ProxyUsername = username;
            ProxyPassword = password;

            try
            {
                Plug(proxyHost, proxyPort);
                Route(targetHost, targetPort);
                Trace.WriteLine(TraceCategory.NetworkingData, "HTTP代理连接成功建立");
            }
            catch (Exception ex)
            {
                Trace.WriteLine(TraceCategory.NetworkingError, $"HTTP代理连接失败: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// 使用指定代理服务器创建HTTP代理客户端流
        /// </summary>
        public HttpProxyClientStream(string proxyHost, int proxyPort)
        {
            if (string.IsNullOrEmpty(proxyHost))
                throw new ArgumentNullException(nameof(proxyHost));

            Trace.WriteLine(TraceCategory.NetworkingData, $"创建到代理服务器的连接 {proxyHost}:{proxyPort}");
            Plug(proxyHost, proxyPort);
        }

        /// <summary>
        /// 使用现有流和目标信息创建HTTP代理客户端流
        /// </summary>
        public HttpProxyClientStream(Stream stream, string targetHost, int targetPort)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            if (string.IsNullOrEmpty(targetHost))
                throw new ArgumentNullException(nameof(targetHost));

            Trace.WriteLine(TraceCategory.NetworkingData, $"使用现有流创建到 {targetHost}:{targetPort} 的连接");
            Plug(null, stream);
            Route(targetHost, targetPort);
        }

        /// <summary>
        /// 连接到代理服务器
        /// </summary>
        public void Plug(string host, int port)
        {
            if (string.IsNullOrEmpty(host))
                throw new ArgumentNullException(nameof(host));

            Trace.WriteLine(TraceCategory.NetworkingData, $"正在连接到代理服务器 {host}:{port}");
            try
            {
                // 这里调用ClientStreamExtensions.Plug会处理IPv6地址格式
                ClientStreamExtensions.Plug(this, host, port);
                Trace.WriteLine(TraceCategory.NetworkingData, "成功连接到代理服务器");
            }
            catch (Exception ex)
            {
                Trace.WriteLine(TraceCategory.NetworkingError, $"连接到代理服务器失败: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// 路由请求到目标URI
        /// </summary>
        public override void Route(Uri uri)
        {
            if (uri == null)
                throw new ArgumentNullException(nameof(uri));

            Trace.WriteLine(TraceCategory.NetworkingData, $"路由请求到 {uri}");
            Route(uri.Host, uri.Port, null);
        }

        /// <summary>
        /// 路由请求到目标
        /// </summary>
        public override void Route(string targetHost, int targetPort, bool? proxyDns = null)
        {
            if (string.IsNullOrEmpty(targetHost))
                throw new ArgumentNullException(nameof(targetHost));

            Trace.WriteLine(TraceCategory.NetworkingData, $"开始路由到 {targetHost}:{targetPort}");

            try
            {
                // 处理IPv6地址格式
                if (IPAddress.TryParse(targetHost, out var ip) && ip.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    targetHost = $"[{ip}]";
                }

                // 构建并发送CONNECT请求
                SendConnectRequest(targetHost, targetPort);

                // 处理响应
                ProcessProxyResponse();

                Trace.WriteLine(TraceCategory.NetworkingData, "代理隧道成功建立");
            }
            catch (Exception ex)
            {
                Trace.WriteLine(TraceCategory.NetworkingError, $"代理连接失败: {ex.Message}");
                throw;
            }
        }
       
            /// <summary>
            /// 发送CONNECT请求
            /// </summary>
            private void SendConnectRequest(string targetHost, int targetPort)
            {
                // 使用StringBuilder预分配合适的容量
                var requestBuilder = new StringBuilder(256);
                requestBuilder.AppendLine($"CONNECT {targetHost}:{targetPort} {HTTP_VERSION}")
                            .AppendLine($"Host: {targetHost}:{targetPort}")
                            .AppendLine("Proxy-Connection: Keep-Alive");

                if (_useAuthentication)
                {
                    Trace.WriteLine(TraceCategory.NetworkingData, "添加Basic认证信息");
                    var credentials = Convert.ToBase64String(
                        Encoding.ASCII.GetBytes($"{ProxyUsername}:{ProxyPassword}"));
                    requestBuilder.AppendLine($"Proxy-Authorization: Basic {credentials}");
                }

                requestBuilder.AppendLine();

                var request = requestBuilder.ToString();
                // Trace.WriteLine(TraceCategory.NetworkingData, $"发送CONNECT请求:\n{request}");

                var requestBytes = Encoding.ASCII.GetBytes(request);
                Stream.Write(requestBytes, 0, requestBytes.Length);
                Stream.Flush();
            }

            /// <summary>
            /// 处理代理服务器的响应
            /// </summary>
            private void ProcessProxyResponse()
            {
                // 读取第一行（状态行）
                string statusLine = ReadLine();
                if (string.IsNullOrEmpty(statusLine))
                {
                    throw new IOException("代理服务器返回空响应");
                }

                // Trace.WriteLine(TraceCategory.NetworkingData, $"收到原始响应数据:\n{statusLine}");

                // 解析状态行
                var parts = statusLine.Split(new[] { ' ' }, 3);
                if (parts.Length < 2 || !parts[0].StartsWith("HTTP/"))
                {
                    throw new IOException($"无效的响应状态行: {statusLine}");
                }

                // 解析状态码
                if (!int.TryParse(parts[1], out int statusCode))
                {
                    throw new IOException($"无效的状态码: {parts[1]}");
                }

                string statusMessage = parts.Length > 2 ? parts[2] : string.Empty;
                Trace.WriteLine(TraceCategory.NetworkingData,
                    $"解析响应 - 版本: {parts[0]}, 状态码: {statusCode}, 消息: {statusMessage}");

                // 检查状态码
                if (statusCode != 200)
                {
                    HandleErrorResponse(statusCode, statusMessage);
                }

                // 读取并记录响应头
                string line;
                while (!string.IsNullOrEmpty(line = ReadLine()))
                {
                    var colonIndex = line.IndexOf(':');
                    if (colonIndex > 0)
                    {
                        var key = line.Substring(0, colonIndex).Trim();
                        var value = line.Substring(colonIndex + 1).Trim();
                        Trace.WriteLine(TraceCategory.NetworkingData, $"响应头: {key}: {value}");
                    }
                }

                Trace.WriteLine(TraceCategory.NetworkingData, "代理连接成功建立");
            }

            /// <summary>
            /// 处理错误响应
            /// </summary>
            private void HandleErrorResponse(int statusCode, string statusMessage)
            {
                var errorMessage = statusCode == 407
                    ? "代理服务器要求认证"
                    : $"代理服务器返回错误状态码: {statusCode} {statusMessage}";

                Trace.WriteLine(TraceCategory.NetworkingError, errorMessage);
                throw new IOException(errorMessage);
            }

            /// <summary>
            /// 读取一行响应数据
            /// </summary>
            private string ReadLine()
            {
                var builder = new StringBuilder(128);
                int b;
                bool cr = false;

                while ((b = Stream.ReadByte()) != -1)
                {
                    if (b == '\r')
                    {
                        cr = true;
                    }
                    else if (b == '\n' && cr)
                    {
                        break;
                    }
                    else
                    {
                        if (cr)
                        {
                            builder.Append('\r');
                            cr = false;
                        }
                        builder.Append((char)b);
                    }
                }

                return builder.ToString();
            }

        
        /// <summary>
        /// 销毁资源
        /// </summary>
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                try
                {
                    if (Stream != null)
                    {
                        Trace.WriteLine(TraceCategory.NetworkingData, "正在关闭HTTP代理连接");
                        Stream.Dispose();
                    }
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