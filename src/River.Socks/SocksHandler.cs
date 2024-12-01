using System;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Collections.Generic;

namespace River.Socks
{
    /// <summary>
    /// SOCKS 协议处理器
    /// 支持 SOCKS4、SOCKS4a、SOCKS5 和 HTTP 代理协议
    /// </summary>
    public class SocksHandler : Handler
    {
        #region 常量定义

        // UTF8 编码器，禁用 BOM 和异常检查以提升性能
        private static readonly Encoding _utf = new UTF8Encoding(false, false);

        // SOCKS 协议版本标识
        private const byte SOCKS4_VERSION = 0x04;
        private const byte SOCKS5_VERSION = 0x05;

        // SOCKS 命令类型
        private const byte CMD_CONNECT = 0x01;

        // SOCKS5 地址类型
        private const byte ADDR_TYPE_IPV4 = 0x01;
        private const byte ADDR_TYPE_DOMAIN = 0x03;
        private const byte ADDR_TYPE_IPV6 = 0x04;

        #endregion

        #region 预分配缓存区域

        // SOCKS4 响应状态码偏移量
        private const int SOCKS4_RESPONSE_GRANTED = 0;   // 请求允许
        private const int SOCKS4_RESPONSE_REJECTED = 8;  // 请求拒绝

        // SOCKS5 响应状态码偏移量
        private const int SOCKS5_RESPONSE_APPROVED = 16; // 无需认证
        private static readonly (int offset, int length, int statusByte) SOCKS5_RESPONSE_REJECTED = (18, 10, 1);

        // 预分配的静态响应数据
        private static readonly byte[] _staticResponses = new byte[]
        {
            // SOCKS4 允许响应 (8字节)
            0x00, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // SOCKS4 拒绝响应 (8字节)
            0x00, 0x5B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // SOCKS5 认证响应 - 无需认证 (2字节)
            0x05, 0x00,
            // SOCKS5 请求响应模板 (10字节)
            0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        // 预分配的临时缓冲区
        private readonly byte[] _ipv4Buffer = new byte[4];
        private readonly byte[] _ipv6Buffer = new byte[16];

        #endregion

        #region 连接状态字段

        private IPAddress _targetAddress;        // 目标IP地址
        private string _targetHostname;          // 目标域名
        private int _targetPort;                 // 目标端口
        private int _processedBytes;             // 已处理的字节数
        private bool _isAuthCompleted;           // 是否完成认证

        #endregion

        /// <summary>
        /// 处理代理协议握手阶段
        /// </summary>
        protected override void HandshakeHandler()
        {
            Profiling.Stamp(TraceCategory.NetworkingData, "开始处理握手...");

            // 确保至少读取了1个字节用于判断协议版本
            if (EnsureReaded(1))
            {
                // 根据第一个字节判断协议类型
                switch (_buffer[HandshakeStartPos])
                {
                    case SOCKS4_VERSION:  // SOCKS4 协议
                        HandleSocks4Handshake();
                        break;

                    case SOCKS5_VERSION:  // SOCKS5 协议
                        HandleSocks5Handshake();
                        break;

                    case (byte)'P': // HTTP PUT/POST/PATCH
                    case (byte)'G': // HTTP GET
                    case (byte)'D': // HTTP DELETE
                    case (byte)'C': // HTTP CONNECT
                    case (byte)'H': // HTTP HEAD
                    case (byte)'T': // HTTP TRACE
                    case (byte)'O': // HTTP OPTIONS
                        HandleHttpProxy();
                        break;

                    default:
                        throw new NotSupportedException($"不支持的协议类型。首字节: {_buffer[HandshakeStartPos]:X2} {_utf.GetString(_buffer, HandshakeStartPos, 1)}");
                }
            }
        }

        /// <summary>
        /// 处理 SOCKS4/4a 协议握手
        /// </summary>
        private void HandleSocks4Handshake()
        {
            // 确保读取了完整的 SOCKS4 请求头(8字节)
            if (!EnsureReaded(8)) return;

            var offset = HandshakeStartPos + 1;

            // 仅支持 CONNECT 命令(0x01)
            if (_buffer[offset++] != CMD_CONNECT)
            {
                throw new NotSupportedException("仅支持 CONNECT 命令");
            }

            // 解析端口号(2字节)
            _targetPort = (_buffer[offset++] << 8) | _buffer[offset++];

            // 解析IP地址(4字节)
            if (_buffer[offset] != 0) // 标准 SOCKS4 模式
            {
                uint ipBytes = BitConverter.ToUInt32(_buffer, offset);
                offset += 4;
                _targetAddress = new IPAddress(ipBytes);
            }
            else // SOCKS4a 模式(支持域名)
            {
                offset += 4; // 跳过无效IP地址
            }

            // 跳过用户ID字段
            offset = SkipNullTerminatedString(offset);

            // SOCKS4a 模式下解析域名
            if (_targetAddress == null)
            {
                _targetHostname = ReadNullTerminatedString(ref offset);
                if (string.IsNullOrEmpty(_targetHostname))
                {
                    throw new Exception("域名解析失败");
                }
            }

            try
            {
                // 建立到目标服务器的连接
                EstablishUpstream(new DestinationIdentifier
                {
                    Host = _targetHostname,
                    IPAddress = _targetAddress,
                    Port = _targetPort
                });

                // 转发剩余数据
                ForwardRemainingData(offset);

                // 发送成功响应
                Stream.Write(_staticResponses, SOCKS4_RESPONSE_GRANTED, 8);
                BeginStreaming();
            }
            catch (Exception ex)
            {
                HandleConnectionError(ex, "SOCKS4");
            }
        }

        /// <summary>
        /// 处理 SOCKS5 协议握手
        /// </summary>
        private void HandleSocks5Handshake()
        {
            // 第一阶段: 认证方法协商
            if (!_isAuthCompleted)
            {
                HandleSocks5Auth();
                return;
            }

            // 第二阶段: 连接请求
            if (!EnsureReaded(_processedBytes + 4)) return;

            var offset = _processedBytes;

            // 验证协议版本和命令
            if (_buffer[offset++] != SOCKS5_VERSION)
                throw new Exception("需要 SOCKS5 请求");
            if (_buffer[offset++] != CMD_CONNECT)
                throw new Exception("仅支持 CONNECT 命令");

            offset++; // 跳过保留字节

            // 解析地址类型和地址
            byte addressType = _buffer[offset++];
            bool addressProcessed = false;

            switch (addressType)
            {
                case ADDR_TYPE_IPV4:
                    addressProcessed = HandleSocks5Ipv4Address(ref offset);
                    break;

                case ADDR_TYPE_DOMAIN:
                    addressProcessed = HandleSocks5DomainAddress(ref offset);
                    break;

                case ADDR_TYPE_IPV6:
                    addressProcessed = HandleSocks5Ipv6Address(ref offset);
                    break;

                default:
                    throw new Exception("不支持的地址类型");
            }

            if (addressProcessed && EnsureReaded(offset + 2))
            {
                _targetPort = (_buffer[offset++] << 8) | _buffer[offset++];
                EstablishSocks5Connection(offset);
            }
        }

        /// <summary>
        /// 处理 SOCKS5 认证阶段
        /// </summary>
        private void HandleSocks5Auth()
        {
            if (!EnsureReaded(2)) return;

            byte methodCount = _buffer[HandshakeStartPos + 1];
            if (!EnsureReaded(2 + methodCount)) return;

            // 检查是否支持无认证方式
            bool supportsNoAuth = false;
            for (int i = 0; i < methodCount; i++)
            {
                if (_buffer[HandshakeStartPos + 2 + i] == 0x00)
                {
                    supportsNoAuth = true;
                    break;
                }
            }

            if (!supportsNoAuth)
            {
                throw new Exception("客户端必须支持无认证模式");
            }

            _processedBytes = 2 + methodCount;
            _isAuthCompleted = true;

            // 发送无需认证的响应
            Stream.Write(_staticResponses, SOCKS5_RESPONSE_APPROVED, 2);
            Stream.Flush();
        }

        /// <summary>
        /// 处理 SOCKS5 IPv4 地址
        /// </summary>
        private bool HandleSocks5Ipv4Address(ref int offset)
        {
            if (!EnsureReaded(offset + 4)) return false;

            Array.Copy(_buffer, offset, _ipv4Buffer, 0, 4);
            _targetAddress = new IPAddress(_ipv4Buffer);
            offset += 4;
            return true;
        }

        /// <summary>
        /// 处理 SOCKS5 域名地址
        /// </summary>
        private bool HandleSocks5DomainAddress(ref int offset)
        {
            if (!EnsureReaded(offset + 1)) return false;

            byte domainLength = _buffer[offset++];
            if (!EnsureReaded(offset + domainLength)) return false;

            _targetHostname = _utf.GetString(_buffer, offset, domainLength);
            offset += domainLength;
            return true;
        }

        /// <summary>
        /// 处理 SOCKS5 IPv6 地址
        /// </summary>
        private bool HandleSocks5Ipv6Address(ref int offset)
        {
            if (!EnsureReaded(offset + 16)) return false;

            Array.Copy(_buffer, offset, _ipv6Buffer, 0, 16);
            _targetAddress = new IPAddress(_ipv6Buffer);
            offset += 16;
            return true;
        }

        /// <summary>
        /// 建立 SOCKS5 连接
        /// </summary>
        private void EstablishSocks5Connection(int offset)
        {
            try
            {
                EstablishUpstream(new DestinationIdentifier
                {
                    Host = _targetHostname,
                    IPAddress = _targetAddress,
                    Port = _targetPort
                });

                ForwardRemainingData(offset);

                // 发送成功响应
                var response = new byte[SOCKS5_RESPONSE_REJECTED.length];
                Array.Copy(_staticResponses, SOCKS5_RESPONSE_REJECTED.offset,
                    response, 0, response.Length);
                response[SOCKS5_RESPONSE_REJECTED.statusByte] = 0x00;

                if (!IsDisposed)
                {
                    Stream.Write(response, 0, response.Length);
                    Stream.Flush();
                }

                BeginStreaming();
            }
            catch (Exception ex)
            {
                HandleConnectionError(ex, "SOCKS5");
            }
        }
        /// <summary>
        /// 处理 HTTP 代理请求
        /// </summary>
        private void HandleHttpProxy()
        {
            // 解析 HTTP 头部
            string headerString;
            int headerEnd;
            var headers = HttpUtils.TryParseHttpHeader(_buffer, HandshakeStartPos,
                _bufferReceivedCount - HandshakeStartPos, out headerEnd, out headerString);

            // 如果头部解析未完成，继续读取更多数据
            if (headers == null)
            {
                ReadMoreHandshake();
                return;
            }

            try
            {
                // 从头部或URL解析目标地址
                ParseHttpTargetAddress(headers);

                // 检查代理循环
                bool isProxyLoop = headers.ContainsKey(_randomHeader.Value);
                if (isProxyLoop)
                {
                    _targetHostname = "_river"; // 内部标记，终止循环
                }

                // 建立到目标服务器的连接
                EstablishUpstream(new DestinationIdentifier
                {
                    Host = _targetHostname,
                    Port = _targetPort
                });

                // 根据请求方法处理
                if (headers["_verb"] == "CONNECT")
                {
                    // 发送连接成功响应
                    byte[] response = _utf.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n");
                    Stream.Write(response, 0, response.Length);
                    Stream.Flush();

                    // 转发剩余数据
                    if (headerEnd < _bufferReceivedCount)
                    {
                        Trace.WriteLine(TraceCategory.NetworkingData, $"转发剩余数据: {_bufferReceivedCount - headerEnd} 字节");
                        SendForward(_buffer, headerEnd, _bufferReceivedCount - headerEnd);
                    }
                }
                else
                {
                    // 普通 HTTP 请求处理
                    if (!isProxyLoop && (_bufferReceivedCount == headerEnd || Interlocked.Increment(ref _requestCounter) % 50 == 0))
                    {
                        // 添加循环检测头部
                        string extraHeader = _randomHeaderLine.Value;
                        int insertPosition = headerEnd - 2; // 在末尾\r\n之前插入

                        // 如果有正文，需要移动数据
                        if (_bufferReceivedCount > headerEnd)
                        {
                            Array.Copy(_buffer, headerEnd, _buffer,
                                headerEnd + extraHeader.Length, _bufferReceivedCount - headerEnd);
                        }

                        // 插入新头部
                        byte[] headerBytes = _utf.GetBytes(extraHeader + "\r\n");
                        Array.Copy(headerBytes, 0, _buffer, insertPosition, headerBytes.Length);
                        _bufferReceivedCount += headerBytes.Length;
                    }

                    // 转发整个请求
                    SendForward(_buffer, HandshakeStartPos, _bufferReceivedCount - HandshakeStartPos);
                }

                BeginStreaming();
            }
            catch (Exception ex)
            {
                // 错误处理
                Trace.WriteLine(TraceCategory.NetworkingError, $"HTTP代理错误: {ex.Message}");

                // 发送错误响应
                string errorResponse =
                    "HTTP/1.1 502 Bad Gateway\r\n" +
                    "Content-Type: text/plain\r\n" +
                    "Connection: close\r\n\r\n" +
                    "连接目标服务器失败";
                byte[] errorBytes = _utf.GetBytes(errorResponse);

                if (!IsDisposed)
                {
                    Stream.Write(errorBytes, 0, errorBytes.Length);
                    Stream.Flush();
                }

                Dispose();
            }
        }

        /// <summary>
        /// 跳过以null结尾的字符串
        /// </summary>
        private int SkipNullTerminatedString(int offset)
        {
            while (offset < _buffer.Length && _buffer[offset] != 0) offset++;
            return offset + 1;
        }

        /// <summary>
        /// 读取以null结尾的字符串
        /// </summary>
        private string ReadNullTerminatedString(ref int offset)
        {
            int start = offset;
            while (offset < _buffer.Length && _buffer[offset] != 0) offset++;

            if (offset >= _buffer.Length) return null;

            string result = _utf.GetString(_buffer, start, offset - start);
            offset++; // 跳过null终止符
            return result;
        }

        /// <summary>
        /// 转发剩余数据
        /// </summary>
        private void ForwardRemainingData(int offset)
        {
            if (offset < _bufferReceivedCount)
            {
                Trace.WriteLine(TraceCategory.NetworkingData, $"转发剩余数据: {_bufferReceivedCount - offset} 字节");
                SendForward(_buffer, offset, _bufferReceivedCount - offset);
            }
        }

        /// <summary>
        /// 从HTTP头部解析目标地址
        /// </summary>
        private void ParseHttpTargetAddress(IDictionary<string, string> headers)
        {
            // 尝试从Host头部获取地址
            if (headers.TryGetValue("HOST", out string hostHeader))
            {
                ParseHostHeader(hostHeader);
            }
            else // 从URL中获取地址
            {
                headers.TryGetValue("_url_host", out string host);
                headers.TryGetValue("_url_port", out string port);

                _targetHostname = host;
                _targetPort = string.IsNullOrEmpty(port) ? 80 : int.Parse(port, CultureInfo.InvariantCulture);
            }
        }

        /// <summary>
        /// 解析Host头部
        /// </summary>
        private void ParseHostHeader(string hostHeader)
        {
            int colonIndex = hostHeader.LastIndexOf(':');
            if (colonIndex > 0)
            {
                _targetHostname = hostHeader.Substring(0, colonIndex);
                _targetPort = int.Parse(hostHeader.Substring(colonIndex + 1), CultureInfo.InvariantCulture);
            }
            else
            {
                _targetHostname = hostHeader;
                _targetPort = 80; // 默认HTTP端口
            }
        }

        /// <summary>
        /// 检查代理循环
        /// </summary>
        private bool CheckProxyLoop(Dictionary<string, string> headers)
        {
            if (headers.ContainsKey(_randomHeader.Value))
            {
                _targetHostname = "_river"; // 内部标记，终止循环
                return true;
            }
            return false;
        }

        /// <summary>
        /// 处理HTTP CONNECT方法
        /// </summary>
        private void HandleHttpConnect(int headerEnd)
        {
            // 发送连接成功响应
            byte[] response = _utf.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n");
            Stream.Write(response, 0, response.Length);
            Stream.Flush();

            // 转发剩余数据
            ForwardRemainingData(headerEnd);
        }

        /// <summary>
        /// 处理HTTP转发请求
        /// </summary>
        private void HandleHttpForward(Dictionary<string, string> headers, int headerEnd, bool isProxyLoop)
        {
            // 检查是否需要添加循环检测头
            if (!isProxyLoop && ShouldAddLoopDetectionHeader())
            {
                InsertLoopDetectionHeader(headerEnd);
            }
            else
            {
                SendForward(_buffer, HandshakeStartPos, _bufferReceivedCount);
            }
        }

        /// <summary>
        /// 是否应该添加循环检测头
        /// </summary>
        private bool ShouldAddLoopDetectionHeader()
        {
            return _bufferReceivedCount == _processedBytes ||
                   Interlocked.Increment(ref _requestCounter) % 50 == 0;
        }

        /// <summary>
        /// 插入循环检测头
        /// </summary>
        private void InsertLoopDetectionHeader(int headerEnd)
        {
            string extraHeader = _randomHeaderLine.Value;
            int insertPosition = HandshakeStartPos + headerEnd - 2; // 在末尾\r\n之前插入

            // 如果有正文，需要移动数据
            if (_bufferReceivedCount > headerEnd)
            {
                int bodyLength = _bufferReceivedCount - headerEnd;
                Array.Copy(_buffer, headerEnd, _buffer,
                    headerEnd + extraHeader.Length, bodyLength);
            }

            // 插入新头部
            byte[] headerBytes = _utf.GetBytes(extraHeader + "\r\n");
            Array.Copy(headerBytes, 0, _buffer, insertPosition, headerBytes.Length);
            _bufferReceivedCount += headerBytes.Length;
        }

        /// <summary>
        /// 处理连接错误
        /// </summary>
        private void HandleConnectionError(Exception ex, string protocolType)
        {
            Trace.WriteLine(TraceCategory.NetworkingError,
                $"{protocolType}协议处理错误: {ex.Message}");

            // 根据协议类型发送错误响应
            switch (protocolType)
            {
                case "SOCKS4":
                    Stream.Write(_staticResponses, SOCKS4_RESPONSE_REJECTED, 8);
                    break;
                case "SOCKS5":
                    var response = new byte[SOCKS5_RESPONSE_REJECTED.length];
                    Array.Copy(_staticResponses, SOCKS5_RESPONSE_REJECTED.offset,
                        response, 0, response.Length);
                    response[SOCKS5_RESPONSE_REJECTED.statusByte] = 0x01; // 连接失败
                    Stream.Write(response, 0, response.Length);
                    break;
                case "HTTP":
                    string errorResponse =
                        "HTTP/1.1 502 Bad Gateway\r\n" +
                        "Content-Type: text/plain\r\n" +
                        "Connection: close\r\n\r\n" +
                        "连接目标服务器失败";
                    byte[] errorBytes = _utf.GetBytes(errorResponse);
                    Stream.Write(errorBytes, 0, errorBytes.Length);
                    break;
            }

            Stream.Flush();
            Dispose();
        }

        #region 静态工具方法和字段

        // 随机数生成器
        private static readonly Random _random = new Random();

        // 请求计数器 - 用于循环检测
        private static int _requestCounter;

        // 随机头部名称和完整头部行 - 延迟初始化
        private static readonly Lazy<string> _randomHeader =
            new Lazy<string>(GenerateRandomHeaderName);
        private static readonly Lazy<string> _randomHeaderLine =
            new Lazy<string>(() => $"{_randomHeader.Value}: {GenerateRandomHeaderName()}");

        /// <summary>
        /// 生成随机头部名称
        /// </summary>
        private static string GenerateRandomHeaderName()
        {
            var length = _random.Next(5, 10);
            var chars = new char[length];
            for (var i = 0; i < length; i++)
            {
                chars[i] = (char)(_random.Next(26) + 'a');
            }
            return new string(chars);
        }

        #endregion
    }
}