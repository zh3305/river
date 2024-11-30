using River.Common;
using River.Internal;
using System;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace River
{
    /// <summary>
    /// 客户端流的基类，提供基本的网络流功能
    /// </summary>
    public abstract class ClientStream : SimpleNetworkStream
    {
        /// <summary>
        /// TCP客户端实例
        /// </summary>
        public TcpClient Client { get; private set; }

        /// <summary>
        /// 基础流对象
        /// </summary>
        protected Stream Stream { get; set; }

        /// <summary>
        /// 代理服务器主机名
        /// </summary>
        protected string ProxyHost { get; private set; }

        /// <summary>
        /// 代理服务器端口
        /// </summary>
        protected int ProxyPort { get; private set; }

        /// <summary>
        /// 代理服务器用户名
        /// </summary>
        protected string ProxyUsername { get; set; }

        /// <summary>
        /// 代理服务器密码
        /// </summary>
        protected string ProxyPassword { get; set; }

        /// <summary>
        /// 连接超时时间（毫秒）
        /// </summary>
        public int ConnectionTimeout { get; set; } = 4000;

        public override string ToString() => $"{GetType().Name} {Client?.Client?.RemoteEndPoint} {Stream}";

        /// <summary>
        /// 建立到目标主机的路由
        /// </summary>
        /// <param name="targetHost">目标主机名</param>
        /// <param name="targetPort">目标端口</param>
        /// <param name="proxyDns">是否使用代理进行DNS解析</param>
        public virtual void Route(string targetHost, int targetPort, bool? proxyDns = null)
        {
            if (string.IsNullOrEmpty(targetHost))
            {
                throw new ArgumentNullException(nameof(targetHost));
            }

            var uriBuilder = new UriBuilder("none", targetHost, targetPort);
            if (proxyDns.HasValue)
            {
                uriBuilder.Query = $"proxyDns={proxyDns.Value}";
            }
            Route(uriBuilder.Uri);
        }

        /// <summary>
        /// 建立到目标URI的路由
        /// </summary>
        public virtual void Route(Uri uri)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// 获取指定协议的默认端口
        /// </summary>
        protected virtual int GetDefaultPort(string scheme)
        {
            return scheme.ToLower() switch
            {
                "http" => 80,
                "https" => 443,
                "socks" => 1080,
                "socks4" => 1080,
                "socks5" => 1080,
                _ => -1
            };
        }

        /// <summary>
        /// 连接到新的套接字
        /// 支持格式：scheme://[username:password@]host:port
        /// 例如：socks5://username:password@proxy-server:1080
        /// </summary>
        public virtual void Plug(Uri uri)
        {
            if (uri is null)
            {
                throw new ArgumentNullException(nameof(uri));
            }

            if (Stream != null)
            {
                throw new InvalidOperationException("已经建立了连接");
            }

            // 解析认证信息
            ParseProxyCredentials(uri);

            // 设置代理服务器信息
            ProxyHost = uri.Host;
            ProxyPort = uri.Port == -1 ? GetDefaultPort(uri.Scheme) : uri.Port;

            if (ProxyPort == -1)
            {
                throw new ArgumentException($"无法确定协议 {uri.Scheme} 的默认端口");
            }

            try
            {
                // 创建TCP连接
                Client = Utils.WithTimeout(ClientFactory, (ProxyHost, ProxyPort), ConnectionTimeout);
                Client.Configure();
                Stream = Client.GetStream2();
            }
            catch (Exception ex)
            {
                Trace.Default.WriteLine(TraceCategory.NetworkingError, $"连接到代理服务器 {ProxyHost}:{ProxyPort} 失败: {ex.Message}");
                throw new IOException($"连接到代理服务器 {ProxyHost}:{ProxyPort} 失败: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// 从URI中解析代理认证信息
        /// </summary>
        protected virtual void ParseProxyCredentials(Uri uri)
        {
            ProxyUsername = null;
            ProxyPassword = null;

            if (!string.IsNullOrEmpty(uri.UserInfo))
            {
                var credentials = uri.UserInfo.Split(new[] { ':' }, 2);
                if (credentials.Length == 2)
                {
                    ProxyUsername = HttpUtility.UrlDecode(credentials[0]);
                    ProxyPassword = HttpUtility.UrlDecode(credentials[1]);
                }
            }
        }

        /// <summary>
        /// 使用现有的流进行连接
        /// </summary>
        public virtual void Plug(Uri uri, Stream stream)
        {
            if (Stream != null)
            {
                throw new InvalidOperationException("已经建立了连接");
            }

            if (uri != null)
            {
                ParseProxyCredentials(uri);
                ProxyHost = uri.Host;
                ProxyPort = uri.Port == -1 ? GetDefaultPort(uri.Scheme) : uri.Port;
            }

            Stream = stream;
        }

        /// <summary>
        /// 创建TCP客户端的工厂方法
        /// </summary>
        protected static TcpClient ClientFactory((string ProxyHost, int ProxyPort) p)
        {
            return TcpClientFactory.Create(p.ProxyHost, p.ProxyPort);
        }

        #region Stream 操作实现

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (buffer == null) throw new ArgumentNullException(nameof(buffer));

            var bytesRead = Stream.Read(buffer, offset, count);
            if (bytesRead <= 0) Close();

            StatService.Instance.MaxBufferUsage(offset + bytesRead, GetType().Name);
            return bytesRead;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (buffer == null) throw new ArgumentNullException(nameof(buffer));

            var stream = Stream;
            if (stream != null)
            {
                stream.Write(buffer, offset, count);
                stream.Flush();
            }
        }

        public override void Close()
        {
            base.Close();

            try
            {
                if (Client?.Client != null)
                {
                    Client.Client.Shutdown(SocketShutdown.Both);
                    Client = null;
                }
            }
            catch { }

            try
            {
                if (Stream != null)
                {
                    Stream.Close();
                    Stream = null;
                }
            }
            catch { }
        }

        public override IAsyncResult BeginRead(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
            => Stream.BeginRead(buffer, offset, count, callback, state);

        public override int EndRead(IAsyncResult asyncResult)
        {
            if (IsDisposed) return 0;
            return Stream.EndRead(asyncResult);
        }

        public override IAsyncResult BeginWrite(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
            => Stream.BeginWrite(buffer, offset, count, callback, state);

        public override void EndWrite(IAsyncResult asyncResult)
        {
            if (IsDisposed) return;
            Stream.EndWrite(asyncResult);
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => Stream.ReadAsync(buffer, offset, count, cancellationToken);

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => Stream.WriteAsync(buffer, offset, count, cancellationToken);

        #endregion
    }
}