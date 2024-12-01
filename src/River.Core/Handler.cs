using River.Common;
using River.Internal;
using System;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace River
{
    /// <summary>
    /// 处理服务器的传入连接
    /// 由服务器创建和拥有
    /// Handler 作为客户端的服务者，客户端是老板
    /// Handler 必须尽可能满足客户端需求，补偿客户端的所有错误，并对其保持优雅
    /// </summary>
    public abstract class Handler : IDisposable
    {
        // 日志追踪器
        protected static readonly Trace Trace = River.Trace.Default;

        // 定义常量
        private const int BUFFER_SIZE = 16 * 1024;
        private const int DEFAULT_TIMEOUT = 30000; // 30秒超时
        private const int THREAD_JOIN_TIMEOUT = 1000; // 线程Join超时时间

#if DEBUG
        private static readonly Encoding _utf8 = new UTF8Encoding(false, false);
#endif
        // 基础属性
        protected Stream Stream { get; private set; }
        protected byte[] _buffer = new byte[BUFFER_SIZE];
        protected byte[] _bufferTarget = new byte[BUFFER_SIZE];
        protected int _bufferReceivedCount;
        protected RiverServer Server { get; private set; }
        protected TcpClient Client { get; private set; }

        // 线程相关
        private Thread _sourceReaderThread;
        private Thread _targetReaderThread;
        private Stream _upstreamClient;
        private DestinationIdentifier _target;
        private readonly object _disposingSync = new object();

        // 状态标志
        private bool _isResigned;
        private bool _isReadHandshake = true;
        protected bool IsDisposed { get; private set; }
        private string _disposedComment;

        protected bool IsResigned
        {
            get => _isResigned;
            set
            {
                if (_targetReaderThread != null)
                {
                    throw new InvalidOperationException("无法在目标读取线程存在时注销Handler");
                }
                _isResigned = value;
            }
        }

        /// <summary>
        /// 源端口信息
        /// </summary>
        protected string Source => $"{Client?.GetHashCode():X4} {Client?.Client?.RemoteEndPoint}";

        /// <summary>
        /// 目标端口信息
        /// </summary>
        protected string Destination
        {
            get
            {
                if (_target != null)
                {
                    return $"{_target.Host}{_target.IPAddress}:{_target.Port}";
                }
                if (_upstreamClient is ClientStream cs)
                {
                    return cs?.Client?.Client?.RemoteEndPoint?.ToString();
                }
                return null;
            }
        }

        /// <summary>
        /// 构造函数
        /// </summary>
        public Handler()
        {
            ObjectTracker.Default.Register(this, 10, true);
        }

        /// <summary>
        /// 带参数的构造函数
        /// </summary>
        public Handler(RiverServer server, TcpClient client) : this()
        {
            Init(server, client);
        }

        /// <summary>
        /// 初始化处理程序
        /// </summary>
        public void Init(RiverServer server, TcpClient client, Stream stream = null)
        {
            Server = server ?? throw new ArgumentNullException(nameof(server));
            Client = client ?? throw new ArgumentNullException(nameof(client));

            // 禁用 Nagle 算法以提高性能
            Client.Client.NoDelay = true;

            // 设置超时时间
            Client.ReceiveTimeout = DEFAULT_TIMEOUT;
            Client.SendTimeout = DEFAULT_TIMEOUT;

            Stream = WrapStream(stream ?? Client.GetStream2());

            BeginSourceReader();
            ReadMoreHandshake();
        }

        /// <summary>
        /// 包装流，可被子类重写以添加额外的流处理
        /// </summary>
        protected virtual Stream WrapStream(Stream stream) => stream;

        /// <summary>
        /// 握手起始位置，可被子类重写以优化HTTP头部处理
        /// </summary>
        protected virtual int HandshakeStartPos => 0;

        /// <summary>
        /// 开始数据流传输
        /// </summary>
        protected void BeginStreaming()
        {
            BeginReadSource();
            BeginReadTarget();
        }

        /// <summary>
        /// 处理握手数据
        /// </summary>
        protected abstract void HandshakeHandler();

        /// <summary>
        /// 确保读取了指定数量的数据
        /// </summary>
        protected bool EnsureReaded(int readed)
        {
            if (_bufferReceivedCount < readed)
            {
                ReadMoreHandshake();
                return false;
            }
            return true;
        }

        /// <summary>
        /// 读取更多握手数据
        /// </summary>
        protected void ReadMoreHandshake()
        {
            // 实现在SourceReaderThreadWorker中的循环读取中
        }

        /// <summary>
        /// 开始源数据读取
        /// </summary>
        protected void BeginReadSource()
        {
            if (IsDisposed)
                throw new ObjectDisposedException(nameof(Handler));

            Profiling.Stamp(TraceCategory.Misc, "开始读取源数据...");

            _isReadHandshake = false;
            _bufferReceivedCount = 0;
        }

        /// <summary>
        /// 源数据读取线程工作方法
        /// </summary>
        private void SourceReaderThreadWorker()
        {
            Trace.WriteLine(TraceCategory.ObjectLive, $"启动线程 {Thread.CurrentThread.Name}");
            try
            {
                while (!IsDisposed)
                {
                    // 优化：仅在有可用数据时才读取
                    if (Client.Client != null && Client.Available > 0)
                    {
                        var bytesRead = Stream.Read(_buffer, _bufferReceivedCount, _buffer.Length - _bufferReceivedCount);

                        if (!SourceReceived(bytesRead))
                        {
                            break;
                        }
                    }
                    else
                    {
                        // 避免CPU空转
                        Thread.Sleep(1);
                    }
                }
            }
            catch (Exception ex) when (ex.IsConnectionClosing())
            {
                // 正常的连接关闭，无需特殊处理
            }
            catch (Exception ex)
            {
                Trace.TraceError($"源数据读取错误: {ex}");
            }
            finally
            {
                Dispose();
                Trace.WriteLine(TraceCategory.ObjectLive, $"关闭线程 {Thread.CurrentThread.Name}");
            }
        }

        /// <summary>
        /// 处理接收到的源数据
        /// </summary>
        private bool SourceReceived(int bytesRead)
        {
            if (IsDisposed || bytesRead <= 0)
            {
                Dispose();
                return false;
            }

            try
            {
                Profiling.Stamp(TraceCategory.Misc, "处理源数据...");
                StatService.Instance.MaxBufferUsage(bytesRead, $"{GetType().Name} src");

                if (_isReadHandshake)
                {
                    _bufferReceivedCount += bytesRead;

#if DEBUG
                    Trace.TraceError($"{Source} 握手... {_bufferReceivedCount} 字节, " +
                        $"首字节 0x{_buffer[HandshakeStartPos]:X2} " +
                        $"{_utf8.GetString(_buffer, HandshakeStartPos, 1)} " +
                        $"{Preview(_buffer, HandshakeStartPos, _bufferReceivedCount)}");
#endif
                    HandshakeHandler();
                }
                else
                { // 添加空检查
                    if (_upstreamClient == null)
                    {
                        Trace.TraceError("上游客户端未初始化");
                        Dispose();
                        return false;
                    }
                    _upstreamClient.Write(_buffer, 0, bytesRead);
                }

                Profiling.Stamp(TraceCategory.Misc, "源数据处理完成");
                return true;
            }
            catch (Exception ex)
            {
                Trace.TraceError($"处理源数据时出错: {ex.Message}");
                Dispose();
                return false;
            }
        }

        /// <summary>
        /// 开始目标数据读取线程
        /// </summary>
        protected void BeginReadTarget()
        {
            if (IsDisposed)
                throw new ObjectDisposedException(nameof(Handler));

            Profiling.Stamp(TraceCategory.Misc, "开始读取目标数据...");

            _targetReaderThread = new Thread(TargetReaderThreadWorker)
            {
                IsBackground = true,
                Name = $"Target Reader: {GetType().Name} {Destination}"
            };

            _targetReaderThread.Start();
            ObjectTracker.Default.Register(_targetReaderThread);
        }

        /// <summary>
        /// 目标数据读取线程工作方法
        /// </summary>
        private void TargetReaderThreadWorker()
        {
            Trace.WriteLine(TraceCategory.ObjectLive,
                $"启动线程 {Thread.CurrentThread.ManagedThreadId} {Thread.CurrentThread.Name}");

            try
            {
                while (!IsDisposed)
                {
                    var bytesRead = _upstreamClient.Read(_bufferTarget, 0, _bufferTarget.Length);
                    if (!TargetReceived(bytesRead))
                    {
                        break;
                    }
                }
            }
            catch (Exception ex) when (ex.IsConnectionClosing())
            {
                // 正常的连接关闭
            }
            catch (Exception ex)
            {
                Trace.TraceError($"目标数据读取错误: {ex}");
            }
            finally
            {
                Dispose();
                Trace.WriteLine(TraceCategory.ObjectLive,
                    $"关闭线程 {Thread.CurrentThread.ManagedThreadId} {Thread.CurrentThread.Name}");
            }
        }

        /// <summary>
        /// 处理接收到的目标数据
        /// </summary>
        private bool TargetReceived(int bytesRead)
        {
            if (IsDisposed || bytesRead <= 0)
            {
                Dispose();
                return false;
            }

            try
            {
                StatService.Instance.MaxBufferUsage(bytesRead, $"{GetType().Name} trg");

                Trace.WriteLine(TraceCategory.NetworkingData,
                    $"{Source} <<< {bytesRead} 字节 <<< {Destination} " +
                    $"{Preview(_bufferTarget, 0, bytesRead)}");

                Stream.Write(_bufferTarget, 0, bytesRead);
                return true;
            }
            catch (Exception ex)
            {
                Trace.TraceError($"处理目标数据时出错: {ex.Message}");
                Dispose();
                return false;
            }
        }

        /// <summary>
        /// 预览数据内容
        /// </summary>
        private static string Preview(byte[] buf, int pos, int cnt)
        {
#if DEBUG
            var previewLength = Math.Min(cnt, 32);
            var chars = _utf8.GetChars(buf, pos, previewLength);

            for (var i = 0; i < chars.Length; i++)
            {
                if (chars[i] < 32)
                {
                    chars[i] = '?';
                }
            }

            return new string(chars) + (previewLength < cnt ? "..." : "");
#else
                    return string.Empty;
#endif
        }

        /// <summary>
        /// 向目标发送数据
        /// </summary>
        protected void SendForward(byte[] buf, int pos = 0, int cnt = -1)
        {
            if (buf == null)
                throw new ArgumentNullException(nameof(buf));

            if (cnt == -1)
                cnt = buf.Length;

            try
            {
                Trace.WriteLine(TraceCategory.NetworkingData,
                    $"{Source} >>> 发送 {cnt} 字节 >>> {Destination} {Preview(buf, pos, cnt)}");

                _upstreamClient.Write(buf, pos, cnt);
            }
            catch (Exception ex)
            {
                Trace.TraceError($"发送数据时出错: {ex.Message}");
                Dispose();
                throw;
            }
        }

        /// <summary>
        /// 建立上游连接
        /// </summary>
        protected void EstablishUpstream(DestinationIdentifier target)
        {
            if (IsDisposed) throw new ObjectDisposedException(nameof(Handler));
            if (target == null) throw new ArgumentNullException(nameof(target));

            Profiling.Stamp(TraceCategory.Networking, "建立上游连接...");

            try
            {
                _target = target;
                Trace.WriteLine(TraceCategory.Networking, $"{Source} 路由到 {Destination}");

                var streamOverride = Resolver.GetStreamOverride(target);
                if (streamOverride != null)
                {
                    _upstreamClient = streamOverride;
                    return;
                }

                // 处理代理链
                foreach (var proxy in Server.Chain)
                {
                    var clientType = Resolver.GetClientType(proxy.Uri);
                    var clientStream = (ClientStream)Activator.CreateInstance(clientType);

                    if (_upstreamClient == null)
                    {
                        clientStream.Plug(proxy.Uri);
                    }
                    else
                    {
                        ((ClientStream)_upstreamClient).Route(proxy.Uri);
                        clientStream.Plug(proxy.Uri, (ClientStream)_upstreamClient);
                    }
                    _upstreamClient = clientStream;
                }

                // 设置最终目标
                if (_upstreamClient != null)
                {
                    var client = (ClientStream)_upstreamClient;
                    client.Route(target.Host ?? target.IPAddress.ToString(), target.Port);
                }
                else
                {
                    // 直接连接
                    _upstreamClient = new NullClientStream();
                    ((ClientStream)_upstreamClient).Plug(
                        target.Host ?? target.IPAddress.ToString(),
                        target.Port
                    );
                }
            }
            catch
            {
                Dispose();
                throw;
            }

            Profiling.Stamp(TraceCategory.Networking, "连接已建立");
        }

        public override string ToString()
        {
            var baseName = base.ToString();
            return $"{baseName} {Source}<=>{Destination} " +
                   $"{(IsDisposed ? "已释放" + _disposedComment : "未释放")}";
        }
        #region IDisposable 实现

        public void Dispose()
        {
            Dispose(true);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposing || IsDisposed) return;

            lock (_disposingSync)
            {
                if (IsDisposed) return;

                try
                {
                    HandleResignedDisposal();
                    DisposeResources();
                }
                finally
                {
                    IsDisposed = true;
                    Trace.WriteLine(TraceCategory.ObjectLive,
                        $"{Client?.GetHashCode():X4} Handler已释放. {_disposedComment}");
                }
            }
        }

        /// <summary>
        /// 处理已注销Handler的释放
        /// </summary>
        private void HandleResignedDisposal()
        {
            if (!_isResigned) return;

            _disposedComment += " 已注销";

            if (Thread.CurrentThread != _sourceReaderThread)
            {
                try
                {
                    // 中止源读取线程
                    _sourceReaderThread?.Abort();
                    Trace.WriteLine(TraceCategory.ObjectLive, "注销 - 已中止");
                }
                catch (Exception ex)
                {
                    Trace.TraceError($"中止源读取线程时出错: {ex.Message}");
                }

                try
                {
                    _sourceReaderThread?.Join(THREAD_JOIN_TIMEOUT);
                    Trace.WriteLine(TraceCategory.ObjectLive, "注销 - 已加入");
                }
                catch (Exception ex)
                {
                    Trace.TraceError($"等待源读取线程时出错: {ex.Message}");
                }
            }
            else
            {
                Trace.WriteLine(TraceCategory.ObjectLive, "注销 - 来自当前线程");
            }

            _sourceReaderThread = null;
        }

        /// <summary>
        /// 释放所有资源
        /// </summary>
        private void DisposeResources()
        {
            try
            {
                // 关闭并释放上游客户端
                if (_upstreamClient != null)
                {
                    _upstreamClient.Close();
                    _upstreamClient.Dispose();
                    Trace.WriteLine(TraceCategory.ObjectLive,
                        $"{Client?.GetHashCode():X4} 关闭Handler - 上游客户端已关闭");
                }
            }
            catch (Exception ex)
            {
                Trace.TraceError($"关闭上游客户端时出错: {ex}");
            }
            finally
            {
                _upstreamClient = null;
            }

            try
            {
                // 等待目标读取线程结束
                if (_targetReaderThread != null)
                {
                    _targetReaderThread.Join(THREAD_JOIN_TIMEOUT);
                    Trace.WriteLine(TraceCategory.ObjectLive,
                        $"{Client?.GetHashCode():X4} 关闭Handler - 目标线程已加入到 {_targetReaderThread?.ManagedThreadId}");
                }
            }
            catch (Exception ex)
            {
                Trace.TraceError($"等待目标读取线程时出错: {ex}");
            }

            try
            {
                // 关闭客户端连接
                if (Client?.Client != null)
                {
                    // 优雅地关闭TCP连接
                    Client.Client.Shutdown(SocketShutdown.Both);
                    Client.Close();
                }
            }
            catch (Exception ex)
            {
                Trace.TraceError($"关闭客户端连接时出错: {ex}");
            }

            try
            {
                // 关闭流
                Stream?.Close();
            }
            catch (Exception ex)
            {
                Trace.TraceError($"关闭流时出错: {ex}");
            }

            // 等待源读取线程结束
            try
            {
                _sourceReaderThread?.Join(THREAD_JOIN_TIMEOUT);
            }
            catch (Exception ex)
            {
                Trace.TraceError($"等待源读取线程时出错: {ex}");
            }
        }

        #endregion

        #region 辅助方法

        /// <summary>
        /// 启动源数据读取线程
        /// </summary>
        private void BeginSourceReader()
        {
            if (IsDisposed)
                throw new ObjectDisposedException(nameof(Handler));

            if (_sourceReaderThread != null)
                throw new InvalidOperationException("源读取线程已存在");

            _sourceReaderThread = new Thread(SourceReaderThreadWorker)
            {
                IsBackground = true,
                Name = $"Source Reader: {GetType().Name} {Source}"
            };

            ObjectTracker.Default.Register(_sourceReaderThread);
            _sourceReaderThread.Start();
        }

        #endregion
    }
}