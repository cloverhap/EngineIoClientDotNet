using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using NSspi;
using NSspi.Contexts;
using NSspi.Credentials;
using SuperSocket.ClientEngine;

namespace SuperSocket.ClientEngine.Proxy.EngineIo
{
    public class HttpConnectProxy : ProxyConnectorBase
    {
        class ConnectContext
        {
            public Socket Socket { get; set; }

            public SearchMarkState<byte> SearchState { get; set; }
        }

        private const string m_RequestTemplate = "CONNECT {3}:{1} HTTP/1.1\r\nHost: {0}:{1}\r\nProxy-Connection: Keep-Alive\r\n{2}\r\n";

        private const string m_ResponsePrefix = "HTTP/1.1";
        private const char m_Space = ' ';

        private static byte[] m_LineSeparator;

        static HttpConnectProxy()
        {
            m_LineSeparator = ASCIIEncoding.GetBytes("\r\n\r\n");
        }

        private int m_ReceiveBufferSize;
        private int m_StatusCode;
        private string m_HostPrefix;
        private string m_AuthProtocol;
        private string m_ServerAuthChallenge;
        private ClientCurrentCredential m_ClientCred;
        private ClientContext m_Client;
        private byte[] m_ClientToken;
        private EndPoint m_TargetEndPoint;

#if SILVERLIGHT && !WINDOWS_PHONE
        public HttpConnectProxy(EndPoint proxyEndPoint, SocketClientAccessPolicyProtocol clientAccessPolicyProtocol)
            : this(proxyEndPoint, clientAccessPolicyProtocol, 128)
        {

        }

        public HttpConnectProxy(EndPoint proxyEndPoint, SocketClientAccessPolicyProtocol clientAccessPolicyProtocol, int receiveBufferSize)
            : base(proxyEndPoint, clientAccessPolicyProtocol)
        {
            m_ReceiveBufferSize = receiveBufferSize;
        }
#else
        public HttpConnectProxy(EndPoint proxyEndPoint)
            : this(proxyEndPoint, 128, null)
        {

        }

        public HttpConnectProxy(EndPoint proxyEndPoint, string targetHostName)
            : this(proxyEndPoint, 128, targetHostName)
        {

        }

        public HttpConnectProxy(EndPoint proxyEndPoint, int receiveBufferSize, string targetHostName)
            : base(proxyEndPoint, targetHostName)
        {
            m_ReceiveBufferSize = receiveBufferSize;
        }
#endif

        public override void Connect(EndPoint remoteEndPoint)
        {
            if (remoteEndPoint == null)
                throw new ArgumentNullException("remoteEndPoint");

            if (!(remoteEndPoint is IPEndPoint || remoteEndPoint is DnsEndPoint))
                throw new ArgumentException("remoteEndPoint must be IPEndPoint or DnsEndPoint", "remoteEndPoint");

            try
            {
#if SILVERLIGHT && !WINDOWS_PHONE
                ProxyEndPoint.ConnectAsync(ClientAccessPolicyProtocol, ProcessConnect, remoteEndPoint);
#elif WINDOWS_PHONE
                ProxyEndPoint.ConnectAsync(ProcessConnect, remoteEndPoint);
#else
                ProxyEndPoint.ConnectAsync(null, ProcessConnect, remoteEndPoint);
#endif
            }
            catch (Exception e)
            {
                OnException(new Exception("Failed to connect proxy server", e));
            }
        }

        protected override void ProcessConnect(Socket socket, object targetEndPoint, SocketAsyncEventArgs e, Exception exception)
        {
            if (exception != null)
            {
                OnException(exception);
                return;
            }

            if (e != null)
            {
                if (!ValidateAsyncResult(e))
                    return;
            }

            if (socket == null)
            {
                OnException(new SocketException((int)SocketError.ConnectionAborted));
                return;
            }

            if (e == null)
                e = new SocketAsyncEventArgs();

            string request;

            if (m_StatusCode == 400)
                m_HostPrefix = "/";

            string authorizationHeader = null;
            if (m_StatusCode == 401)
            {
                var auth = getClientToken(m_AuthProtocol, m_ServerAuthChallenge);
                authorizationHeader = string.Format("Authorization: {0} {1}\r\n", m_AuthProtocol, auth);
            }

            m_TargetEndPoint = (EndPoint)targetEndPoint;
            if (targetEndPoint is DnsEndPoint)
            {
                var targetDnsEndPoint = (DnsEndPoint)targetEndPoint;
                request = string.Format(m_RequestTemplate, targetDnsEndPoint.Host, targetDnsEndPoint.Port, authorizationHeader, m_HostPrefix + targetDnsEndPoint.Host);
            }
            else
            {
                var targetIPEndPoint = (IPEndPoint)targetEndPoint;
                request = string.Format(m_RequestTemplate, targetIPEndPoint.Address, targetIPEndPoint.Port, authorizationHeader, m_HostPrefix + targetIPEndPoint.Address);
            }

            var requestData = ASCIIEncoding.GetBytes(request);

            if (m_StatusCode != 401)
                e.Completed += AsyncEventArgsCompleted;

            e.UserToken = new ConnectContext { Socket = socket, SearchState = new SearchMarkState<byte>(m_LineSeparator) };
            e.SetBuffer(requestData, 0, requestData.Length);

            StartSend(socket, e);
        }

        protected override void ProcessSend(SocketAsyncEventArgs e)
        {
            if (!ValidateAsyncResult(e))
                return;

            var context = (ConnectContext)e.UserToken;

            var buffer = new byte[m_ReceiveBufferSize];
            e.SetBuffer(buffer, 0, buffer.Length);

            StartReceive(context.Socket, e);
        }

        protected override void ProcessReceive(SocketAsyncEventArgs e)
        {
            if (!ValidateAsyncResult(e))
                return;

            var context = (ConnectContext)e.UserToken;

            int prevMatched = context.SearchState.Matched;

            int result = e.Buffer.SearchMark(e.Offset, e.BytesTransferred, context.SearchState);

            if (result < 0)
            {
                int total = e.Offset + e.BytesTransferred;

                if(total >= m_ReceiveBufferSize)
                {
                    OnException("receive buffer size has been exceeded");
                    return;
                }

                e.SetBuffer(total, m_ReceiveBufferSize - total);
                StartReceive(context.Socket, e);
                return;
            }

            int responseLength = prevMatched > 0 ? (e.Offset - prevMatched) : (e.Offset + result);

            //if (e.Offset + e.BytesTransferred > responseLength + m_LineSeparator.Length)
            //{
            //    OnException("protocol error: more data has been received");
            //    return;
            //}

            var lineReader = new StringReader(ASCIIEncoding.GetString(e.Buffer, 0, responseLength));

            var line = lineReader.ReadLine();

            if (string.IsNullOrEmpty(line))
            {
                OnException("protocol error: invalid response");
                return;
            }

            //HTTP/1.1 2** OK
            var pos = line.IndexOf(m_Space);

            if (pos <= 0 || line.Length <= (pos + 2))
            {
                OnException("protocol error: invalid response");
                return;
            }

            var httpProtocol = line.Substring(0, pos);

            if (!m_ResponsePrefix.Equals(httpProtocol))
            {
                OnException("protocol error: invalid protocol");
                return;
            }

            var statusPos = line.IndexOf(m_Space, pos + 1);

            if (statusPos < 0)
            {
                OnException("protocol error: invalid response");
                return;
            }

            int statusCode;
            bool statusCodeParsed = int.TryParse(line.Substring(pos + 1, statusPos - pos - 1), out statusCode);
            //Status code should be 2**
            if (!statusCodeParsed)
            {
                OnException("the proxy server refused the connection");
                return;
            }
            else if (statusCode == 400)
            {
                if (m_StatusCode != 400)
                {
                    m_StatusCode = statusCode;
                    Connect(m_TargetEndPoint);
                }
                else
                {
                    m_StatusCode = statusCode;
                    OnException("the proxy server refused the connection");
                }
                return;
            }
            else if (statusCode == 401)
            {
                m_StatusCode = statusCode;

                List<string> authenticationMethods = new List<string>();
                while ((line = lineReader.ReadLine()) != null)
                {
                    if (line.IndexOf("WWW-Authenticate: ") > -1)
                        authenticationMethods.Add(line.Substring(line.IndexOf("WWW-Authenticate: ") + 18));
                }

                string[] methodNames = new string[] { PackageNames.Negotiate, PackageNames.Kerberos, PackageNames.Ntlm };
                foreach (var methodName in methodNames) {
                    int methodIndex = authenticationMethods.FindIndex(s => s.IndexOf(methodName) > -1);
                    if (methodIndex > -1)
                    {
                        string methodString = authenticationMethods[methodIndex];
                        if (methodString.Contains(" "))
                            m_ServerAuthChallenge = methodString.Substring(methodString.IndexOf(" ") + 1);

                        m_AuthProtocol = methodName;
                    }
                }

                ProcessConnect(((ConnectContext)e.UserToken).Socket, m_TargetEndPoint, e, null);
                return;
            }
            else if (statusCode > 299 || statusCode < 200)
            {
                OnException("the proxy server refused the connection");
                return;
            }

            if (m_Client != null)
            {
                m_Client.Dispose();
            }

            if (m_ClientCred != null)
            {
                m_ClientCred.Dispose();
            }

            OnCompleted(new ProxyEventArgs(context.Socket, TargetHostHame));
        }

        private string getClientToken(string packageName, string serverAuthString = null)
        {
            try
            {
                if (m_ClientCred == null)
                    m_ClientCred = new ClientCurrentCredential(packageName);

                if (m_Client == null)
                {
                    m_Client = new ClientContext(
                        m_ClientCred,
                        m_ClientCred.PrincipleName,
                        ContextAttrib.MutualAuth |
                        ContextAttrib.InitIdentify |
                        ContextAttrib.Confidentiality |
                        ContextAttrib.ReplayDetect |
                        ContextAttrib.SequenceDetect |
                        ContextAttrib.Connection |
                        ContextAttrib.Delegate
                    );
                }

                byte[] serverToken = serverAuthString == null ? null : Convert.FromBase64String(serverAuthString);

                SecurityStatus clientStatus = m_Client.Init(serverToken, out m_ClientToken);
            }
            catch (Exception e)
            {
                OnException("proxy credential token generation error");
            }

            return m_ClientToken != null ? Convert.ToBase64String(m_ClientToken) : "";
        }
    }
}
