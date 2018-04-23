using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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

        private const string m_RequestTemplate = "CONNECT {3}{0}:{1} HTTP/1.1\r\nHost: {0}:{1}\r\nProxy-Connection: Keep-Alive\r\n{2}\r\n";

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
        private Dictionary<int, AuthToken> m_AuthTokens;
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
            m_AuthTokens = new Dictionary<int, AuthToken>();
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

            string authorizationHeader = "";
            if (m_StatusCode == 401 || m_StatusCode == 407)
                authorizationHeader = m_AuthTokens.Aggregate("", (sum, next) => sum + next.Value.GetAuthorizationHeader());

            m_TargetEndPoint = (EndPoint)targetEndPoint;
            if (targetEndPoint is DnsEndPoint)
            {
                var targetDnsEndPoint = (DnsEndPoint)targetEndPoint;
                request = string.Format(m_RequestTemplate, targetDnsEndPoint.Host, targetDnsEndPoint.Port, authorizationHeader, m_HostPrefix);
            }
            else
            {
                var targetIPEndPoint = (IPEndPoint)targetEndPoint;
                request = string.Format(m_RequestTemplate, targetIPEndPoint.Address, targetIPEndPoint.Port, authorizationHeader, m_HostPrefix);
            }

            var requestData = ASCIIEncoding.GetBytes(request);

            if (m_StatusCode != 401 && m_StatusCode != 407)
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
            else if (statusCode == 401 || statusCode == 407)
            {
                m_StatusCode = statusCode;
                if (!m_AuthTokens.ContainsKey(statusCode))
                    m_AuthTokens.Add(statusCode, new AuthToken(statusCode, lineReader));
                else
                    m_AuthTokens[statusCode].SetNextHeaders(lineReader);
                ProcessConnect(((ConnectContext)e.UserToken).Socket, m_TargetEndPoint, e, null);
                return;
            }
            else if (statusCode > 299 || statusCode < 200)
            {
                OnException("the proxy server refused the connection");
                return;
            }
            
            foreach (var tokenPair in m_AuthTokens)
            {
                tokenPair.Value.Dispose();
            }
            m_AuthTokens = new Dictionary<int, AuthToken>();

            OnCompleted(new ProxyEventArgs(context.Socket, TargetHostHame));
        }

        class AuthToken
        {
            private string m_Header;
            private string m_AuthenticateHeader;
            private string m_AuthProtocol;
            private string m_ServerAuthChallenge;
            private ClientCurrentCredential m_ClientCred;
            private ClientContext m_Client;
            private ServerCurrentCredential m_ServerCred;
            private byte[] m_ClientToken;
            private List<string> m_AuthMethods;

            private static Dictionary<int, string> CODE_TO_HEADER = new Dictionary<int, string>
            {
                { 401, "Authorization" },
                { 407, "Proxy-Authorization" }
            };
            private static Dictionary<int, string> CODE_TO_AUTHENTICATE_HEADER = new Dictionary<int, string>
            {
                { 401, "WWW-Authenticate: " },
                { 407, "Proxy-Authenticate: " }
            };
            private static string[] METHOD_NAMES = new string[] { PackageNames.Negotiate, PackageNames.Kerberos, PackageNames.Ntlm };

            public AuthToken(int statusCode, StringReader lineReader)
            {
                m_AuthenticateHeader = CODE_TO_AUTHENTICATE_HEADER[statusCode];
                m_Header = CODE_TO_HEADER[statusCode];
                SetFirstHeaders(lineReader);
                m_ClientCred = new ClientCurrentCredential(m_AuthProtocol);
                m_ServerCred = new ServerCurrentCredential(m_AuthProtocol);
                m_Client = new ClientContext(
                    m_ClientCred,
                    m_ServerCred.PrincipleName,
                    ContextAttrib.MutualAuth |
                    ContextAttrib.InitIdentify |
                    ContextAttrib.Confidentiality |
                    ContextAttrib.ReplayDetect |
                    ContextAttrib.SequenceDetect |
                    ContextAttrib.Connection |
                    ContextAttrib.Delegate
                );
            }

            private void SetFirstHeaders(StringReader lineReader)
            {
                m_AuthMethods = new List<string>();
                string line;
                while ((line = lineReader.ReadLine()) != null)
                {
                    int authenticateIndex = line.IndexOf(m_AuthenticateHeader);
                    if (authenticateIndex > -1)
                        m_AuthMethods.Add(line.Substring(authenticateIndex + 18));
                }

                foreach (var methodName in METHOD_NAMES)
                {
                    int methodIndex = m_AuthMethods.FindIndex(s => s.IndexOf(methodName) > -1);
                    if (methodIndex > -1)
                    {
                        m_AuthProtocol = methodName;
                        break;
                    }
                }
            }

            public void SetNextHeaders(StringReader headersLineReader)
            {
                string line;
                while ((line = headersLineReader.ReadLine()) != null)
                {
                    int authenticateIndex = line.IndexOf(m_AuthenticateHeader);
                    if (authenticateIndex > -1)
                    {
                        int protocolIndex = line.IndexOf(m_AuthProtocol);
                        if (protocolIndex > -1)
                        {
                            string protocolString = line.Substring(protocolIndex);
                            int challengeIndex = protocolString.IndexOf(" ");
                            if (challengeIndex != -1)
                            {
                                string challenge = protocolString.Substring(challengeIndex).Trim();
                                GetClientToken(challenge);
                                m_ServerAuthChallenge = challenge;
                            }
                            else
                            {
                                throw new Exception("authentication from server missing authentication challenge");
                            }
                        }
                    }
                }
            }
            
            public string GetAuthorizationHeader()
            {
                return string.Format("{2}: {0} {1}\r\n", m_AuthProtocol, GetClientToken(m_ServerAuthChallenge), m_Header);
            }

            public void Dispose()
            {
                if (m_Client != null)
                    m_Client.Dispose();
                if (m_ClientCred != null)
                    m_ClientCred.Dispose();
            }

            private string GetClientToken(string serverAuthString)
            {
                if (serverAuthString == null || serverAuthString != m_ServerAuthChallenge)
                {
                    try
                    {
                        byte[] serverToken = serverAuthString == null ? null : Convert.FromBase64String(serverAuthString);
                        SecurityStatus clientStatus = m_Client.Init(serverToken, out m_ClientToken);
                    }
                    catch (Exception e)
                    {
                        throw new Exception("authentication token generation error", e);
                    }
                }
             
                return m_ClientToken != null ? Convert.ToBase64String(m_ClientToken) : "";
            }
        }
    }
}
