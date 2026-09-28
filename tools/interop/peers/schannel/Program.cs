// The Windows SChannel peer for tools/interop/run.sh: System.Net.Security.
// SslStream (SChannel on Windows) as a TLS client or server, driven by
// peers/schannel.sh. After each handshake the negotiated parameters go to a
// report file as `key: value` lines (the adapter's `verify` reads them), then
// the application payload is exchanged and the session ends with
// close_notify (SslStream.ShutdownAsync).
//
//   schannel-peer info
//   schannel-peer probe --cert leaf.crt --key leaf.key [--chain int.crt]
//       (diagnostic: is the certificate usable as an SChannel credential?)
//   schannel-peer server --cert leaf.crt --key leaf.key [--chain int.crt]
//       [--ca ca.crt] [--alpn h2,http/1.1] [--tls12] [--accept N]
//       [--send FILE] --out PREFIX
//   schannel-peer client --port N [--host NAME] --ca ca.crt
//       [--cert c.crt --key c.key] [--alpn h2,http/1.1] [--tls12]
//       [--connections N] [--rounds N] [--revocation online] [--send FILE]
//       --out PREFIX
//
// Files: PREFIX.out (the first connection's report and received data),
// PREFIX2.out for the second one, and for the server PREFIX.port with the
// port it listens on (bound to 127.0.0.1:0, kernel-chosen).
//
// What SslStream cannot express on Windows is left to the adapter's SKIPs:
// cipher suites and groups follow the system policy (CipherSuitesPolicy is
// Linux/macOS only), there is no 0-RTT, KeyUpdate or raw-public-key API,
// and resumption is transparent (nothing reports it; the purecrypto side
// does).

using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SchannelPeer;

sealed class Options
{
    public string Mode = "";
    public string? Cert;
    public string? Key;
    public string? Chain;
    public string? Ca;
    public List<string> Alpn = new();
    public bool Tls12;
    public int Accept = 1;
    public int Connections = 1;
    public int Rounds = 1;
    public string? Send;
    public string Out = "peer";
    public string Host = "localhost";
    public int Port;
    public X509RevocationMode Revocation = X509RevocationMode.NoCheck;

    public SslProtocols Protocols => Tls12 ? SslProtocols.Tls12 : SslProtocols.Tls13;

    public static Options Parse(string[] args)
    {
        var o = new Options();
        if (args.Length == 0) throw new ArgumentException("usage: schannel-peer info|server|client ...");
        o.Mode = args[0];
        for (int i = 1; i < args.Length; i++)
        {
            string a = args[i];
            string Next()
            {
                if (i + 1 >= args.Length) throw new ArgumentException($"{a} needs a value");
                return args[++i];
            }
            switch (a)
            {
                case "--cert": o.Cert = Next(); break;
                case "--key": o.Key = Next(); break;
                case "--chain": o.Chain = Next(); break;
                case "--ca": o.Ca = Next(); break;
                case "--alpn": o.Alpn = Next().Split(',', StringSplitOptions.RemoveEmptyEntries).ToList(); break;
                case "--tls12": o.Tls12 = true; break;
                case "--accept": o.Accept = int.Parse(Next()); break;
                case "--connections": o.Connections = int.Parse(Next()); break;
                case "--rounds": o.Rounds = int.Parse(Next()); break;
                case "--send": o.Send = Next(); break;
                case "--out": o.Out = Next(); break;
                case "--host": o.Host = Next(); break;
                case "--port": o.Port = int.Parse(Next()); break;
                case "--revocation":
                    o.Revocation = Next().ToLowerInvariant() switch
                    {
                        "online" => X509RevocationMode.Online,
                        "offline" => X509RevocationMode.Offline,
                        _ => X509RevocationMode.NoCheck,
                    };
                    break;
                default: throw new ArgumentException($"unknown argument {a}");
            }
        }
        return o;
    }
}

static class Program
{
    static int Main(string[] args)
    {
        try
        {
            var o = Options.Parse(args);
            return o.Mode switch
            {
                "info" => Info(),
                "probe" => Probe(o).GetAwaiter().GetResult(),
                "server" => Server(o).GetAwaiter().GetResult(),
                "client" => Client(o).GetAwaiter().GetResult(),
                _ => throw new ArgumentException($"unknown mode {o.Mode}"),
            };
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"error: {e}");
            return 1;
        }
    }

    static void Log(string s)
    {
        Console.Error.WriteLine(s);
    }

    static int Info()
    {
        Console.WriteLine(
            $"SChannel via .NET SslStream ({RuntimeInformation.FrameworkDescription}) on " +
            $"{RuntimeInformation.OSDescription} {RuntimeInformation.OSArchitecture}");
        return 0;
    }

    // ------------------------------------------------------------ certificates

    // A certificate with its private key, usable by SChannel. Loading a PEM
    // pair gives an ephemeral key SChannel cannot use ("No credentials are
    // available in the security package"), so the pair goes through PKCS#12
    // once to land the key in a CNG container.
    static X509Certificate2 LoadIdentity(string certPem, string keyPem)
    {
        using var ephemeral = X509Certificate2.CreateFromPemFile(certPem, keyPem);
        byte[] pfx = ephemeral.Export(X509ContentType.Pkcs12);
        return new X509Certificate2(pfx, (string?)null,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.UserKeySet);
    }

    static X509Certificate2Collection LoadPem(string path)
    {
        var c = new X509Certificate2Collection();
        c.ImportFromPemFile(path);
        return c;
    }

    // Trust exactly the run's CA (RFC 5280 path validation by the platform
    // engine, rooted in it rather than in the machine store), and no
    // revocation checking unless asked: the leaves carry no AIA/CRL URLs.
    static X509ChainPolicy TrustPolicy(string caPem, X509RevocationMode revocation)
    {
        var p = new X509ChainPolicy
        {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
            RevocationMode = revocation,
            RevocationFlag = X509RevocationFlag.EndCertificateOnly,
            VerificationFlags = X509VerificationFlags.NoFlag,
        };
        p.CustomTrustStore.AddRange(LoadPem(caPem));
        return p;
    }

    static bool Validate(TextWriter report, X509Certificate? cert, X509Chain? chain, SslPolicyErrors errors)
    {
        report.WriteLine($"validation: {errors}");
        if (chain != null)
        {
            foreach (var st in chain.ChainStatus)
                report.WriteLine($"chain status: {st.Status} ({st.StatusInformation.Trim()})");
            report.WriteLine($"chain length: {chain.ChainElements.Count}");
        }
        return errors == SslPolicyErrors.None;
    }

    // ------------------------------------------------------------ report

    static void Report(TextWriter w, SslStream ssl, int n)
    {
        w.WriteLine($"connection: {n}");
        w.WriteLine($"protocol: {ssl.SslProtocol}");
        w.WriteLine($"cipher suite: {ssl.NegotiatedCipherSuite}");
        w.WriteLine($"cipher: {ssl.CipherAlgorithm} {ssl.CipherStrength}");
        w.WriteLine($"hash: {ssl.HashAlgorithm} {ssl.HashStrength}");
        // On TLS 1.3 SChannel reports the exchange algorithm but not the
        // group; the purecrypto side pins and verifies that one.
        w.WriteLine($"key exchange: {ssl.KeyExchangeAlgorithm} {ssl.KeyExchangeStrength}");
        w.WriteLine($"alpn: {(ssl.NegotiatedApplicationProtocol.Protocol.IsEmpty ? "none" : ssl.NegotiatedApplicationProtocol.ToString())}");
        w.WriteLine($"peer certificate: {(ssl.RemoteCertificate == null ? "none" : ssl.RemoteCertificate.Subject)}");
        w.WriteLine($"local certificate: {(ssl.LocalCertificate == null ? "none" : ssl.LocalCertificate.Subject)}");
        w.WriteLine($"mutually authenticated: {(ssl.IsMutuallyAuthenticated ? "yes" : "no")}");
        w.Flush();
    }

    static StreamWriter OpenReport(string prefix, int n)
    {
        string path = n == 1 ? prefix + ".out" : $"{prefix}{n}.out";
        return new StreamWriter(path, false, new UTF8Encoding(false)) { AutoFlush = true, NewLine = "\n" };
    }

    // ------------------------------------------------------------ data phase

    // Read until the peer ends the session (close_notify: Read returns 0) or,
    // with `atLeast` > 0, until that many bytes are in.
    static async Task<(byte[] data, bool eof)> ReadUntil(SslStream ssl, int atLeast)
    {
        var got = new MemoryStream();
        var buf = new byte[16384];
        bool eof = false;
        while (atLeast <= 0 || got.Length < atLeast)
        {
            int n = await ssl.ReadAsync(buf);
            if (n == 0) { eof = true; break; }
            got.Write(buf, 0, n);
        }
        return (got.ToArray(), eof);
    }

    static void ReportData(TextWriter w, string what, byte[] data)
    {
        w.WriteLine($"{what}: {data.Length} bytes");
        w.WriteLine($"--- {what} ---");
        w.Write(Encoding.UTF8.GetString(data));
        if (data.Length > 0 && data[^1] != (byte)'\n') w.WriteLine();
        w.WriteLine($"--- end {what} ---");
        w.Flush();
    }

    // ------------------------------------------------------------ probe

    // Diagnostic: can SChannel take this certificate as a server credential?
    // A loopback handshake between two SslStreams in this process, with
    // and without the extra chain, reporting the innermost error.
    static async Task<int> Probe(Options o)
    {
        if (o.Cert == null || o.Key == null) throw new ArgumentException("probe needs --cert and --key");
        using var ident = LoadIdentity(o.Cert, o.Key);
        Console.WriteLine($"certificate: {ident.Subject}, {ident.RawData.Length} bytes DER, key {ident.GetKeyAlgorithm()}, private key {ident.HasPrivateKey}");
        var extra = new X509Certificate2Collection();
        if (o.Chain != null) extra.AddRange(LoadPem(o.Chain));
        foreach (var (label, ctx) in new[] {
            ("leaf only, SslStreamCertificateContext", SslStreamCertificateContext.Create(ident, null, offline: true)),
            ("leaf + chain, SslStreamCertificateContext", SslStreamCertificateContext.Create(ident, extra, offline: true)),
        })
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var serverTask = Task.Run(async () =>
            {
                using var tcp = await listener.AcceptTcpClientAsync();
                using var ssl = new SslStream(tcp.GetStream(), false);
                await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificateContext = ctx,
                    EnabledSslProtocols = o.Protocols,
                });
                return $"{ssl.SslProtocol} {ssl.NegotiatedCipherSuite}";
            });
            string clientResult;
            try
            {
                using var tcp = new TcpClient(AddressFamily.InterNetwork);
                await tcp.ConnectAsync(IPAddress.Loopback, port);
                using var ssl = new SslStream(tcp.GetStream(), false);
                await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = o.Host,
                    EnabledSslProtocols = o.Protocols,
                    RemoteCertificateValidationCallback = (s, c, ch, e) => true,
                });
                clientResult = "ok";
            }
            catch (Exception e)
            {
                clientResult = $"client: {Innermost(e)}";
            }
            string serverResult;
            try { serverResult = await serverTask; }
            catch (Exception e) { serverResult = $"server: {Innermost(e)}"; }
            listener.Stop();
            Console.WriteLine($"{label}: {serverResult} / {clientResult}");
        }
        return 0;
    }

    static string Innermost(Exception e)
    {
        while (e.InnerException != null) e = e.InnerException;
        return $"{e.GetType().Name}: {e.Message}";
    }

    // ------------------------------------------------------------ server

    static async Task<int> Server(Options o)
    {
        if (o.Cert == null || o.Key == null) throw new ArgumentException("server needs --cert and --key");
        using var ident = LoadIdentity(o.Cert, o.Key);
        var extra = new X509Certificate2Collection();
        if (o.Chain != null)
        {
            extra.AddRange(LoadPem(o.Chain));
            // SChannel assembles the chain it sends from the certificate
            // stores; the context below records the intermediates, and the
            // user's Intermediate CA store (no prompt, no privilege) is
            // where SChannel looks.
            try
            {
                using var store = new X509Store(StoreName.CertificateAuthority, StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadWrite);
                store.AddRange(extra);
            }
            catch (Exception e)
            {
                Log($"intermediate store: {e.Message}");
            }
        }
        var ctx = SslStreamCertificateContext.Create(ident, extra, offline: true);
        X509ChainPolicy? clientPolicy = o.Ca != null ? TrustPolicy(o.Ca, o.Revocation) : null;
        byte[] payload = o.Send != null ? File.ReadAllBytes(o.Send) : Array.Empty<byte>();

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        // The adapter polls for the port file; write it whole, then rename.
        File.WriteAllText(o.Out + ".port.tmp", port + "\n");
        File.Move(o.Out + ".port.tmp", o.Out + ".port", true);
        Log($"listening on 127.0.0.1:{port}");

        int rc = 0;
        for (int n = 1; n <= o.Accept; n++)
        {
            using var report = OpenReport(o.Out, n);
            try
            {
                using var tcp = await listener.AcceptTcpClientAsync();
                tcp.NoDelay = true;
                using var ssl = new SslStream(tcp.GetStream(), false);
                var opts = new SslServerAuthenticationOptions
                {
                    ServerCertificateContext = ctx,
                    ClientCertificateRequired = clientPolicy != null,
                    EnabledSslProtocols = o.Protocols,
                    CertificateRevocationCheckMode = o.Revocation,
                    AllowRenegotiation = false,
                };
                if (clientPolicy != null)
                {
                    // Only a requested client certificate is validated; the
                    // callback is otherwise invoked with "not available".
                    opts.CertificateChainPolicy = clientPolicy;
                    opts.RemoteCertificateValidationCallback = (s, c, ch, e) => Validate(report, c, ch, e);
                }
                if (o.Alpn.Count > 0)
                    opts.ApplicationProtocols = o.Alpn.Select(a => new SslApplicationProtocol(a)).ToList();
                await ssl.AuthenticateAsServerAsync(opts);
                Report(report, ssl, n);
                // Wait for the client to speak before answering: a
                // ticket-only connection (purecrypto `-reconnect`) says
                // goodbye at once, and data sent into its closing socket
                // would turn into a reset that discards its close_notify
                // on Windows. It also puts the answer after any KeyUpdate
                // the client sent first, where RFC 8446 §4.6.3 wants the
                // reply KeyUpdate.
                var (data, eof) = await ReadUntil(ssl, 1);
                if (!eof)
                {
                    if (payload.Length > 0)
                    {
                        await ssl.WriteAsync(payload);
                        await ssl.FlushAsync();
                    }
                    report.WriteLine($"sent: {payload.Length} bytes");
                    var (rest, eof2) = await ReadUntil(ssl, 0);
                    data = data.Concat(rest).ToArray();
                    eof = eof2;
                }
                ReportData(report, "received", data);
                report.WriteLine($"peer close: {(eof ? "eof" : "no")}");
                await ssl.ShutdownAsync();
                report.WriteLine("close_notify: sent");
            }
            catch (Exception e)
            {
                report.WriteLine($"error: {e.GetType().Name}: {e.Message}");
                Log($"connection {n}: {e}");
                rc = 1;
            }
        }
        listener.Stop();
        return rc;
    }

    // ------------------------------------------------------------ client

    static async Task<int> Client(Options o)
    {
        if (o.Port == 0) throw new ArgumentException("client needs --port");
        X509Certificate2? ident = o.Cert != null && o.Key != null ? LoadIdentity(o.Cert, o.Key) : null;
        X509ChainPolicy? policy = o.Ca != null ? TrustPolicy(o.Ca, o.Revocation) : null;
        byte[] payload = o.Send != null ? File.ReadAllBytes(o.Send) : Array.Empty<byte>();
        int rc = 0;
        for (int n = 1; n <= o.Connections; n++)
        {
            using var report = OpenReport(o.Out, n);
            try
            {
                using var tcp = new TcpClient(AddressFamily.InterNetwork);
                await tcp.ConnectAsync(IPAddress.Loopback, o.Port);
                tcp.NoDelay = true;
                using var ssl = new SslStream(tcp.GetStream(), false);
                var opts = new SslClientAuthenticationOptions
                {
                    TargetHost = o.Host,
                    EnabledSslProtocols = o.Protocols,
                    CertificateRevocationCheckMode = o.Revocation,
                    AllowRenegotiation = false,
                    AllowTlsResume = true,
                    RemoteCertificateValidationCallback = (s, c, ch, e) => Validate(report, c, ch, e),
                };
                if (policy != null) opts.CertificateChainPolicy = policy;
                if (o.Alpn.Count > 0)
                    opts.ApplicationProtocols = o.Alpn.Select(a => new SslApplicationProtocol(a)).ToList();
                if (ident != null)
                {
                    opts.ClientCertificates = new X509Certificate2Collection(ident);
                    // Bypass SslStream's issuer filtering: whatever CA names
                    // the server lists, this is the identity to present.
                    opts.LocalCertificateSelectionCallback = (s, host, local, remote, issuers) =>
                    {
                        report.WriteLine($"certificate request: {issuers.Length} acceptable issuers");
                        return ident;
                    };
                }
                await ssl.AuthenticateAsClientAsync(opts);
                Report(report, ssl, n);
                // The purecrypto server echoes what it gets; wait for all of
                // it, then say goodbye and wait for the server's close_notify.
                // Several rounds (write, read the echo, write again) give a
                // KeyUpdate the server sent a following application-data
                // record to precede (RFC 8446 §4.6.3).
                byte[] data = Array.Empty<byte>();
                bool eof = false;
                for (int r = 1; r <= o.Rounds && !eof; r++)
                {
                    if (payload.Length > 0)
                    {
                        await ssl.WriteAsync(payload);
                        await ssl.FlushAsync();
                    }
                    report.WriteLine($"sent: {payload.Length} bytes");
                    var (echo, e) = await ReadUntil(ssl, payload.Length);
                    data = data.Concat(echo).ToArray();
                    eof = e;
                }
                ReportData(report, "received", data);
                if (!eof)
                {
                    await ssl.ShutdownAsync();
                    report.WriteLine("close_notify: sent");
                    var (tail, eof2) = await ReadUntil(ssl, 0);
                    if (tail.Length > 0) ReportData(report, "received after shutdown", tail);
                    eof = eof2;
                }
                report.WriteLine($"peer close: {(eof ? "eof" : "no")}");
            }
            catch (Exception e)
            {
                report.WriteLine($"error: {e.GetType().Name}: {e.Message}");
                Log($"connection {n}: {e}");
                rc = 1;
            }
        }
        ident?.Dispose();
        return rc;
    }
}
