using System.Net;
using System.Net.NetworkInformation;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Net.Http;
using System.Net.Security;
using System.Net.Http.Headers;
using System.Diagnostics;
namespace SiteMonitor
{
    public class MonitorSettings
    {
        public int interval { get; set; } = 60;
        public int timeout { get; set; } = 5;
        public int retries_max { get; set; } = 2;
        public List<int> valid_status_codes { get; set; } = new() { 200, 201, 202, 204, 300, 301, 302, 303, 307, 308, 405, 418 };
        public List<int> warn_status_codes { get; set; } = new() { 401, 403, 429 };
        public string sorted { get; set; } = "status";
        public bool ping_enabled { get; set; } = true;
        public bool uptime_enabled { get; set; } = false;
        public bool use_head_first { get; set; } = true;
    }
    public class MonitorConfig
    {
        public bool logging_enabled { get; set; } = false;
        public string log_file_path { get; set; } = "monitor.log";
    }
    public class Config
    {
        public MonitorSettings monitor_settings { get; set; } = new();
        public List<string> websites { get; set; } = new();
        public MonitorConfig Monitor { get; set; } = new();
    }
    public class WebsiteResult
    {
        public string url { get; set; } = string.Empty;
        public string ip { get; set; } = string.Empty;
        public string status { get; set; } = string.Empty;
        public string code { get; set; } = string.Empty;
        public string error_type { get; set; } = string.Empty;
        public long duration_ms { get; set; }
        public int retries { get; set; }
        public string http_method { get; set; } = "GET";
    }
    class Program
    {
        static string scriptDir = string.Empty;
        static string configPath = string.Empty;
        static Config config = new();
        static bool exitRequested = false;
        static HttpClient client = null!;
        static SocketsHttpHandler handler = null!;
        static Dictionary<string, List<bool>> uptimeHistory = new();
        static Dictionary<string, int> failureCount = new();
        static bool configReloaded = false;
        static Dictionary<string, bool> alertLocked = new();
        static async Task Main(string[] args)
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            scriptDir = AppDomain.CurrentDomain.BaseDirectory;
            configPath = Path.Combine(scriptDir, "config.json");
            Console.CancelKeyPress += (s, e) => { e.Cancel = true; exitRequested = true; };
            config = LoadOrCreateConfigWithMessage();
            SafeClear();
            PrintBanner();
            StartHttpClient();
            while (!exitRequested)
            {
                var startTime = DateTime.Now;
                int total = config.websites.Count;
                int done = 0;
                using var overlayCts = new CancellationTokenSource();
                var overlayTask = RunOverlayAsync(total, () => Volatile.Read(ref done), overlayCts.Token);
                var tasks = config.websites.Select(site => CheckWebsiteWrapped(site, () => Interlocked.Increment(ref done))).ToArray();
                var results = await Task.WhenAll(tasks);
                overlayCts.Cancel();
                try { await overlayTask; } catch { }
                if (config.monitor_settings.sorted == "status") results = results.OrderBy(r => r.status != "OK" && r.status != "WARN").ThenBy(r => r.url).ToArray();
                SafeClear();
                PrintBanner();
                SafeWriteLine($"Мониторинг начался в: {startTime:yyyy-MM-dd HH:mm:ss}\n");
                PrintResults(results);
                if (config.monitor_settings.uptime_enabled)
                {
                    int historyMax = 1440;
                    foreach (var r in results)
                    {
                        if (!uptimeHistory.ContainsKey(r.url)) uptimeHistory[r.url] = new List<bool>();
                        uptimeHistory[r.url].Add(r.status == "OK" || r.status == "WARN");
                        if (uptimeHistory[r.url].Count > historyMax) uptimeHistory[r.url].RemoveAt(0);
                    }
                    SafeWriteLine(new string('-', GetWidth()));
                    WriteCentered("АПТАЙМ ЗА СУТКИ", ConsoleColor.Cyan);
                    SafeWriteLine(new string('-', GetWidth()));
                    PrintUptime(results);
                }
                foreach (var r in results)
                {
                    if (!failureCount.ContainsKey(r.url)) failureCount[r.url] = 0;
                    if (r.status == "OK" || r.status == "WARN") failureCount[r.url] = 0; else failureCount[r.url]++;
                    if (failureCount[r.url] == 3)
                    {
                        SetColor(ConsoleColor.Yellow);
                        SafeWriteLine($"[АЛЕРТ] Сайт {r.url} трижды подряд недоступен! Статус: {r.status}");
                        ResetColor();
                    }
                }
                if (results.All(r => r.status != "OK" && r.status != "WARN"))
                {
                    SafeWriteLine("\nНи один сайт не отвечает. Информация об интерфейсах:");
                    foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                    {
                        SafeWriteLine($"[{ni.Name}] {ni.Description} — {ni.OperationalStatus}");
                        var ipProps = ni.GetIPProperties();
                        foreach (var ip in ipProps.UnicastAddresses) SafeWriteLine($" IP: {ip.Address}");
                    }
                }
                if (configReloaded) configReloaded = false;
                if (config.Monitor.logging_enabled) await LogResults(results);
                SafeWriteLine();
                int countdownLine = GetCursorTop();
                int totalDelay = Math.Max(1, config.monitor_settings.interval) * 1000;
                int delayStep = 100;
                int elapsed = 0;
                bool breakNow = false;
                while (elapsed < totalDelay && !exitRequested)
                {
                    int remaining = totalDelay - elapsed;
                    int remainingSec = (remaining + 999) / 1000;
                    int totalBars = 30;
                    int filledBars = Math.Clamp(totalBars - (remaining * totalBars) / Math.Max(1, totalDelay), 0, totalBars);
                    string bar = "[" + new string('█', filledBars) + new string('░', totalBars - filledBars) + $"] {remainingSec}s";
                    SafeSetCursorPosition(0, countdownLine);
                    SafeWrite("Нажмите "); SetColor(ConsoleColor.Blue); SafeWrite("R"); ResetColor();
                    SafeWrite(" для обновления или ожидайте "); SafeWrite(bar);
                    SafeWrite(". Нажмите "); SetColor(ConsoleColor.Red); SafeWrite("Ctrl+C"); ResetColor(); SafeWrite(" для выхода.");
                    if (ConsoleIsInteractive() && Console.KeyAvailable)
                    {
                        var key = Console.ReadKey(true);
                        if (key.Key == ConsoleKey.R)
                        {
                            config = LoadOrCreateConfigWithMessage();
                            RestartHttpClient();
                            configReloaded = true;
                            breakNow = true;
                            break;
                        }
                    }
                    await Task.Delay(delayStep);
                    elapsed += delayStep;
                }
                if (!breakNow) SafeWriteLine();
            }
        }
        static async Task<WebsiteResult> CheckWebsiteWrapped(string site, Action onDone)
        {
            try { return await CheckWebsiteAsync(site); } finally { onDone(); }
        }
        static async Task RunOverlayAsync(int total, Func<int> getDone, CancellationToken token)
        {
            var sw = Stopwatch.StartNew();
            string[] frames = new[] { "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏" };
            int i = 0;
            while (!token.IsCancellationRequested)
            {
                int done = getDone();
                string t1 = $" СКАНИРОВАНИЕ {frames[i % frames.Length]} ";
                string t2 = $" Готово {done}/{total} • {sw.Elapsed:mm\\:ss\\.f} ";
                int w = GetWidth(); int h = GetHeight();
                int boxW = Math.Max(Math.Max(t1.Length, t2.Length) + 4, 28);
                int boxH = 4;
                int left = Math.Max(0, (w - boxW) / 2);
                int top = Math.Max(0, (h - boxH) / 2);
                string horiz = new string('─', boxW - 2);
                SafeSetCursorPosition(left, top);
                SetColor(ConsoleColor.DarkGray); SafeWrite("┌" + horiz + "┐");
                SafeSetCursorPosition(left, top + 1); SafeWrite("│" + CenterInBox(t1, boxW - 2) + "│");
                SafeSetCursorPosition(left, top + 2); SafeWrite("│" + CenterInBox(t2, boxW - 2) + "│");
                SafeSetCursorPosition(left, top + 3); SafeWrite("└" + horiz + "┘"); ResetColor();
                try { await Task.Delay(125, token); } catch { break; }
                i++;
            }
            ResetColor();
        }
        static void StartHttpClient()
        {
            handler = new SocketsHttpHandler
            {
                UseProxy = false,
                AllowAutoRedirect = true,
                AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli,
                PooledConnectionLifetime = TimeSpan.FromMinutes(5),
                MaxConnectionsPerServer = 64,
                SslOptions = new SslClientAuthenticationOptions
                {
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.Online
                },
                Expect100ContinueTimeout = TimeSpan.Zero
            };
            client = new HttpClient(handler);
            client.Timeout = TimeSpan.FromSeconds(Math.Max(1, config.monitor_settings.timeout));
            client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*"));
        }
        static void RestartHttpClient()
        {
            try { client?.Dispose(); } catch { }
            try { handler?.Dispose(); } catch { }
            StartHttpClient();
        }
        static void PrintBanner()
        {
            int width = GetWidth();
            string line = new string('=', width);
            SetColor(ConsoleColor.Cyan);
            SafeWriteLine(line);
            WriteCentered("МОНИТОРИНГ ДОСТУПНОСТИ САЙТОВ", null);
            WriteCentered("Версия 1.3.6", null);
            SafeWriteLine(line);
            ResetColor();
        }
        static Config LoadOrCreateConfigWithMessage()
        {
            Config def = CreateDefaultConfig();
            if (File.Exists(configPath))
            {
                try
                {
                    string json = File.ReadAllText(configPath);
                    var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                    Config conf = JsonSerializer.Deserialize<Config>(json, options) ?? def;
                    if (conf.monitor_settings == null) conf.monitor_settings = def.monitor_settings;
                    if (conf.Monitor == null) conf.Monitor = def.Monitor;
                    if (conf.websites == null || conf.websites.Count == 0) conf.websites = def.websites;
                    NormalizeSettings(conf.monitor_settings, def.monitor_settings);
                    if (conf.monitor_settings.sorted != "status" && conf.monitor_settings.sorted != "url") conf.monitor_settings.sorted = "status";
                    return conf;
                }
                catch { return def; }
            }
            else
            {
                try { SaveConfig(def); } catch { }
                return def;
            }
        }
        static void NormalizeSettings(MonitorSettings ms, MonitorSettings def)
        {
            ms.interval = Math.Clamp(ms.interval, 1, 86400);
            ms.timeout = Math.Clamp(ms.timeout, 1, 300);
            ms.retries_max = Math.Clamp(ms.retries_max, 0, 5);
            if (ms.valid_status_codes == null || ms.valid_status_codes.Count == 0) ms.valid_status_codes = def.valid_status_codes;
            if (ms.warn_status_codes == null) ms.warn_status_codes = def.warn_status_codes;
            ms.valid_status_codes = ms.valid_status_codes.Distinct().OrderBy(x => x).ToList();
            ms.warn_status_codes = ms.warn_status_codes.Distinct().OrderBy(x => x).ToList();
        }
        static Config CreateDefaultConfig() => new()
        {
            monitor_settings = new MonitorSettings(),
            websites = new List<string>
            {
                "https://ya.ru","https://google.com","https://example.com",
                "https://vk.com","https://youtube.com","https://github.com",
                "https://steamcommunity.com","https://store.steampowered.com","https://twitch.tv",
                "https://reddit.com","https://wikipedia.org","https://x.com"
            },
            Monitor = new MonitorConfig()
        };
        static void SaveConfig(Config conf)
        {
            string json = JsonSerializer.Serialize(conf, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(configPath, json);
        }
        static async Task<WebsiteResult> CheckWebsiteAsync(string rawUrl)
        {
            WebsiteResult result = new() { url = rawUrl, ip = "N/A", status = "INIT", code = "", error_type = "" };
            if (!Uri.TryCreate(rawUrl, UriKind.Absolute, out var uri)) { result.status = "URL_ERROR"; result.code = "ERR"; result.error_type = "URL"; return result; }
            string host = uri.Host;
            if (config.monitor_settings.ping_enabled)
            {
                try
                {
                    using var ping = new Ping();
                    var reply = await ping.SendPingAsync(host, 2000);
                    if (reply.Status != IPStatus.Success && reply.Status != IPStatus.TimedOut) result.error_type = string.IsNullOrEmpty(result.error_type) ? "ICMP" : result.error_type;
                }
                catch { result.error_type = string.IsNullOrEmpty(result.error_type) ? "ICMP_EX" : result.error_type; }
            }
            try
            {
                var entry = await Dns.GetHostEntryAsync(host);
                result.ip = entry.AddressList.FirstOrDefault()?.ToString() ?? "N/A";
            }
            catch
            {
                result.status = "DNS_ERROR"; result.code = "ERR"; result.error_type = "DNS"; return result;
            }
            int attempts = config.monitor_settings.retries_max + 1;
            int tries = 0;
            string methodUsed = config.monitor_settings.use_head_first ? "HEAD" : "GET";
            var delays = new int[] { 250, 750, 1500 };
            Exception? lastEx = null;
            var swTotal = Stopwatch.StartNew();
            while (tries < attempts)
            {
                tries++;
                try
                {
                    var attempt = await SendOnce(uri, methodUsed, TimeSpan.FromSeconds(Math.Max(1, config.monitor_settings.timeout)));
                    swTotal.Stop();
                    result.duration_ms = swTotal.ElapsedMilliseconds;
                    result.retries = tries - 1;
                    result.http_method = attempt.method;
                    int statusCode = (int)attempt.response.StatusCode;
                    bool ok = config.monitor_settings.valid_status_codes.Contains(statusCode);
                    bool warn = !ok && config.monitor_settings.warn_status_codes.Contains(statusCode);
                    result.code = statusCode.ToString();
                    if (ok) { result.status = "OK"; result.error_type = string.Empty; }
                    else if (warn) { result.status = "WARN"; result.error_type = "PARTIAL"; }
                    else { result.status = "HTTP_ERROR"; result.error_type = "HTTP"; }
                    attempt.response.Dispose();
                    return result;
                }
                catch (HttpRequestException ex) when (ex.StatusCode == HttpStatusCode.MethodNotAllowed || ex.StatusCode == HttpStatusCode.NotImplemented)
                {
                    methodUsed = "GET";
                    if (tries <= attempts) await Task.Delay(Math.Min(delays[Math.Min(tries - 1, delays.Length - 1)], 2000));
                    lastEx = ex;
                }
                catch (TaskCanceledException ex)
                {
                    lastEx = ex;
                    if (tries >= attempts) break;
                    await Task.Delay(Math.Min(delays[Math.Min(tries - 1, delays.Length - 1)], 2000));
                }
                catch (HttpRequestException ex)
                {
                    lastEx = ex;
                    if (IsTransientStatus(ex.StatusCode))
                    {
                        if (tries >= attempts) break;
                        await Task.Delay(Math.Min(delays[Math.Min(tries - 1, delays.Length - 1)], 2000));
                    }
                    else break;
                }
                catch (AuthenticationException ex) { lastEx = ex; break; }
                catch (Exception ex)
                {
                    lastEx = ex;
                    if (tries >= attempts) break;
                    await Task.Delay(Math.Min(delays[Math.Min(tries - 1, delays.Length - 1)], 2000));
                }
            }
            swTotal.Stop();
            result.duration_ms = swTotal.ElapsedMilliseconds;
            result.retries = Math.Max(0, tries - 1);
            result.http_method = methodUsed;
            if (lastEx is AuthenticationException || (lastEx is HttpRequestException hre && hre.InnerException is AuthenticationException))
            {
                result.status = "SSL_ERROR"; result.code = "SSL"; result.error_type = "SSL";
            }
            else if (lastEx is TaskCanceledException)
            {
                result.status = "TIMEOUT"; result.code = "T/O"; result.error_type = "TIMEOUT";
            }
            else if (lastEx is HttpRequestException ex && (ex.StatusCode == HttpStatusCode.Redirect || ex.StatusCode == HttpStatusCode.RedirectKeepVerb || ex.StatusCode == HttpStatusCode.RedirectMethod))
            {
                result.status = "REDIRECT_LOOP"; result.code = "3xx"; result.error_type = "REDIRECT";
            }
            else
            {
                result.status = "CONN_ERROR"; result.code = "ERR"; result.error_type = "NETWORK";
            }
            return result;
        }
        static bool IsTransientStatus(HttpStatusCode? sc)
        {
            if (!sc.HasValue) return true;
            int s = (int)sc.Value;
            if (s == 408 || s == 425 || s == 429) return true;
            if (s >= 500 && s <= 504) return true;
            return false;
        }
        static async Task<(HttpResponseMessage response, string method)> SendOnce(Uri uri, string methodPreference, TimeSpan timeout)
        {
            using var cts = new CancellationTokenSource(timeout);
            if (methodPreference == "HEAD")
            {
                using var reqH = new HttpRequestMessage(HttpMethod.Head, uri);
                reqH.Version = new Version(2, 0);
                reqH.VersionPolicy = HttpVersionPolicy.RequestVersionOrLower;
                var respH = await client.SendAsync(reqH, HttpCompletionOption.ResponseHeadersRead, cts.Token);
                return (respH, "HEAD");
            }
            else
            {
                using var reqG = new HttpRequestMessage(HttpMethod.Get, uri);
                reqG.Version = new Version(2, 0);
                reqG.VersionPolicy = HttpVersionPolicy.RequestVersionOrLower;
                var respG = await client.SendAsync(reqG, HttpCompletionOption.ResponseHeadersRead, cts.Token);
                return (respG, "GET");
            }
        }
        static void PrintResults(WebsiteResult[] results)
        {
            int w = GetWidth();
            int statW = 12, ipW = 16, codeW = 6, methodW = 5, retryW = 7, durW = 8;
            int spaces = 6;
            int siteW = Math.Max(20, w - (statW + ipW + codeW + methodW + retryW + durW + spaces));
            SafeWriteLine(new string('-', w));
            SetColor(ConsoleColor.Magenta);
            SafeWriteLine(FormatRow7("Статус", statW, "Сайт", siteW, "IP", ipW, "Код", codeW, "Метод", methodW, "Повторы", retryW, "мс", durW));
            ResetColor();
            SafeWriteLine(new string('-', w));
            int avail = 0;
            foreach (var r in results)
            {
                if (r.status == "OK") SetColor(ConsoleColor.Green);
                else if (r.status == "WARN") SetColor(ConsoleColor.Yellow);
                else SetColor(ConsoleColor.Red);
                SafeWrite(Pad(r.status, statW)); ResetColor(); SafeWrite(" ");
                SafeWrite(Pad(r.url, siteW)); SafeWrite(" ");
                SafeWrite(Pad(r.ip, ipW)); SafeWrite(" ");
                SafeWrite(Pad(r.code, codeW)); SafeWrite(" ");
                SafeWrite(Pad(r.http_method, methodW)); SafeWrite(" ");
                SafeWrite(Pad(r.retries.ToString(), retryW)); SafeWrite(" ");
                if (r.duration_ms < 500) SetColor(ConsoleColor.Green);
                else if (r.duration_ms <= 2000) SetColor(ConsoleColor.Yellow);
                else SetColor(ConsoleColor.Red);
                SafeWriteLine(Pad(r.duration_ms.ToString(), durW)); ResetColor();
                if (r.status == "OK" || r.status == "WARN") avail++;
            }
            SafeWriteLine(new string('-', w));
            SafeWriteLine($"Итого доступно: {avail}/{results.Length} сайтов");
            SafeWriteLine();
        }
        static void PrintUptime(WebsiteResult[] results)
        {
            int barLength = Math.Max(0, GetWidth() - 62);
            foreach (var r in results)
            {
                double uptimePercent = 0.0; int barCount = 0;
                if (uptimeHistory.ContainsKey(r.url))
                {
                    List<bool> history = uptimeHistory[r.url];
                    var dailyHistory = history.Count > 1440 ? history.Skip(history.Count - 1440) : history;
                    int dailyCount = dailyHistory.Count();
                    int greenCount = dailyHistory.Count(x => x);
                    uptimePercent = dailyCount > 0 ? (greenCount * 100.0 / dailyCount) : 0.0;
                    if (!alertLocked.ContainsKey(r.url)) alertLocked[r.url] = false;
                    if (history.Count >= 3)
                    {
                        var lastThree = history.Skip(history.Count - 3);
                        if (!alertLocked[r.url] && lastThree.All(x => !x)) alertLocked[r.url] = true;
                        else if (alertLocked[r.url] && lastThree.All(x => x)) alertLocked[r.url] = false;
                    }
                    var displayHistory = history.Count > barLength ? history.Skip(history.Count - barLength).ToList() : history;
                    barCount = displayHistory.Count;
                    SetColor(alertLocked[r.url] ? ConsoleColor.Red : ConsoleColor.Gray);
                    SafeWrite(Pad(r.url, 35)); ResetColor();
                    SafeWrite($"{uptimePercent,7:0.00}% ");
                    foreach (bool stat in displayHistory) { SetColor(stat ? ConsoleColor.Green : ConsoleColor.Red); SafeWrite("|"); ResetColor(); }
                }
                else
                {
                    SafeWrite($"{Pad(r.url, 35)}{uptimePercent,7:0.00}% ");
                }
                int remaining = barLength - barCount;
                if (remaining > 0) { SetColor(ConsoleColor.Gray); SafeWrite(new string('|', remaining)); ResetColor(); }
                SafeWriteLine();
            }
        }
        static async Task LogResults(WebsiteResult[] results)
        {
            try
            {
                string path = Path.Combine(scriptDir, config.Monitor.log_file_path);
                var log = new
                {
                    timestamp = DateTime.Now.ToString("o"),
                    results = results.Select(r => new { r.url, r.ip, r.status, r.code, r.duration_ms, r.retries, http_method = r.http_method })
                };
                string json = JsonSerializer.Serialize(log);
                await File.AppendAllTextAsync(path, json + Environment.NewLine);
            }
            catch (Exception ex) { SafeWriteLine($"Ошибка логирования: {ex.Message}"); }
        }
        static string CenterInBox(string s, int width)
        {
            if (s.Length > width) return s.Substring(0, width);
            int pad = (width - s.Length) / 2;
            return new string(' ', pad) + s + new string(' ', width - s.Length - pad);
        }
        static string FormatRow7(string a, int aw, string b, int bw, string c, int cw, string d, int dw, string e, int ew, string f, int fw, string g, int gw)
        {
            return $"{Pad(a, aw)} {Pad(b, bw)} {Pad(c, cw)} {Pad(d, dw)} {Pad(e, ew)} {Pad(f, fw)} {Pad(g, gw)}";
        }
        static int GetWidth() { try { return Math.Max(50, Console.WindowWidth); } catch { return 100; } }
        static int GetHeight() { try { return Math.Max(10, Console.WindowHeight); } catch { return 30; } }
        static int GetCursorTop() { try { return Console.CursorTop; } catch { return 0; } }
        static void SafeClear() { try { Console.Clear(); } catch { } }
        static void SafeWrite(string s) { try { Console.Write(s); } catch { } }
        static void SafeWriteLine(string? s = "") { try { Console.WriteLine(s); } catch { } }
        static void SetColor(ConsoleColor c) { try { Console.ForegroundColor = c; } catch { } }
        static void ResetColor() { try { Console.ResetColor(); } catch { } }
        static void WriteCentered(string text, ConsoleColor? color)
        {
            int width = GetWidth();
            if (color.HasValue) SetColor(color.Value);
            SafeWriteLine(text.PadLeft((width + text.Length) / 2));
            if (color.HasValue) ResetColor();
        }
        static void SafeSetCursorPosition(int left, int top)
        {
            try
            {
                left = Math.Max(0, Math.Min(left, Math.Max(0, GetWidth() - 1)));
                top = Math.Max(0, top);
                Console.SetCursorPosition(left, top);
            }
            catch { }
        }
        static bool ConsoleIsInteractive() { try { _ = Console.KeyAvailable; return true; } catch { return false; } }
        static string Pad(string s, int len) { if (s.Length > len) return s.Substring(0, Math.Max(0, len)); return s.PadRight(len); }
    }
}
