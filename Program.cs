using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Net.Http;
using System.Net.Security;
using System.Net.Http.Headers;
using System.Diagnostics;
namespace SiteMonitor
{
    // region Config Models
    public class MonitorSettings
    {
        public int interval { get; set; } = 60;
        public int timeout { get; set; } = 5;
        public int retries_max { get; set; } = 2;
        public List<int> valid_status_codes { get; set; } = new() { 200, 201, 202, 204, 300, 301, 302, 303, 307, 308, 418 };
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
        public long log_max_size_mb { get; set; } = 10;
        public bool log_rotate_daily { get; set; } = true;
    }
    public class WebhookSettings
    {
        public bool enabled { get; set; } = false;
        public string telegram_bot_token { get; set; } = "";
        public string telegram_chat_id { get; set; } = "";
        public string discord_webhook_url { get; set; } = "";
        public string slack_webhook_url { get; set; } = "";
        public bool notify_on_down { get; set; } = true;
        public bool notify_on_recovery { get; set; } = true;
        public int min_failures_before_alert { get; set; } = 3;
    }
    public class WebsiteGroup
    {
        public string name { get; set; } = "";
        public int interval { get; set; } = 60;
        public List<WebsiteEntry> sites { get; set; } = new();
    }
    public class WebsiteEntry
    {
        public string url { get; set; } = "";
        public Dictionary<string, string> headers { get; set; } = new();
    }
    public class ColorTheme
    {
        public string ok { get; set; } = "Green";
        public string warn { get; set; } = "Yellow";
        public string error { get; set; } = "Red";
        public string banner { get; set; } = "Cyan";
        public string header { get; set; } = "Magenta";
        public string fast_ms { get; set; } = "Green";
        public string medium_ms { get; set; } = "Yellow";
        public string slow_ms { get; set; } = "Red";
    }
    public class CsvExportSettings
    {
        public bool enabled { get; set; } = false;
        public string file_path { get; set; } = "results.csv";
    }
    public class Config
    {
        public MonitorSettings monitor_settings { get; set; } = new();
        public List<string> websites { get; set; } = new();
        public List<WebsiteGroup> website_groups { get; set; } = new();
        public MonitorConfig Monitor { get; set; } = new();
        public WebhookSettings webhooks { get; set; } = new();
        public ColorTheme color_theme { get; set; } = new();
        public CsvExportSettings csv_export { get; set; } = new();
        public string uptime_history_path { get; set; } = "uptime_history.json";
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
        public string group_name { get; set; } = "";
    }
    // endregion

    // region Uptime Persistence
    public class UptimeHistoryFile
    {
        public int version { get; set; } = 1;
        public string last_updated { get; set; } = "";
        public Dictionary<string, UptimeSiteData> sites { get; set; } = new();
    }
    public class UptimeSiteData
    {
        public int checks_total { get; set; }
        public int checks_ok { get; set; }
        public string last_status { get; set; } = "";
        public string last_check { get; set; } = "";
        public List<bool> history { get; set; } = new();
    }
    // endregion

    class Program
    {
        static string scriptDir = string.Empty;
        static string configPath = string.Empty;
        static Config config = new();
        static CancellationTokenSource appCts = new();
        static HttpClient client = null!;
        static SocketsHttpHandler handler = null!;
        static HttpClient webhookClient = null!;
        static Dictionary<string, List<bool>> uptimeHistory = new();
        static Dictionary<string, int> failureCount = new();
        static bool configReloaded = false;
        static Dictionary<string, bool> alertLocked = new();
        static Dictionary<string, bool> alertSent = new();
        static Dictionary<string, ConsoleColor> theme = new();
        static WebsiteResult[] lastResults = Array.Empty<WebsiteResult>();
        static bool paused = false;
        static string currentSortMode = "status";

        // Resolved flat list of sites (from groups or flat websites)
        static List<(string url, string group, Dictionary<string, string> headers)> resolvedSites = new();

        static async Task Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            scriptDir = AppDomain.CurrentDomain.BaseDirectory;
            configPath = Path.Combine(scriptDir, "config.json");
            Console.CancelKeyPress += (s, e) => { e.Cancel = true; appCts.Cancel(); };
            config = LoadOrCreateConfigWithMessage();
            InitTheme();
            ResolveSiteList();
            SafeClear();
            PrintBanner();
            StartHttpClient();
            StartWebhookClient();
            LoadUptimeHistory();
            var ct = appCts.Token;
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    if (paused)
                    {
                        SafeSetCursorPosition(0, GetCursorTop());
                        SetColor(ConsoleColor.DarkCyan); SafeWrite(" ┃ ");
                        SetColor(theme["warn"]); SafeWrite("⏸ ПАУЗА"); ResetColor();
                        SetColor(ConsoleColor.DarkGray); SafeWrite("  Нажмите ");
                        SetColor(ConsoleColor.Cyan); SafeWrite("P");
                        SetColor(ConsoleColor.DarkGray); SafeWrite(" для продолжения...");
                        ResetColor();
                        if (ConsoleIsInteractive() && Console.KeyAvailable)
                        {
                            var key = Console.ReadKey(true);
                            if (key.Key == ConsoleKey.P) paused = false;
                        }
                        try { await Task.Delay(200, ct); } catch (OperationCanceledException) { break; }
                        continue;
                    }
                    var startTime = DateTime.Now;
                    int total = resolvedSites.Count;
                    int done = 0;
                    using var overlayCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    var overlayTask = RunOverlayAsync(total, () => Volatile.Read(ref done), overlayCts.Token);
                    var tasks = resolvedSites.Select(site => CheckWebsiteWrapped(site.url, site.group, site.headers, () => Interlocked.Increment(ref done), ct)).ToArray();
                    var results = await Task.WhenAll(tasks);
                    overlayCts.Cancel();
                    try { await overlayTask; } catch { }
                    results = SortResults(results);
                    lastResults = results;
                    SafeClear();
                    PrintBanner();
                    PrintSystemInfo();
                    SafeWrite("  ");
                    SetColor(ConsoleColor.DarkGray);
                    SafeWriteLine($"Последняя проверка: {startTime:yyyy-MM-dd HH:mm:ss}");
                    ResetColor();
                    SafeWriteLine();
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
                        SetColor(ConsoleColor.DarkCyan);
                        SafeWriteLine("  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓");
                        SafeWrite("  ┃"); SetColor(ConsoleColor.White); SafeWrite(CenterInBox("АПТАЙМ ЗА СУТКИ", 50)); SetColor(ConsoleColor.DarkCyan); SafeWriteLine("┃");
                        SafeWriteLine("  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛");
                        ResetColor();
                        PrintUptime(results);
                        SaveUptimeHistory();
                    }
                    // Failure tracking + webhook alerts
                    foreach (var r in results)
                    {
                        if (!failureCount.ContainsKey(r.url)) failureCount[r.url] = 0;
                        if (!alertSent.ContainsKey(r.url)) alertSent[r.url] = false;
                        if (r.status == "OK" || r.status == "WARN")
                        {
                            if (alertSent[r.url] && config.webhooks.enabled && config.webhooks.notify_on_recovery)
                            {
                                _ = SendAllWebhooksAsync($"✅ ВОССТАНОВЛЕН: {r.url}\nСтатус: {r.status} ({r.code})\nВремя: {r.duration_ms}мс", ct);
                            }
                            failureCount[r.url] = 0;
                            alertSent[r.url] = false;
                        }
                        else
                        {
                            failureCount[r.url]++;
                            if (failureCount[r.url] == config.webhooks.min_failures_before_alert)
                            {
                                SetColor(ConsoleColor.DarkCyan); SafeWrite("  ┃ ");
                                SetColor(theme["error"]);
                                SafeWrite($"⚠ АЛЕРТ");
                                SetColor(theme["warn"]);
                                SafeWriteLine($" {r.url} — {config.webhooks.min_failures_before_alert}x подряд недоступен! ({r.status})");
                                ResetColor();
                                if (config.webhooks.enabled && config.webhooks.notify_on_down)
                                {
                                    alertSent[r.url] = true;
                                    _ = SendAllWebhooksAsync($"🔴 НЕДОСТУПЕН: {r.url}\nСтатус: {r.status} ({r.code})\nОшибка: {r.error_type}\nНедоступен {failureCount[r.url]} раз подряд", ct);
                                }
                            }
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
                    if (configReloaded)
                    {
                        configReloaded = false;
                        var currentUrls = new HashSet<string>(resolvedSites.Select(s => s.url));
                        foreach (var key in uptimeHistory.Keys.Where(k => !currentUrls.Contains(k)).ToList()) uptimeHistory.Remove(key);
                        foreach (var key in failureCount.Keys.Where(k => !currentUrls.Contains(k)).ToList()) failureCount.Remove(key);
                        foreach (var key in alertLocked.Keys.Where(k => !currentUrls.Contains(k)).ToList()) alertLocked.Remove(key);
                        foreach (var key in alertSent.Keys.Where(k => !currentUrls.Contains(k)).ToList()) alertSent.Remove(key);
                    }
                    if (config.Monitor.logging_enabled) await LogResults(results);
                    if (config.csv_export.enabled) await ExportCsv(results);
                    SafeWriteLine();
                    int countdownLine = GetCursorTop();
                    int totalDelay = Math.Max(1, config.monitor_settings.interval) * 1000;
                    int delayStep = 100;
                    int elapsed = 0;
                    bool breakNow = false;
                    while (elapsed < totalDelay && !ct.IsCancellationRequested)
                    {
                        int remaining = totalDelay - elapsed;
                        int remainingSec = (remaining + 999) / 1000;
                        int totalBars = 20;
                        int filledBars = Math.Clamp(totalBars - (remaining * totalBars) / Math.Max(1, totalDelay), 0, totalBars);
                        string progressBar = new string('█', filledBars) + new string('░', totalBars - filledBars);
                        SafeSetCursorPosition(0, countdownLine);
                        SetColor(ConsoleColor.DarkCyan); SafeWrite(" ┃ "); ResetColor();
                        SetColor(ConsoleColor.Cyan); SafeWrite("R"); SetColor(ConsoleColor.DarkGray); SafeWrite(" Обновить ");
                        SetColor(ConsoleColor.Cyan); SafeWrite("L"); SetColor(ConsoleColor.DarkGray); SafeWrite(" Лог ");
                        SetColor(ConsoleColor.Cyan); SafeWrite("P"); SetColor(ConsoleColor.DarkGray); SafeWrite(" Пауза ");
                        SetColor(ConsoleColor.Cyan); SafeWrite("S"); SetColor(ConsoleColor.DarkGray); SafeWrite(" Сорт ");
                        SetColor(ConsoleColor.Cyan); SafeWrite("E"); SetColor(ConsoleColor.DarkGray); SafeWrite(" CSV ");
                        SetColor(ConsoleColor.DarkCyan); SafeWrite("┃ "); ResetColor();
                        SetColor(ConsoleColor.Green); SafeWrite(progressBar); ResetColor();
                        SetColor(ConsoleColor.DarkGray); SafeWrite($" {remainingSec}s "); ResetColor();
                        SetColor(ConsoleColor.DarkCyan); SafeWrite("┃ ");
                        SetColor(ConsoleColor.Red); SafeWrite("Ctrl+C"); SetColor(ConsoleColor.DarkGray); SafeWrite(" Выход");
                        ResetColor();
                        SafeWrite("     "); // clear trailing chars
                        if (ConsoleIsInteractive() && Console.KeyAvailable)
                        {
                            var key = Console.ReadKey(true);
                            if (key.Key == ConsoleKey.R)
                            {
                                config = LoadOrCreateConfigWithMessage();
                                InitTheme();
                                ResolveSiteList();
                                RestartHttpClient();
                                configReloaded = true;
                                breakNow = true;
                                break;
                            }
                            else if (key.Key == ConsoleKey.L)
                            {
                                config.Monitor.logging_enabled = !config.Monitor.logging_enabled;
                                SafeSetCursorPosition(0, countdownLine + 1);
                                SetColor(ConsoleColor.DarkCyan); SafeWrite(" ┃ ");
                                SetColor(config.Monitor.logging_enabled ? theme["ok"] : theme["warn"]);
                                SafeWrite(config.Monitor.logging_enabled ? "● Логирование ВКЛЮЧЕНО  " : "○ Логирование ВЫКЛЮЧЕНО ");
                                ResetColor();
                            }
                            else if (key.Key == ConsoleKey.P)
                            {
                                paused = true;
                                breakNow = true;
                                break;
                            }
                            else if (key.Key == ConsoleKey.S)
                            {
                                currentSortMode = currentSortMode switch { "status" => "url", "url" => "duration", _ => "status" };
                                config.monitor_settings.sorted = currentSortMode;
                                SafeSetCursorPosition(0, countdownLine + 1);
                                SetColor(ConsoleColor.DarkCyan); SafeWrite(" ┃ ");
                                SetColor(ConsoleColor.Cyan);
                                SafeWrite($"↕ Сортировка: {currentSortMode}       ");
                                ResetColor();
                            }
                            else if (key.Key == ConsoleKey.E)
                            {
                                await ExportCsv(lastResults);
                                SafeSetCursorPosition(0, countdownLine + 1);
                                SetColor(ConsoleColor.DarkCyan); SafeWrite(" ┃ ");
                                SetColor(theme["ok"]);
                                SafeWrite($"✓ CSV экспортирован: {config.csv_export.file_path}       ");
                                ResetColor();
                            }
                        }
                        try { await Task.Delay(delayStep, ct); } catch (OperationCanceledException) { break; }
                        elapsed += delayStep;
                    }
                    if (!breakNow) SafeWriteLine();
                }
            }
            catch (OperationCanceledException) { }
            finally
            {
                try { client?.Dispose(); } catch { }
                try { handler?.Dispose(); } catch { }
                try { webhookClient?.Dispose(); } catch { }
                appCts.Dispose();
            }
        }

        // region Site Resolution
        static void ResolveSiteList()
        {
            resolvedSites.Clear();
            if (config.website_groups != null && config.website_groups.Count > 0)
            {
                foreach (var group in config.website_groups)
                    foreach (var site in group.sites)
                        if (!string.IsNullOrWhiteSpace(site.url))
                            resolvedSites.Add((site.url, group.name, site.headers ?? new()));
            }
            else
            {
                foreach (var url in config.websites)
                    resolvedSites.Add((url, "", new Dictionary<string, string>()));
            }
        }
        // endregion

        // region Theme
        static void InitTheme()
        {
            theme.Clear();
            var ct = config.color_theme ?? new ColorTheme();
            theme["ok"] = ParseColor(ct.ok, ConsoleColor.Green);
            theme["warn"] = ParseColor(ct.warn, ConsoleColor.Yellow);
            theme["error"] = ParseColor(ct.error, ConsoleColor.Red);
            theme["banner"] = ParseColor(ct.banner, ConsoleColor.Cyan);
            theme["header"] = ParseColor(ct.header, ConsoleColor.Magenta);
            theme["fast_ms"] = ParseColor(ct.fast_ms, ConsoleColor.Green);
            theme["medium_ms"] = ParseColor(ct.medium_ms, ConsoleColor.Yellow);
            theme["slow_ms"] = ParseColor(ct.slow_ms, ConsoleColor.Red);
        }
        static ConsoleColor ParseColor(string name, ConsoleColor fallback)
        {
            if (Enum.TryParse<ConsoleColor>(name, true, out var c)) return c;
            return fallback;
        }
        // endregion

        // region Sorting
        static WebsiteResult[] SortResults(WebsiteResult[] results)
        {
            return currentSortMode switch
            {
                "url" => results.OrderBy(r => r.url).ToArray(),
                "duration" => results.OrderBy(r => r.duration_ms).ToArray(),
                _ => results.OrderBy(r => r.status != "OK" && r.status != "WARN").ThenBy(r => r.url).ToArray()
            };
        }
        // endregion

        static async Task<WebsiteResult> CheckWebsiteWrapped(string site, string groupName, Dictionary<string, string> headers, Action onDone, CancellationToken ct)
        {
            try
            {
                var result = await CheckWebsiteAsync(site, headers, ct);
                result.group_name = groupName;
                return result;
            }
            finally { onDone(); }
        }
        static async Task RunOverlayAsync(int total, Func<int> getDone, CancellationToken token)
        {
            var sw = Stopwatch.StartNew();
            string[] frames = new[] { "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏" };
            int i = 0;
            while (!token.IsCancellationRequested)
            {
                int done = getDone();
                double pct = total > 0 ? done * 100.0 / total : 0;
                int barW = 20;
                int filled = (int)(barW * pct / 100);
                string progressBar = new string('█', filled) + new string('░', barW - filled);
                string t1 = $"  {frames[i % frames.Length]}  СКАНИРОВАНИЕ  {frames[i % frames.Length]}  ";
                string t2 = $"  [{progressBar}] {pct:0}%  ";
                string t3 = $"  Готово {done}/{total}  ·  {sw.Elapsed:mm\\:ss\\.f}  ";
                int ww = GetWidth(); int h = GetHeight();
                int boxW = Math.Max(Math.Max(Math.Max(t1.Length, t2.Length), t3.Length) + 4, 36);
                int left = Math.Max(0, (ww - boxW) / 2);
                int top = Math.Max(0, (h - 6) / 2);
                string horiz = new string('═', boxW - 2);

                SafeSetCursorPosition(left, top);
                SetColor(ConsoleColor.Cyan); SafeWrite("╔" + horiz + "╗");
                SafeSetCursorPosition(left, top + 1); SafeWrite("║" + CenterInBox("", boxW - 2) + "║");
                SafeSetCursorPosition(left, top + 2); SafeWrite("║"); SetColor(ConsoleColor.White); SafeWrite(CenterInBox(t1, boxW - 2)); SetColor(ConsoleColor.Cyan); SafeWrite("║");
                SafeSetCursorPosition(left, top + 3); SafeWrite("║"); SetColor(ConsoleColor.Green); SafeWrite(CenterInBox(t2, boxW - 2)); SetColor(ConsoleColor.Cyan); SafeWrite("║");
                SafeSetCursorPosition(left, top + 4); SafeWrite("║"); SetColor(ConsoleColor.DarkGray); SafeWrite(CenterInBox(t3, boxW - 2)); SetColor(ConsoleColor.Cyan); SafeWrite("║");
                SafeSetCursorPosition(left, top + 5); SafeWrite("╚" + horiz + "╝"); ResetColor();
                try { await Task.Delay(100, token); } catch { break; }
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
        static void StartWebhookClient()
        {
            webhookClient = new HttpClient();
            webhookClient.Timeout = TimeSpan.FromSeconds(10);
        }
        static void RestartHttpClient()
        {
            try { client?.Dispose(); } catch { }
            try { handler?.Dispose(); } catch { }
            StartHttpClient();
        }
        static void PrintBanner()
        {
            int w = GetWidth();
            string border = new string('=', w);
            string title = "S I T E   M O N I T O R";
            string version = "v2.0.0  |  Full Edition";
            string sub = "[ Monitoring Dashboard ]";

            SetColor(theme["banner"]);
            SafeWriteLine(border);
            SafeWriteLine();
            WriteCentered(title, null);
            WriteCentered(sub, null);
            WriteCentered(version, null);
            SafeWriteLine();
            SafeWriteLine(border);
            ResetColor();
        }
        static void PrintSystemInfo()
        {
            int w = GetWidth();
            int siteCount = resolvedSites.Count;
            int groupCount = config.website_groups?.Count(g => g.sites.Count > 0) ?? 0;
            string intervalStr = $"{config.monitor_settings.interval}s";
            string timeoutStr = $"{config.monitor_settings.timeout}s";
            string retriesStr = config.monitor_settings.retries_max.ToString();
            string sortStr = currentSortMode;
            string methodStr = config.monitor_settings.use_head_first ? "HEAD→GET" : "GET";
            string pingStr = config.monitor_settings.ping_enabled ? "ON" : "OFF";
            string logStr = config.Monitor.logging_enabled ? "ON" : "OFF";
            string webhookStr = config.webhooks.enabled ? "ON" : "OFF";

            string top    = "┌" + new string('─', w - 2) + "┐";
            string mid    = "├" + new string('─', w - 2) + "┤";
            string bottom = "└" + new string('─', w - 2) + "┘";
            SetColor(ConsoleColor.DarkCyan);
            SafeWriteLine(top);
            SetColor(ConsoleColor.Cyan);
            SafeWrite("│ "); SetColor(ConsoleColor.White);
            SafeWrite("СИСТЕМА"); SetColor(ConsoleColor.DarkGray);
            string sysInfo = $"  Сайтов: {siteCount}  ·  Групп: {groupCount}  ·  Интервал: {intervalStr}  ·  Таймаут: {timeoutStr}  ·  Ретраи: {retriesStr}";
            SafeWrite(sysInfo);
            int sysRemain = Math.Max(0, w - 4 - 7 - sysInfo.Length);
            SafeWrite(new string(' ', sysRemain));
            SetColor(ConsoleColor.DarkCyan);
            SafeWriteLine(" │");

            SafeWriteLine(mid);
            SetColor(ConsoleColor.Cyan);
            SafeWrite("│ "); SetColor(ConsoleColor.White);
            SafeWrite("НАСТРОЙКИ"); SetColor(ConsoleColor.DarkGray);
            string cfgInfo = $"  Метод: {methodStr}  ·  Пинг: {pingStr}  ·  Сорт: {sortStr}  ·  Лог: {logStr}  ·  Вебхуки: {webhookStr}";
            SafeWrite(cfgInfo);
            int cfgRemain = Math.Max(0, w - 4 - 9 - cfgInfo.Length);
            SafeWrite(new string(' ', cfgRemain));
            SetColor(ConsoleColor.DarkCyan);
            SafeWriteLine(" │");

            SafeWriteLine(bottom);
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
                    if (conf.webhooks == null) conf.webhooks = new WebhookSettings();
                    if (conf.color_theme == null) conf.color_theme = new ColorTheme();
                    if (conf.csv_export == null) conf.csv_export = new CsvExportSettings();
                    if (conf.website_groups == null) conf.website_groups = new List<WebsiteGroup>();
                    if ((conf.websites == null || conf.websites.Count == 0) && conf.website_groups.Count == 0)
                        conf.websites = def.websites;
                    NormalizeSettings(conf.monitor_settings, def.monitor_settings);
                    if (conf.monitor_settings.sorted != "status" && conf.monitor_settings.sorted != "url" && conf.monitor_settings.sorted != "duration")
                        conf.monitor_settings.sorted = "status";
                    currentSortMode = conf.monitor_settings.sorted;
                    ValidateUrls(conf);
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
        static void ValidateUrls(Config conf)
        {
            var valid = new List<string>();
            foreach (var url in conf.websites)
            {
                if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out var uri) || (uri.Scheme != "http" && uri.Scheme != "https"))
                {
                    SetColor(theme.GetValueOrDefault("warn", ConsoleColor.Yellow));
                    SafeWriteLine($"[ПРЕДУПРЕЖДЕНИЕ] Невалидный URL пропущен: {url}");
                    ResetColor();
                }
                else valid.Add(url);
            }
            conf.websites = valid;
            foreach (var group in conf.website_groups)
            {
                var validSites = new List<WebsiteEntry>();
                foreach (var site in group.sites)
                {
                    if (string.IsNullOrWhiteSpace(site.url) || !Uri.TryCreate(site.url, UriKind.Absolute, out var uri) || (uri.Scheme != "http" && uri.Scheme != "https"))
                    {
                        SetColor(theme.GetValueOrDefault("warn", ConsoleColor.Yellow));
                        SafeWriteLine($"[ПРЕДУПРЕЖДЕНИЕ] Невалидный URL в группе \"{group.name}\" пропущен: {site.url}");
                        ResetColor();
                    }
                    else validSites.Add(site);
                }
                group.sites = validSites;
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
            Monitor = new MonitorConfig(),
            webhooks = new WebhookSettings(),
            color_theme = new ColorTheme(),
            csv_export = new CsvExportSettings()
        };
        static void SaveConfig(Config conf)
        {
            string json = JsonSerializer.Serialize(conf, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(configPath, json);
        }

        // region Check Website
        static async Task<WebsiteResult> CheckWebsiteAsync(string rawUrl, Dictionary<string, string> customHeaders, CancellationToken ct)
        {
            WebsiteResult result = new() { url = rawUrl, ip = "N/A", status = "INIT", code = "", error_type = "" };
            if (!Uri.TryCreate(rawUrl, UriKind.Absolute, out var uri)) { result.status = "URL_ERROR"; result.code = "ERR"; result.error_type = "URL"; return result; }
            string host = uri.Host;
            var delays = new int[] { 250, 750, 1500 };

            // Parallel ping + DNS
            Task<string> pingTask = config.monitor_settings.ping_enabled ? PingHostAsync(host) : Task.FromResult("");
            Task<string?> dnsTask = ResolveDnsAsync(host, delays, ct);
            await Task.WhenAll(pingTask, (Task)dnsTask);

            string pingError = pingTask.Result;
            if (!string.IsNullOrEmpty(pingError)) result.error_type = pingError;

            string? ip = await dnsTask;
            if (ip == null)
            {
                result.status = "DNS_ERROR"; result.code = "ERR"; result.error_type = "DNS"; return result;
            }
            result.ip = ip;

            int attempts = config.monitor_settings.retries_max + 1;
            int tries = 0;
            string methodUsed = config.monitor_settings.use_head_first ? "HEAD" : "GET";
            Exception? lastEx = null;
            long totalDuration = 0;
            while (tries < attempts)
            {
                tries++;
                try
                {
                    var sw = Stopwatch.StartNew();
                    var attempt = await SendOnce(uri, methodUsed, customHeaders, ct);
                    sw.Stop();
                    totalDuration += sw.ElapsedMilliseconds;
                    int statusCode = (int)attempt.response.StatusCode;
                    if (methodUsed == "HEAD" && (statusCode == 405 || statusCode == 501))
                    {
                        attempt.response.Dispose();
                        methodUsed = "GET";
                        if (tries < attempts)
                            try { await Task.Delay(Math.Min(delays[Math.Min(tries - 1, delays.Length - 1)], 2000), ct); } catch (OperationCanceledException) { break; }
                        continue;
                    }
                    result.duration_ms = totalDuration;
                    result.retries = tries - 1;
                    result.http_method = attempt.method;
                    bool ok = config.monitor_settings.valid_status_codes.Contains(statusCode);
                    bool warn = !ok && config.monitor_settings.warn_status_codes.Contains(statusCode);
                    result.code = statusCode.ToString();
                    if (ok) { result.status = "OK"; result.error_type = string.Empty; }
                    else if (warn) { result.status = "WARN"; result.error_type = "PARTIAL"; }
                    else { result.status = "HTTP_ERROR"; result.error_type = "HTTP"; }
                    attempt.response.Dispose();
                    return result;
                }
                catch (TaskCanceledException ex) when (!ct.IsCancellationRequested)
                {
                    lastEx = ex;
                    if (tries >= attempts) break;
                    try { await Task.Delay(Math.Min(delays[Math.Min(tries - 1, delays.Length - 1)], 2000), ct); } catch (OperationCanceledException) { break; }
                }
                catch (HttpRequestException ex)
                {
                    lastEx = ex;
                    if (IsTransientStatus(ex.StatusCode))
                    {
                        if (tries >= attempts) break;
                        try { await Task.Delay(Math.Min(delays[Math.Min(tries - 1, delays.Length - 1)], 2000), ct); } catch (OperationCanceledException) { break; }
                    }
                    else break;
                }
                catch (AuthenticationException ex) { lastEx = ex; break; }
                catch (OperationCanceledException) { break; }
                catch (Exception ex)
                {
                    lastEx = ex;
                    if (tries >= attempts) break;
                    try { await Task.Delay(Math.Min(delays[Math.Min(tries - 1, delays.Length - 1)], 2000), ct); } catch (OperationCanceledException) { break; }
                }
            }
            result.duration_ms = totalDuration;
            result.retries = Math.Max(0, tries - 1);
            result.http_method = methodUsed;
            if (lastEx is AuthenticationException || (lastEx is HttpRequestException hre && hre.InnerException is AuthenticationException))
            { result.status = "SSL_ERROR"; result.code = "SSL"; result.error_type = "SSL"; }
            else if (lastEx is TaskCanceledException)
            { result.status = "TIMEOUT"; result.code = "T/O"; result.error_type = "TIMEOUT"; }
            else if (lastEx is HttpRequestException ex2 && (ex2.StatusCode == HttpStatusCode.Redirect || ex2.StatusCode == HttpStatusCode.RedirectKeepVerb || ex2.StatusCode == HttpStatusCode.RedirectMethod))
            { result.status = "REDIRECT_LOOP"; result.code = "3xx"; result.error_type = "REDIRECT"; }
            else
            { result.status = "CONN_ERROR"; result.code = "ERR"; result.error_type = "NETWORK"; }
            return result;
        }
        static async Task<string> PingHostAsync(string host)
        {
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(host, 2000);
                if (reply.Status != IPStatus.Success && reply.Status != IPStatus.TimedOut) return "ICMP";
                return "";
            }
            catch { return "ICMP_EX"; }
        }
        static async Task<string?> ResolveDnsAsync(string host, int[] delays, CancellationToken ct)
        {
            for (int attempt = 0; attempt <= config.monitor_settings.retries_max; attempt++)
            {
                try
                {
                    var entry = await Dns.GetHostEntryAsync(host);
                    return entry.AddressList.FirstOrDefault()?.ToString() ?? "N/A";
                }
                catch
                {
                    if (attempt >= config.monitor_settings.retries_max) return null;
                    try { await Task.Delay(delays[Math.Min(attempt, delays.Length - 1)], ct); } catch (OperationCanceledException) { return null; }
                }
            }
            return null;
        }
        // endregion

        static bool IsTransientStatus(HttpStatusCode? sc)
        {
            if (!sc.HasValue) return true;
            int s = (int)sc.Value;
            if (s == 408 || s == 425 || s == 429) return true;
            if (s >= 500 && s <= 504) return true;
            return false;
        }
        static async Task<(HttpResponseMessage response, string method)> SendOnce(Uri uri, string methodPreference, Dictionary<string, string> customHeaders, CancellationToken ct)
        {
            var method = methodPreference == "HEAD" ? HttpMethod.Head : HttpMethod.Get;
            var req = new HttpRequestMessage(method, uri);
            req.Version = new Version(2, 0);
            req.VersionPolicy = HttpVersionPolicy.RequestVersionOrLower;
            if (customHeaders != null)
                foreach (var (key, value) in customHeaders)
                    req.Headers.TryAddWithoutValidation(key, value);
            var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
            return (resp, methodPreference);
        }

        // region Display
        static void PrintResults(WebsiteResult[] results)
        {
            int w = GetWidth();
            bool hasGroups = resolvedSites.Any(s => !string.IsNullOrEmpty(s.group));
            // Column widths (inner content, excluding border chars)
            int statW = 10, ipW = 16, codeW = 5, methodW = 6, retryW = 5, durW = 8;
            int groupW = hasGroups ? 12 : 0;
            int colCount = hasGroups ? 8 : 7;
            int bordersWidth = 1 + colCount + 1; // outer borders + inner separators
            int siteW = Math.Max(16, w - (statW + ipW + codeW + methodW + retryW + durW + groupW + bordersWidth));

            // Build horizontal lines
            string MakeHLine(char left, char mid, char right, char fill, params int[] widths)
            {
                var sb = new StringBuilder();
                sb.Append(left);
                for (int i = 0; i < widths.Length; i++)
                {
                    sb.Append(new string(fill, widths[i]));
                    sb.Append(i < widths.Length - 1 ? mid : right);
                }
                return sb.ToString();
            }
            int[] cols = hasGroups
                ? new[] { statW, siteW, groupW, ipW, codeW, methodW, retryW, durW }
                : new[] { statW, siteW, ipW, codeW, methodW, retryW, durW };

            string topLine = MakeHLine('┌', '┬', '┐', '─', cols);
            string hdrLine = MakeHLine('├', '┼', '┤', '─', cols);
            string botLine = MakeHLine('└', '┴', '┘', '─', cols);

            void WriteTableRow(params (string text, int width, ConsoleColor? color)[] cells)
            {
                SetColor(ConsoleColor.DarkCyan); SafeWrite("│"); ResetColor();
                for (int i = 0; i < cells.Length; i++)
                {
                    if (cells[i].color is ConsoleColor c) SetColor(c);
                    SafeWrite(Pad(cells[i].text, cells[i].width));
                    ResetColor();
                    SetColor(ConsoleColor.DarkCyan); SafeWrite("│"); ResetColor();
                }
                SafeWriteLine();
            }

            // Table header
            SetColor(ConsoleColor.DarkCyan);
            SafeWriteLine(topLine);
            ResetColor();

            if (hasGroups)
                WriteTableRow(
                    ("  Статус", statW, theme["header"]),
                    ("  Сайт", siteW, theme["header"]),
                    ("  Группа", groupW, theme["header"]),
                    ("  IP", ipW, theme["header"]),
                    (" Код", codeW, theme["header"]),
                    (" Метод", methodW, theme["header"]),
                    (" Повт", retryW, theme["header"]),
                    ("   мс", durW, theme["header"]));
            else
                WriteTableRow(
                    ("  Статус", statW, theme["header"]),
                    ("  Сайт", siteW, theme["header"]),
                    ("  IP", ipW, theme["header"]),
                    (" Код", codeW, theme["header"]),
                    (" Метод", methodW, theme["header"]),
                    (" Повт", retryW, theme["header"]),
                    ("   мс", durW, theme["header"]));

            SetColor(ConsoleColor.DarkCyan);
            SafeWriteLine(hdrLine);
            ResetColor();

            // Data rows
            int avail = 0;
            foreach (var r in results)
            {
                ConsoleColor statusColor = r.status == "OK" ? theme["ok"] : r.status == "WARN" ? theme["warn"] : theme["error"];
                string statusIcon = r.status == "OK" ? " ● " : r.status == "WARN" ? " ▲ " : " ✖ ";
                ConsoleColor durColor = r.duration_ms < 500 ? theme["fast_ms"] : r.duration_ms <= 2000 ? theme["medium_ms"] : theme["slow_ms"];

                if (hasGroups)
                    WriteTableRow(
                        (statusIcon + r.status, statW, statusColor),
                        (" " + r.url, siteW, (ConsoleColor?)ConsoleColor.White),
                        (" " + r.group_name, groupW, (ConsoleColor?)ConsoleColor.DarkGray),
                        (" " + r.ip, ipW, (ConsoleColor?)ConsoleColor.Gray),
                        (" " + r.code, codeW, (ConsoleColor?)null),
                        (" " + r.http_method, methodW, (ConsoleColor?)ConsoleColor.DarkGray),
                        (" " + r.retries.ToString(), retryW, (ConsoleColor?)null),
                        (r.duration_ms.ToString().PadLeft(durW), durW, durColor));
                else
                    WriteTableRow(
                        (statusIcon + r.status, statW, statusColor),
                        (" " + r.url, siteW, (ConsoleColor?)ConsoleColor.White),
                        (" " + r.ip, ipW, (ConsoleColor?)ConsoleColor.Gray),
                        (" " + r.code, codeW, (ConsoleColor?)null),
                        (" " + r.http_method, methodW, (ConsoleColor?)ConsoleColor.DarkGray),
                        (" " + r.retries.ToString(), retryW, (ConsoleColor?)null),
                        (r.duration_ms.ToString().PadLeft(durW), durW, durColor));

                if (r.status == "OK" || r.status == "WARN") avail++;
            }

            SetColor(ConsoleColor.DarkCyan);
            SafeWriteLine(botLine);
            ResetColor();

            // Summary line
            double pct = results.Length > 0 ? avail * 100.0 / results.Length : 0;
            ConsoleColor sumColor = pct >= 90 ? theme["ok"] : pct >= 50 ? theme["warn"] : theme["error"];
            SafeWrite("  ");
            SetColor(sumColor);
            SafeWrite($"● {avail}/{results.Length} доступно ({pct:0.0}%)");
            ResetColor();
            SafeWrite("  ");
            SetColor(ConsoleColor.DarkGray);
            SafeWriteLine($"Сортировка: {currentSortMode}");
            ResetColor();
            SafeWriteLine();
        }
        static void PrintUptime(WebsiteResult[] results)
        {
            int w = GetWidth();
            int urlW = 30;
            int pctW = 9; // " 99.99% "
            int barLength = Math.Max(0, w - urlW - pctW - 6); // 6 for borders + spaces

            string topLine = "┌" + new string('─', urlW) + "┬" + new string('─', pctW) + "┬" + new string('─', barLength + 2) + "┐";
            string hdrLine = "├" + new string('─', urlW) + "┼" + new string('─', pctW) + "┼" + new string('─', barLength + 2) + "┤";
            string botLine = "└" + new string('─', urlW) + "┴" + new string('─', pctW) + "┴" + new string('─', barLength + 2) + "┘";

            SetColor(ConsoleColor.DarkCyan); SafeWriteLine(topLine); ResetColor();
            SetColor(ConsoleColor.DarkCyan); SafeWrite("│"); SetColor(theme["header"]); SafeWrite(Pad(" Сайт", urlW));
            SetColor(ConsoleColor.DarkCyan); SafeWrite("│"); SetColor(theme["header"]); SafeWrite(Pad(" Аптайм", pctW));
            SetColor(ConsoleColor.DarkCyan); SafeWrite("│"); SetColor(theme["header"]); SafeWrite(Pad(" За сутки", barLength + 2));
            SetColor(ConsoleColor.DarkCyan); SafeWriteLine("│"); ResetColor();
            SetColor(ConsoleColor.DarkCyan); SafeWriteLine(hdrLine); ResetColor();

            foreach (var r in results)
            {
                double uptimePercent = 0.0; int barCount = 0;
                SetColor(ConsoleColor.DarkCyan); SafeWrite("│"); ResetColor();
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
                    ConsoleColor urlColor = alertLocked.GetValueOrDefault(r.url) ? theme["error"] : ConsoleColor.White;
                    SetColor(urlColor);
                    SafeWrite(Pad(" " + r.url, urlW)); ResetColor();
                    SetColor(ConsoleColor.DarkCyan); SafeWrite("│");
                    ConsoleColor pctColor = uptimePercent >= 99 ? theme["ok"] : uptimePercent >= 90 ? theme["warn"] : theme["error"];
                    SetColor(pctColor);
                    SafeWrite($"{uptimePercent,7:0.00}% "); ResetColor();
                    SetColor(ConsoleColor.DarkCyan); SafeWrite("│"); SafeWrite(" ");
                    foreach (bool stat in displayHistory) { SetColor(stat ? theme["ok"] : theme["error"]); SafeWrite("█"); ResetColor(); }
                    int remaining = barLength - barCount;
                    if (remaining > 0) { SetColor(ConsoleColor.DarkGray); SafeWrite(new string('░', remaining)); ResetColor(); }
                    SafeWrite(" ");
                }
                else
                {
                    SetColor(ConsoleColor.White); SafeWrite(Pad(" " + r.url, urlW)); ResetColor();
                    SetColor(ConsoleColor.DarkCyan); SafeWrite("│");
                    SetColor(ConsoleColor.DarkGray); SafeWrite($"{uptimePercent,7:0.00}% "); ResetColor();
                    SetColor(ConsoleColor.DarkCyan); SafeWrite("│ ");
                    SetColor(ConsoleColor.DarkGray); SafeWrite(new string('░', barLength)); ResetColor();
                    SafeWrite(" ");
                }
                SetColor(ConsoleColor.DarkCyan); SafeWriteLine("│"); ResetColor();
            }
            SetColor(ConsoleColor.DarkCyan); SafeWriteLine(botLine); ResetColor();
        }
        // endregion

        // region Logging
        static async Task LogResults(WebsiteResult[] results)
        {
            try
            {
                string path = GetCurrentLogPath();
                RotateIfNeeded(path);
                var log = new
                {
                    timestamp = DateTime.Now.ToString("o"),
                    results = results.Select(r => new { r.url, r.ip, r.status, r.code, r.duration_ms, r.retries, r.http_method, r.group_name })
                };
                string json = JsonSerializer.Serialize(log);
                await File.AppendAllTextAsync(path, json + Environment.NewLine);
            }
            catch (Exception ex) { SafeWriteLine($"Ошибка логирования: {ex.Message}"); }
        }
        static string GetCurrentLogPath()
        {
            string basePath = config.Monitor.log_file_path;
            if (config.Monitor.log_rotate_daily)
            {
                string ext = Path.GetExtension(basePath);
                string name = Path.GetFileNameWithoutExtension(basePath);
                basePath = $"{name}_{DateTime.Now:yyyy-MM-dd}{ext}";
            }
            return Path.Combine(scriptDir, basePath);
        }
        static void RotateIfNeeded(string path)
        {
            try
            {
                if (!File.Exists(path)) return;
                long maxBytes = config.Monitor.log_max_size_mb * 1024 * 1024;
                if (new FileInfo(path).Length < maxBytes) return;
                string ext = Path.GetExtension(path);
                string nameNoExt = Path.Combine(Path.GetDirectoryName(path) ?? "", Path.GetFileNameWithoutExtension(path));
                for (int i = 1; i <= 999; i++)
                {
                    string candidate = $"{nameNoExt}_{i:D3}{ext}";
                    if (!File.Exists(candidate)) { File.Move(path, candidate); return; }
                }
            }
            catch { }
        }
        // endregion

        // region CSV Export
        static async Task ExportCsv(WebsiteResult[] results)
        {
            try
            {
                string path = Path.Combine(scriptDir, config.csv_export.file_path);
                bool writeHeader = !File.Exists(path);
                var sb = new StringBuilder();
                if (writeHeader)
                    sb.AppendLine("Timestamp,URL,Group,IP,Status,Code,Method,Retries,DurationMs,UptimePercent");
                string ts = DateTime.Now.ToString("o");
                foreach (var r in results)
                {
                    double uptime = 0;
                    if (uptimeHistory.ContainsKey(r.url))
                    {
                        var h = uptimeHistory[r.url];
                        int ok = h.Count(x => x);
                        uptime = h.Count > 0 ? Math.Round(ok * 100.0 / h.Count, 2) : 0;
                    }
                    sb.AppendLine($"{CsvEscape(ts)},{CsvEscape(r.url)},{CsvEscape(r.group_name)},{CsvEscape(r.ip)},{r.status},{r.code},{r.http_method},{r.retries},{r.duration_ms},{uptime:0.00}");
                }
                await File.AppendAllTextAsync(path, sb.ToString());
            }
            catch (Exception ex) { SafeWriteLine($"Ошибка CSV экспорта: {ex.Message}"); }
        }
        static string CsvEscape(string s)
        {
            if (s.Contains(',') || s.Contains('"') || s.Contains('\n'))
                return "\"" + s.Replace("\"", "\"\"") + "\"";
            return s;
        }
        // endregion

        // region Webhooks
        static async Task SendAllWebhooksAsync(string message, CancellationToken ct)
        {
            try
            {
                var tasks = new List<Task>();
                if (!string.IsNullOrEmpty(config.webhooks.telegram_bot_token) && !string.IsNullOrEmpty(config.webhooks.telegram_chat_id))
                    tasks.Add(SendTelegramAsync(message, ct));
                if (!string.IsNullOrEmpty(config.webhooks.discord_webhook_url))
                    tasks.Add(SendDiscordAsync(message, ct));
                if (!string.IsNullOrEmpty(config.webhooks.slack_webhook_url))
                    tasks.Add(SendSlackAsync(message, ct));
                if (tasks.Count > 0)
                {
                    using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    timeoutCts.CancelAfter(TimeSpan.FromSeconds(10));
                    try { await Task.WhenAll(tasks); } catch { }
                }
            }
            catch { }
        }
        static async Task SendTelegramAsync(string message, CancellationToken ct)
        {
            try
            {
                string url = $"https://api.telegram.org/bot{config.webhooks.telegram_bot_token}/sendMessage";
                var payload = JsonSerializer.Serialize(new { chat_id = config.webhooks.telegram_chat_id, text = message, parse_mode = "HTML" });
                var content = new StringContent(payload, Encoding.UTF8, "application/json");
                await webhookClient.PostAsync(url, content, ct);
            }
            catch (Exception ex) { SafeWriteLine($"[WEBHOOK ОШИБКА] Telegram: {ex.Message}"); }
        }
        static async Task SendDiscordAsync(string message, CancellationToken ct)
        {
            try
            {
                bool isDown = message.Contains("НЕДОСТУПЕН");
                int color = isDown ? 0xFF0000 : 0x00FF00;
                string title = isDown ? "Сайт недоступен" : "Сайт восстановлен";
                var payload = JsonSerializer.Serialize(new
                {
                    embeds = new[]
                    {
                        new { title = title, description = message, color = color }
                    }
                });
                var content = new StringContent(payload, Encoding.UTF8, "application/json");
                await webhookClient.PostAsync(config.webhooks.discord_webhook_url, content, ct);
            }
            catch (Exception ex) { SafeWriteLine($"[WEBHOOK ОШИБКА] Discord: {ex.Message}"); }
        }
        static async Task SendSlackAsync(string message, CancellationToken ct)
        {
            try
            {
                var payload = JsonSerializer.Serialize(new { text = message });
                var content = new StringContent(payload, Encoding.UTF8, "application/json");
                await webhookClient.PostAsync(config.webhooks.slack_webhook_url, content, ct);
            }
            catch (Exception ex) { SafeWriteLine($"[WEBHOOK ОШИБКА] Slack: {ex.Message}"); }
        }
        // endregion

        // region Uptime Persistence
        static void LoadUptimeHistory()
        {
            try
            {
                string path = Path.Combine(scriptDir, config.uptime_history_path);
                if (!File.Exists(path)) return;
                string json = File.ReadAllText(path);
                var data = JsonSerializer.Deserialize<UptimeHistoryFile>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                if (data?.sites == null) return;
                foreach (var (url, siteData) in data.sites)
                {
                    if (siteData.history != null && siteData.history.Count > 0)
                    {
                        uptimeHistory[url] = siteData.history.Count > 1440
                            ? siteData.history.Skip(siteData.history.Count - 1440).ToList()
                            : new List<bool>(siteData.history);
                    }
                }
            }
            catch { }
        }
        static void SaveUptimeHistory()
        {
            try
            {
                string path = Path.Combine(scriptDir, config.uptime_history_path);
                string tmpPath = path + ".tmp";
                var data = new UptimeHistoryFile
                {
                    version = 1,
                    last_updated = DateTime.Now.ToString("o"),
                    sites = new Dictionary<string, UptimeSiteData>()
                };
                foreach (var (url, history) in uptimeHistory)
                {
                    int okCount = history.Count(x => x);
                    data.sites[url] = new UptimeSiteData
                    {
                        checks_total = history.Count,
                        checks_ok = okCount,
                        last_status = history.Count > 0 ? (history[^1] ? "OK" : "ERROR") : "",
                        last_check = DateTime.Now.ToString("o"),
                        history = history.Count > 1440 ? history.Skip(history.Count - 1440).ToList() : history
                    };
                }
                string json = JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(tmpPath, json);
                File.Move(tmpPath, path, true);
            }
            catch { }
        }
        // endregion

        // region Utility
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
        static string FormatRow8(string a, int aw, string b, int bw, string c, int cw, string d, int dw, string e, int ew, string f, int fw, string g, int gw, string h, int hw)
        {
            return $"{Pad(a, aw)} {Pad(b, bw)} {Pad(c, cw)} {Pad(d, dw)} {Pad(e, ew)} {Pad(f, fw)} {Pad(g, gw)} {Pad(h, hw)}";
        }
        static int GetWidth() { try { return Math.Max(50, Console.WindowWidth - 1); } catch { return 100; } }
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
        // endregion
    }
}
