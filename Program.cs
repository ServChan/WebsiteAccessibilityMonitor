using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using System.Text.Json;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;

namespace SiteMonitor
{
    public class MonitorSettings
    {
        public int interval { get; set; } = 60;
        public int timeout { get; set; } = 5;
        public List<int> valid_status_codes { get; set; } = new() { 200, 201, 202, 204, 300, 301, 302, 303, 307, 308 };
        public string sorted { get; set; } = "status";
        public bool ping_enabled { get; set; } = true;
        public bool uptime_enabled { get; set; } = false;
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
        public string url { get; set; }
        public string ip { get; set; }
        public string status { get; set; }
        public string code { get; set; }
        public string error_type { get; set; }
    }

    class Program
    {
        static string scriptDir;
        static string configPath;
        static Config config;
        static bool exitRequested = false;
        static HttpClient client;
        static SocketsHttpHandler handler;
        static Dictionary<string, List<bool>> uptimeHistory = new();

        static async Task Main(string[] args)
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            scriptDir = AppDomain.CurrentDomain.BaseDirectory;
            configPath = Path.Combine(scriptDir, "config.json");
            Console.CancelKeyPress += (s, e) => { e.Cancel = true; exitRequested = true; };
            PrintBanner();
            bool configExists = File.Exists(configPath);
            config = LoadOrCreateConfigWithMessage();
            if (!configExists)
            {
                PrintIntro(config);
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("\nНажмите любую клавишу для начала мониторинга...");
                Console.ResetColor();
                Console.ReadKey(true);
            }
            Console.Clear();
            PrintBanner();
            StartHttpClient();
            while (!exitRequested)
            {
                Console.Clear();
                PrintBanner();
                Console.WriteLine($"Мониторинг начался в: {DateTime.Now:yyyy-MM-dd HH:mm:ss}\n");
                var results = await Task.WhenAll(config.websites.Select(site => CheckWebsiteAsync(site)));
                if (config.monitor_settings.sorted == "status")
                    results = results.OrderBy(r => r.status != "OK").ThenBy(r => r.url).ToArray();
                PrintResults(results);
                if (config.monitor_settings.uptime_enabled)
                {
                    int historyMax = Math.Max(0, Console.WindowWidth - (30 + 3 + 4 + 5));
                    foreach (var r in results)
                    {
                        if (!uptimeHistory.ContainsKey(r.url))
                            uptimeHistory[r.url] = new List<bool>();
                        uptimeHistory[r.url].Add(r.status == "OK");
                        if (uptimeHistory[r.url].Count > historyMax)
                            uptimeHistory[r.url].RemoveAt(0);
                    }
                    PrintUptime(results);
                }
                if (config.Monitor.logging_enabled)
                    await LogResults(results);
                int storedWidth = Console.WindowWidth;
                Console.WriteLine();
                int countdownLine = Console.CursorTop;
                int totalDelay = config.monitor_settings.interval * 1000;
                int delayStep = 100;
                int elapsed = 0;
                bool breakNow = false;
                while (elapsed < totalDelay && !exitRequested)
                {
                    if (Console.WindowWidth != storedWidth)
                    {
                        storedWidth = Console.WindowWidth;
                        Console.Clear();
                        PrintBanner();
                        Console.WriteLine($"Мониторинг начался в: {DateTime.Now:yyyy-MM-dd HH:mm:ss}\n");
                        PrintResults(results);
                        if (config.monitor_settings.uptime_enabled)
                            PrintUptime(results);
                        Console.WriteLine();
                        countdownLine = Console.CursorTop;
                        await Task.Delay(300);
                        continue;
                    }
                    int remainingSeconds = (totalDelay - elapsed + 999) / 1000;
                    Console.SetCursorPosition(0, countdownLine);
                    string part1 = "Нажмите ";
                    Console.Write(part1);
                    Console.ForegroundColor = ConsoleColor.Blue;
                    Console.Write("R");
                    Console.ResetColor();
                    string part2 = " для немедленного обновления или ожидайте ";
                    Console.Write(part2);
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.Write(remainingSeconds);
                    Console.ResetColor();
                    string part3 = " секунд. ";
                    Console.Write(part3);
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Write("Ctrl+C");
                    Console.ResetColor();
                    string part4 = " для выхода.";
                    Console.Write(part4);
                    int currentLength = part1.Length + 1 + part2.Length + remainingSeconds.ToString().Length + part3.Length + "Ctrl+C".Length + part4.Length;
                    if (currentLength < Console.WindowWidth)
                        Console.Write(new string(' ', Console.WindowWidth - currentLength));
                    if (Console.KeyAvailable)
                    {
                        var key = Console.ReadKey(true);
                        if (key.Key == ConsoleKey.R)
                        {
                            config = LoadOrCreateConfigWithMessage();
                            RestartHttpClient();
                            breakNow = true;
                            break;
                        }
                    }
                    await Task.Delay(delayStep);
                    elapsed += delayStep;
                }
                if (!breakNow)
                    Console.WriteLine();
            }
        }

        static void StartHttpClient()
        {
            handler = new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = true };
            client = new HttpClient(handler);
            client.Timeout = TimeSpan.FromSeconds(config.monitor_settings.timeout);
            client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
        }

        static void RestartHttpClient()
        {
            client.Dispose();
            handler.Dispose();
            StartHttpClient();
            Console.Clear();
            PrintBanner();
            Console.WriteLine("Конфигурация обновлена и применена.\n");
        }

        static void PrintBanner()
        {
            int width = Console.WindowWidth;
            string line = new string('=', width);
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(line);
            string title = "МОНИТОРИНГ ДОСТУПНОСТИ САЙТОВ";
            Console.WriteLine(title.PadLeft((width + title.Length) / 2));
            string version = "Версия 1.2.8";
            Console.WriteLine(version.PadLeft((width + version.Length) / 2));
            Console.WriteLine(line);
            Console.ResetColor();
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
                    if (conf.monitor_settings == null)
                        conf.monitor_settings = def.monitor_settings;
                    if (conf.Monitor == null)
                        conf.Monitor = def.Monitor;
                    if (conf.websites == null || conf.websites.Count == 0)
                        conf.websites = def.websites;
                    return conf;
                }
                catch
                {
                    return def;
                }
            }
            else
            {
                Console.WriteLine("Конфигурация не обнаружена.");
                Console.WriteLine("Создаю базовый файл конфигурации...");
                try
                {
                    SaveConfig(def);
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("Файл создан успешно.");
                    Console.ResetColor();
                    return def;
                }
                catch
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Ошибка создания файла!");
                    Console.ResetColor();
                    return def;
                }
            }
        }

        static Config CreateDefaultConfig() => new()
        {
            monitor_settings = new MonitorSettings(),
            websites = new List<string>
            {
                "https://ya.ru", "https://google.com", "https://example.com",
                "https://vk.com", "https://youtube.com", "https://github.com",
                "https://steamcommunity.com", "https://store.steampowered.com", "https://twitch.tv",
                "https://reddit.com", "https://wikipedia.org", "https://x.com",
            },
            Monitor = new MonitorConfig()
        };

        static void SaveConfig(Config conf)
        {
            string json = JsonSerializer.Serialize(conf, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(configPath, json);
        }

        static void PrintIntro(Config conf)
        {
            Console.WriteLine("\nБазовые настройки:");
            Console.WriteLine($"Интервал обновления: {conf.monitor_settings.interval} сек — задержка между проверками.");
            Console.WriteLine($"Таймаут подключения: {conf.monitor_settings.timeout} сек — максимальное время ожидания ответа.");
            Console.WriteLine($"Сортировка по статусу: {conf.monitor_settings.sorted} — как упорядочивать таблицу (status/url).");
            Console.WriteLine($"Проверка пингом: {(conf.monitor_settings.ping_enabled ? "включена" : "отключена")} — отправка ICMP-запросов.");
            Console.WriteLine($"Статистика аптайма: {(conf.monitor_settings.uptime_enabled ? "включена" : "отключена")} — анализ за сутки.");
            Console.WriteLine($"Логирование: {(conf.Monitor.logging_enabled ? "включено" : "отключено")} — сохранение в файл {conf.Monitor.log_file_path}.");
            Console.WriteLine($"Количество сайтов: {conf.websites.Count} — список проверяемых адресов.");
        }

        static async Task<WebsiteResult> CheckWebsiteAsync(string url)
        {
            WebsiteResult result = new() { url = url };
            string host = url.Replace("https://", "").Replace("http://", "").Split('/')[0];
            if (config.monitor_settings.ping_enabled)
            {
                try
                {
                    Ping ping = new();
                    var reply = await ping.SendPingAsync(host, 2000);
                    if (reply.Status != IPStatus.Success)
                    {
                        result.status = "PING_FAIL";
                        result.code = "N/A";
                        result.error_type = "ICMP";
                    }
                }
                catch
                {
                    result.status = "PING_ERR";
                    result.code = "ERR";
                    result.error_type = "ICMP_EX";
                }
            }
            try
            {
                var entry = await Dns.GetHostEntryAsync(host);
                result.ip = entry.AddressList.FirstOrDefault()?.ToString() ?? "N/A";
            }
            catch
            {
                result.ip = "N/A";
                result.status = "DNS_ERROR";
                result.code = "ERR";
                result.error_type = "DNS";
                return result;
            }
            try
            {
                var response = await client.GetAsync(url);
                int statusCode = (int)response.StatusCode;
                result.status = config.monitor_settings.valid_status_codes.Contains(statusCode) ? "OK" : "HTTP_ERROR";
                result.code = statusCode.ToString();
                if (result.status == "OK")
                    result.error_type = null;
            }
            catch (TaskCanceledException)
            {
                result.status = "TIMEOUT";
                result.code = "T/O";
                result.error_type = "TIMEOUT";
            }
            catch (HttpRequestException ex) when (ex.InnerException is AuthenticationException)
            {
                result.status = "SSL_ERROR";
                result.code = "SSL";
                result.error_type = "SSL";
            }
            catch
            {
                result.status = "CONN_ERROR";
                result.code = "ERR";
                result.error_type = "NETWORK";
            }
            return result;
        }

        static void PrintResults(WebsiteResult[] results)
        {
            Console.WriteLine(new string('-', Console.WindowWidth));
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("{0,-12} {1,-30} {2,-16} {3,-6} {4,-10}", "Статус", "Сайт", "IP", "Код", "Тип ошибки");
            Console.ResetColor();
            Console.WriteLine(new string('-', Console.WindowWidth));
            int okCount = 0;
            foreach (var r in results)
            {
                Console.ForegroundColor = r.status == "OK" ? ConsoleColor.Green : ConsoleColor.Red;
                Console.Write("{0,-12}", r.status);
                Console.ResetColor();
                Console.Write(" {0,-30} {1,-16} {2,-6} ", r.url, r.ip, r.code);
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("{0,-10}", r.error_type ?? "");
                Console.ResetColor();
                if (r.status == "OK")
                    okCount++;
            }
            Console.WriteLine(new string('-', Console.WindowWidth));
            Console.WriteLine($"\nИтого доступно: {okCount}/{results.Length} сайтов\n");
        }

        static void PrintUptime(WebsiteResult[] results)
        {
            Console.WriteLine("--- Аптайм за сутки ---");
            int historyMax = Math.Max(0, Console.WindowWidth - (30 + 3 + 4 + 5));
            foreach (var r in results)
            {
                int uptime = r.status == "OK" ? 100 : 0;
                Console.Write($"{r.url,-30} - {uptime,3}% ");
                if (uptimeHistory.ContainsKey(r.url))
                {
                    foreach (bool stat in uptimeHistory[r.url])
                    {
                        Console.ForegroundColor = stat ? ConsoleColor.Green : ConsoleColor.Red;
                        Console.Write("|");
                        Console.ResetColor();
                    }
                }
                Console.WriteLine();
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
                    results = results.Select(r => new { r.url, r.ip, r.status, r.code })
                };
                string json = JsonSerializer.Serialize(log);
                await File.AppendAllTextAsync(path, json + Environment.NewLine);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка логирования: {ex.Message}");
            }
        }

        static void Color(string text, ConsoleColor color)
        {
            Console.ForegroundColor = color;
            Console.Write(text);
            Console.ResetColor();
        }
    }
}
