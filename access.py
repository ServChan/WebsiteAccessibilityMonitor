import asyncio
import itertools
import json
import os
import platform
import socket
import ssl
import subprocess
import sys
import time
from datetime import datetime
from aiohttp import ClientSession, ClientTimeout, TCPConnector
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.style import Style
from colorama import Fore, Style

if getattr(sys, 'frozen', False):
    script_dir = os.path.dirname(sys.executable)
else:
    script_dir = os.path.dirname(os.path.abspath(__file__))

config_path = os.path.join(script_dir, 'config.json')
console = Console()


def load_config():
    try:
        with open(config_path, encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        default_config = {
            "monitor_settings": {
                "interval": 60,
                "timeout": 5,
                "valid_status_codes": [200, 201, 202, 204, 300, 301, 302, 303, 307, 308],
                "sorted": "status"
            },
            "websites": [
                "ya.ru",
                "google.com",
                "example.com",
                "vk.com",
                "youtube.com",
                "github.com",
                "store.steampowered.com",
                "steamcommunity.com",
                "t.me",
                "discord.com",
                "pikabu.ru",
                "x.com",
                "anime.reactor.cc",
                "pixiv.net"
            ],
            "Monitor": {
                "logging_enabled": False,
                "log_file_path": "monitor.log"
            }
        }
        with open(config_path, 'w', encoding='utf-8') as config_file:
            json.dump(default_config, config_file, ensure_ascii=False, indent=4)
        print(f"Файл конфигурации создан по пути: {config_path}")
        return default_config


def print_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    console.print("=" * console.width, style="cyan")
    console.print("МОНИТОРИНГ ДОСТУПНОСТИ САЙТОВ".center(console.width), style="bold cyan")
    console.print("Версия 1.2.0".center(console.width), style="cyan")
    console.print("=" * console.width, style="cyan")


async def check_website(url, config, session):
    ms = config.get("monitor_settings", {})
    t = ms.get("timeout", 5)
    v = ms.get("valid_status_codes", [200])

    try:
        ip = await asyncio.to_thread(socket.gethostbyname, url)
    except Exception as e:
        return {"url": url, "ip": "N/A", "status": "DNS_ERROR", "code": "ERR", "error_type": "DNS"}

    try:
        async with session.get(f"https://{url}", timeout=ClientTimeout(total=t)) as r:
            ok = r.status in v
            return {
                "url": url,
                "ip": ip,
                "status": "OK" if ok else "HTTP_ERROR",
                "code": r.status,
                "error_type": None
            }
    except asyncio.TimeoutError:
        return {"url": url, "ip": ip, "status": "TIMEOUT", "code": "T/O", "error_type": "TIMEOUT"}
    except ssl.SSLError:
        return {"url": url, "ip": ip, "status": "SSL_ERROR", "code": "SSL", "error_type": "SSL"}
    except Exception as e:
        return {"url": url, "ip": ip, "status": "CONN_ERROR", "code": "ERR", "error_type": "NETWORK"}


async def monitor_websites(config):
    ms = config.get("monitor_settings", {})
    websites = config.get("websites", [])
    sort_mode = ms.get("sorted", "status")

    async with ClientSession(connector=TCPConnector(ssl=ssl.create_default_context())) as session:
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print_banner()
            console.print(f"Мониторинг начался в: [bold yellow]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/]\n")

            with Progress(SpinnerColumn(), TextColumn("[bold cyan]{task.description}")) as progress:
                task = progress.add_task("Проверка сайтов...", total=len(websites))
                tasks = [check_website(site, config, session) for site in websites]
                results = []
                for future in asyncio.as_completed(tasks):
                    results.append(await future)
                    progress.update(task, advance=1)

            # Сортировка результатов
            if sort_mode == "status":
                results.sort(key=lambda x: (x["status"] != "OK", x["url"]))
            elif sort_mode == "response_time":
                results.sort(key=lambda x: x.get("ping", float('inf')))

            # Создание таблицы с выравниванием
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Статус", width=12, justify="center")
            table.add_column("Сайт", justify="left")
            table.add_column("IP", style="magenta", justify="left")
            table.add_column("Код", justify="center")
            table.add_column("Тип ошибки", justify="center")

            up_count = 0
            for res in results:
                # Определение стилей
                site_style = "bold white" if res["status"] == "OK" else "bold red"
                status_style = "bold green" if res["status"] == "OK" else "bold red"
                error_type = res["error_type"] if res["status"] != "OK" else ""

                if res["status"] == "OK":
                    up_count += 1

                table.add_row(
                    f"[{status_style}]{res['status']}[/]",
                    f"[{site_style}]{res['url']}[/]",
                    res["ip"],
                    f"[bold]{str(res['code'])}[/]",
                    f"[bold red]{error_type}[/]" if error_type else ""
                )

            console.print(table)
            console.print(f"\n[bold]Итого доступно: [green]{up_count}[/]/[yellow]{len(results)}[/] сайтов[/]")
            console.print(f"\n[bold magenta]Следующая проверка через {ms.get('interval', 60)} секунд...[/]")
            await asyncio.sleep(ms.get('interval', 60))


async def log_website_statuses(results, config):
    try:
        monitor_cfg = config.get("Monitor", {})
        if monitor_cfg.get("logging_enabled", False):
            log_path = os.path.join(script_dir, monitor_cfg.get("log_file_path", "monitor.log"))
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "results": [
                    {k: v for k, v in res.items() if k != "error_type"}
                    for res in results
                ]
            }
            with open(log_path, 'a', encoding='utf-8') as f:
                json.dump(log_entry, f, ensure_ascii=False)
                f.write("\n")
    except Exception as e:
        console.print(f"[red]Ошибка записи лога: {e}[/]")


def main():
    config = load_config()
    print_banner()
    try:
        asyncio.run(monitor_websites(config))
    except KeyboardInterrupt:
        console.print("\n[red]Мониторинг остановлен пользователем[/]")


if __name__ == "__main__":
    main()
