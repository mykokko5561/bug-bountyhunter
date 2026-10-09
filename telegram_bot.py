"""
telegram_bot.py
----------------
Katman 5: Orkestrasyon. İki görevi var:

1. PROAKTİF BİLDİRİM: Local AI (Katman 3) bir isteği 'sent_to_ai' olarak
   işaretlediğinde, arka plan job'u bunu yakalar ve sana Telegram'dan mesaj
   atar (isteğin tam detayını, kopyala-yapıştır şeklinde Claude'a
   yapıştırabileceğin formatta).
2. MANUEL SORGULAMA: /stats, /pending, /show <id>, /mark <id> <status>
   komutlarıyla sistemi mobilden yönetebilirsin.

ORTAM DEĞİŞKENLERİ (zorunlu):
    BUGBOUNTY_TG_TOKEN   -> BotFather'dan aldığın token
    BUGBOUNTY_TG_CHAT_ID -> Bildirimlerin gideceği chat ID (kendi hesabın)

ÇALIŞTIRMA:
    export BUGBOUNTY_TG_TOKEN="123456:ABC-DEF..."
    export BUGBOUNTY_TG_CHAT_ID="987654321"
    python telegram_bot.py
"""

import html
import json
import logging
import os
import sqlite3
import sys


def esc(v) -> str:
    """Telegram HTML parse_mode için dinamik metni güvenli hale getirir.
    URL'lerdeki & < > karakterleri HTML'i bozup mesajın sessizce
    düşmesine yol açar — bunları escape ederiz."""
    return html.escape(str(v if v is not None else ""))

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import Application, CommandHandler, ContextTypes

from database import init_db, get_connection

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("bugbounty.telegram_bot")

NOTIFY_POLL_SECONDS = 20
MAX_TELEGRAM_MSG_LEN = 3800  # Telegram limiti 4096; güvenlik payı bırakıyoruz.


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        logger.critical("Ortam değişkeni eksik: %s. Botu başlatamıyorum.", name)
        sys.exit(1)
    return value


def _format_request_message(row: sqlite3.Row) -> str:
    """Bir isteği Telegram'da okunaklı + Claude'a yapıştırılabilir formatta üretir."""
    try:
        headers = json.loads(row["headers_json"] or "{}")
    except json.JSONDecodeError:
        headers = {}

    body_preview = (row["body"] or "")[:500]
    secret_note = ""
    if row["contains_secret"]:
        secret_note = f"\n🔑 <b>SECRET TESPİT EDİLDİ:</b> {esc(row['secret_matches'])}"

    return (
        f"🎯 <b>Yeni İnceleme Adayı (#{row['id']})</b>\n"
        f"<b>Kategori:</b> {esc(row['ai_verdict'] or 'bilinmiyor')}\n"
        f"<b>Neden:</b> {esc(row['ai_reasoning'] or '-')}"
        f"{secret_note}\n\n"
        f"<b>{esc(row['method'])}</b> <code>{esc(row['url'])}</code>\n"
        f"<b>Host:</b> {esc(row['host'])}\n"
        f"<b>Headers:</b> <code>{esc(json.dumps(headers, ensure_ascii=False)[:400])}</code>\n"
        f"<b>Body:</b> <code>{esc(body_preview)}</code>\n\n"
        f"Detay için: /show {row['id']}"
    )[:MAX_TELEGRAM_MSG_LEN]


# --------------------------------------------------------------------------
# Komutlar
# --------------------------------------------------------------------------

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "Bug Bounty AI Bridge aktif.\n"
        "/stats - genel istatistik\n"
        "/progress - triyaj ilerleme çubuğu\n"
        "/pending - analiz bekleyen istekler\n"
        "/show <id> - tam istek detayı\n"
        "/mark <id> <status> - durumu manuel güncelle\n"
        "\n<b>🚀 OTONOM:</b>\n"
        "/scan &lt;domain&gt; - TAM otonom (wildcard scope için; subdomain keşfi dahil)\n"
        "/browse &lt;url&gt; - tek URL crawl (URL-scope için; subdomain keşfi YOK, güvenli)\n"
        "/source &lt;github_url&gt; - açık kaynak kod analizi (Cloudflare/auth duvarı yok)\n"
        "\n<b>Recon (parça parça):</b>\n"
        "/recon &lt;domain&gt; - sadece subdomain + alive + nuclei\n"
        "/subs [domain] - keşfedilen canlı subdomainler\n"
        "/findings - tüm bulgular (nuclei + idor + web vuln + kod)\n"
        "/idor &lt;id&gt; - yakalanmış isteği IDOR için test et\n"
        "/chains - bulguları kritik zincire birleştir\n"
        "/dom - yakalanan HTML'den gizli param/endpoint çıkar\n"
        "/poc &lt;id&gt; - istekten curl+python PoC üret\n"
        "/skills - yüklü uzman metodolojiler\n"
        "/report &lt;id&gt; &lt;program&gt; - H1 rapor taslağı",
        parse_mode=ParseMode.HTML,
    )


async def cmd_stats(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    try:
        with get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) c FROM requests").fetchone()["c"]
            by_status = conn.execute(
                "SELECT triage_status, COUNT(*) c FROM requests GROUP BY triage_status"
            ).fetchall()
            secrets = conn.execute(
                "SELECT COUNT(*) c FROM requests WHERE contains_secret = 1"
            ).fetchone()["c"]
    except sqlite3.Error as e:
        logger.error("Stats sorgusu başarısız: %s", e)
        await update.message.reply_text("⚠️ Veritabanı hatası, istatistik alınamadı.")
        return

    lines = [f"📊 <b>Toplam:</b> {total}", f"🔑 <b>Secret bulunan:</b> {secrets}", ""]
    for row in by_status:
        lines.append(f"  • {row['triage_status']}: {row['c']}")

    await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.HTML)


async def cmd_pending(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    try:
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT id, method, url, ai_verdict FROM requests "
                "WHERE triage_status = 'sent_to_ai' ORDER BY created_at DESC LIMIT 10"
            ).fetchall()
    except sqlite3.Error as e:
        logger.error("Pending sorgusu başarısız: %s", e)
        await update.message.reply_text("⚠️ Veritabanı hatası.")
        return

    if not rows:
        await update.message.reply_text("✅ Analiz bekleyen istek yok.")
        return

    lines = ["🎯 <b>Analiz bekleyenler:</b>\n"]
    for r in rows:
        lines.append(f"#{r['id']} [{esc(r['ai_verdict'])}] {esc(r['method'])} "
                     f"<code>{esc(r['url'])}</code>")
    lines.append("\nDetay için: /show &lt;id&gt;")

    await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.HTML)


async def cmd_show(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.args:
        await update.message.reply_text("Kullanım: /show <id>")
        return

    try:
        request_id = int(context.args[0])
    except ValueError:
        await update.message.reply_text("Geçersiz id. Örnek: /show 42")
        return

    try:
        with get_connection() as conn:
            row = conn.execute("SELECT * FROM requests WHERE id = ?", (request_id,)).fetchone()
    except sqlite3.Error as e:
        logger.error("Show sorgusu başarısız (id=%s): %s", request_id, e)
        await update.message.reply_text("⚠️ Veritabanı hatası.")
        return

    if row is None:
        await update.message.reply_text(f"#{request_id} bulunamadı.")
        return

    await update.message.reply_text(_format_request_message(row), parse_mode=ParseMode.HTML)


async def cmd_mark(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if len(context.args) < 2:
        await update.message.reply_text("Kullanım: /mark <id> <status>\nörn: /mark 42 reported")
        return

    try:
        request_id = int(context.args[0])
    except ValueError:
        await update.message.reply_text("Geçersiz id.")
        return

    new_status = context.args[1]
    valid_statuses = {"pending", "filtered_out", "sent_to_ai", "analyzed", "reported"}
    if new_status not in valid_statuses:
        await update.message.reply_text(f"Geçersiz status. Geçerli değerler: {valid_statuses}")
        return

    try:
        with get_connection() as conn:
            cursor = conn.execute(
                "UPDATE requests SET triage_status = ?, updated_at = datetime('now') WHERE id = ?",
                (new_status, request_id),
            )
            conn.commit()
        if cursor.rowcount == 0:
            await update.message.reply_text(f"#{request_id} bulunamadı.")
        else:
            await update.message.reply_text(f"✅ #{request_id} -> {new_status} olarak işaretlendi.")
    except sqlite3.Error as e:
        logger.error("Mark güncellemesi başarısız (id=%s): %s", request_id, e)
        await update.message.reply_text("⚠️ Veritabanı hatası, güncelleme yapılamadı.")


async def cmd_progress(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Triyaj ilerleme durumunu göster."""
    try:
        with get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) c FROM requests").fetchone()["c"]
            analyzed = conn.execute("SELECT COUNT(*) c FROM requests WHERE triage_status='analyzed'").fetchone()["c"]
            sent_to_ai = conn.execute("SELECT COUNT(*) c FROM requests WHERE triage_status='sent_to_ai'").fetchone()["c"]
            filtered = conn.execute("SELECT COUNT(*) c FROM requests WHERE triage_status='filtered_out'").fetchone()["c"]
            pending = conn.execute("SELECT COUNT(*) c FROM requests WHERE triage_status='pending'").fetchone()["c"]
            reported = conn.execute("SELECT COUNT(*) c FROM requests WHERE triage_status='reported'").fetchone()["c"]

        done = analyzed + filtered + reported
        percent = round(done / total * 100) if total > 0 else 0

        # İlerleme çubuğu
        filled = percent // 5
        bar = "█" * filled + "░" * (20 - filled)

        msg = (
            f"📊 <b>Triyaj İlerlemesi</b>\n\n"
            f"[{bar}] {percent}%\n\n"
            f"✅ Tamamlanan: {done:,} / {total:,}\n"
            f"⏳ Bekleyen: {pending:,}\n"
            f"🎯 Analiz edildi: {analyzed:,}\n"
            f"🚨 İnceleme bekliyor: {sent_to_ai:,}\n"
            f"🗑️ Filtrelendi: {filtered:,}\n"
            f"📝 Raporlandı: {reported:,}"
        )
        await update.message.reply_text(msg, parse_mode=ParseMode.HTML)
    except Exception as e:
        await update.message.reply_text(f"⚠️ Hata: {e}")


async def cmd_scan(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """TAM OTONOM tarama: subdomain -> alive -> nuclei -> web vuln -> browser crawl."""
    if not context.args:
        await update.message.reply_text(
            "Kullanım: /scan <domain>\nÖrn: /scan bykea.com\n"
            "Tüm zinciri otonom çalıştırır (subdomain, alive, nuclei, web vuln, crawl).\n"
            "SADECE scope'a dahil domainlerde çalıştır."
        )
        return

    # domain veya URL kabul et, domaine indirge
    raw = context.args[0].strip()
    domain = raw.replace("https://", "").replace("http://", "").split("/")[0].lstrip("*.")
    if "." not in domain:
        await update.message.reply_text("Geçersiz domain. Örn: /scan bykea.com")
        return

    extra = []
    if "--no-browser" in context.args:
        extra.append("--no-browser")
    if "--no-nuclei" in context.args:
        extra.append("--no-nuclei")

    await update.message.reply_text(
        f"🚀 <b>Otonom tarama başlıyor:</b> {domain}\n\n"
        "Zincir: subdomain → alive → nuclei → web vuln → browser crawl\n"
        "Her aşamada bildirim gelecek. Bitince /findings ve /pending.",
        parse_mode=ParseMode.HTML,
    )

    import subprocess
    import os
    subprocess.Popen(
        [sys.executable, "autopwn.py", domain, *extra],
        cwd=os.path.dirname(os.path.abspath(__file__)),
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    await update.message.reply_text("✅ Otonom pipeline arka planda başlatıldı.")


async def cmd_report(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """DB kaydından H1 rapor taslağı oluştur."""
    if len(context.args) < 2:
        await update.message.reply_text("Kullanım: /report <id> <program>\nÖrn: /report 676 whatnot")
        return

    try:
        record_id = int(context.args[0])
    except ValueError:
        await update.message.reply_text("Geçersiz id.")
        return

    program = context.args[1]

    try:
        from hackerone_reporter import build_report_from_db
        payload = build_report_from_db(record_id, program)
        attrs = payload["data"]["attributes"]
        msg = (
            f"📋 <b>Rapor Taslağı #{record_id}</b>\n\n"
            f"<b>Program:</b> {program}\n"
            f"<b>Başlık:</b> {attrs['title']}\n"
            f"<b>Severity:</b> {attrs['severity_rating'].upper()}\n\n"
            f"Göndermek için:\n"
            f"<code>python hackerone_reporter.py --id {record_id} --program {program} --no-dry-run</code>"
        )
        await update.message.reply_text(msg, parse_mode=ParseMode.HTML)
    except Exception as e:
        await update.message.reply_text(f"⚠️ Hata: {e}")


async def cmd_recon(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Layer 0 -> Layer 1: subdomain keşfi + alive check + nuclei (arka plan)."""
    if not context.args:
        await update.message.reply_text(
            "Kullanım: /recon <domain>\nÖrn: /recon bykea.net\n"
            "SADECE scope'a dahil domainlerde çalıştır."
        )
        return

    domain = context.args[0].lower().strip().lstrip("*.")
    if "." not in domain or "/" in domain:
        await update.message.reply_text("Geçersiz domain. Örn: bykea.net")
        return

    no_nuclei = "--no-nuclei" in context.args
    await update.message.reply_text(
        f"🔭 Recon başlıyor: {domain}\n"
        f"Layer 0 (crt.sh + DNS brute) -> Layer 1 (alive + "
        f"{'nuclei atlandı' if no_nuclei else 'nuclei'})\n"
        "Bitince /subs ve /findings ile sonuçlara bak."
    )

    import subprocess
    import os
    cmd = [sys.executable, "recon_pipeline.py", domain]
    if no_nuclei:
        cmd.append("--no-nuclei")
    subprocess.Popen(
        cmd,
        cwd=os.path.dirname(os.path.abspath(__file__)),
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    await update.message.reply_text("✅ Recon arka planda başlatıldı.")


async def cmd_browse(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Tek bir in-scope URL'yi otonom crawl et (subdomain keşfi YOK, scope güvenli).
    URL-scope'lu programlar için: /browse https://www.myntra.com"""
    if not context.args:
        await update.message.reply_text(
            "Kullanım: /browse <url> [--depth N]\n"
            "Örn: /browse https://www.myntra.com\n"
            "Tek URL'yi gerçek tarayıcıyla gezer, API çağrılarını yakalar.\n"
            "Subdomain keşfi yapmaz — URL-scope'lu programlar için güvenli.\n"
            "SADECE scope'a dahil URL'lerde çalıştır."
        )
        return

    url = context.args[0].strip()
    if not url.startswith("http"):
        await update.message.reply_text("Geçersiz URL. https:// ile başlamalı.")
        return

    depth = "2"
    if "--depth" in context.args:
        try:
            depth = context.args[context.args.index("--depth") + 1]
        except (IndexError, ValueError):
            pass

    await update.message.reply_text(
        f"🕷️ <b>Otonom crawl:</b> {url}\n"
        f"Derinlik: {depth} | Gerçek tarayıcı (WAF/Cloudflare geçer)\n"
        "API çağrıları yakalanıp triyaja girecek. Bitince /pending.",
        parse_mode=ParseMode.HTML,
    )

    import subprocess
    import os
    subprocess.Popen(
        [sys.executable, "layer4_browser.py", url, "--depth", depth, "--no-session"],
        cwd=os.path.dirname(os.path.abspath(__file__)),
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    await update.message.reply_text("✅ Crawl arka planda başlatıldı.")


async def cmd_subs(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Keşfedilen subdomainleri listeler (opsiyonel: sadece canlı olanlar)."""
    root = context.args[0] if context.args else None
    try:
        with get_connection() as conn:
            if root:
                total = conn.execute(
                    "SELECT COUNT(*) c FROM subdomains WHERE root = ?", (root,)
                ).fetchone()["c"]
                alive_rows = conn.execute(
                    "SELECT subdomain, status_code, tech FROM subdomains "
                    "WHERE root = ? AND alive = 1 ORDER BY subdomain LIMIT 40", (root,)
                ).fetchall()
            else:
                total = conn.execute("SELECT COUNT(*) c FROM subdomains").fetchone()["c"]
                alive_rows = conn.execute(
                    "SELECT subdomain, status_code, tech FROM subdomains "
                    "WHERE alive = 1 ORDER BY subdomain LIMIT 40"
                ).fetchall()
    except sqlite3.Error as e:
        logger.error("Subs sorgusu başarısız: %s", e)
        await update.message.reply_text("⚠️ Veritabanı hatası.")
        return

    if total == 0:
        await update.message.reply_text("Henüz subdomain yok. Önce /recon <domain> çalıştır.")
        return

    lines = [f"🌐 <b>Subdomainler</b> ({root or 'tümü'}) — toplam {total}, canlı {len(alive_rows)}\n"]
    for r in alive_rows:
        tech = f" [{esc(r['tech'])}]" if r["tech"] else ""
        lines.append(f"  • {esc(r['subdomain'])} ({r['status_code']}){tech}")
    if len(alive_rows) == 40:
        lines.append("\n… (ilk 40 gösterildi)")
    await update.message.reply_text("\n".join(lines)[:MAX_TELEGRAM_MSG_LEN],
                                    parse_mode=ParseMode.HTML)


async def cmd_findings(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Recon bulgularını (nuclei + idor) listeler, en yüksek severity önce."""
    sev_order = "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 " \
                "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"
    try:
        with get_connection() as conn:
            rows = conn.execute(
                f"SELECT id, host, source, severity, name, matched_at "
                f"FROM recon_findings ORDER BY {sev_order}, found_at DESC LIMIT 25"
            ).fetchall()
    except sqlite3.Error as e:
        logger.error("Findings sorgusu başarısız: %s", e)
        await update.message.reply_text("⚠️ Veritabanı hatası.")
        return

    if not rows:
        await update.message.reply_text("Henüz recon bulgusu yok.")
        return

    emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
    lines = ["🔎 <b>Recon Bulguları</b>\n"]
    for r in rows:
        e = emoji.get((r["severity"] or "").lower(), "⚫")
        lines.append(f"{e} #{r['id']} [{esc(r['source'])}] {esc(r['name'])}\n"
                     f"    <code>{esc(r['matched_at'] or r['host'])}</code>")
    await update.message.reply_text("\n".join(lines)[:MAX_TELEGRAM_MSG_LEN],
                                    parse_mode=ParseMode.HTML)


async def cmd_source(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Açık kaynak repo analizi: /source https://github.com/org/repo [root]"""
    if not context.args:
        await update.message.reply_text(
            "Kullanım: /source <github_url> [root]\n"
            "Örn: /source https://github.com/kaltura/kmc-ng kaltura.com\n"
            "Hedefin açık kaynak kodunu çekip zafiyet pattern'leri arar "
            "(postMessage, DOM XSS, secret, open redirect, SQLi…). "
            "Cloudflare/auth duvarına takılmaz."
        )
        return

    repo = context.args[0].strip()
    root = context.args[1].strip() if len(context.args) > 1 else ""
    if "github.com" not in repo and not repo.startswith("http"):
        await update.message.reply_text("Geçerli bir GitHub repo URL'si ver.")
        return

    await update.message.reply_text(
        f"📖 <b>Kaynak analizi başlıyor:</b> {esc(repo)}\n"
        "Repo çekilip zafiyet pattern'leri taranacak. Bitince /findings.",
        parse_mode=ParseMode.HTML,
    )

    import subprocess
    import os
    cmd = [sys.executable, "layer7_source.py", repo]
    if root:
        cmd += ["--root", root]
    subprocess.Popen(
        cmd,
        cwd=os.path.dirname(os.path.abspath(__file__)),
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    await update.message.reply_text("✅ Kaynak analizi arka planda başladı.")


async def cmd_chains(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Bulguları kritik zincirlere birleştir (chain_builder)."""
    try:
        import chain_builder
        chains = chain_builder.run()
    except Exception as e:  # noqa: BLE001
        await update.message.reply_text(f"⚠️ Hata: {esc(str(e))}")
        return
    if not chains:
        await update.message.reply_text("Eşleşen zincir yok (yeterli bulgu birikince tekrar dene).")
        return
    lines = ["🔗 <b>Zafiyet Zincirleri</b>\n"]
    for c in chains:
        lines.append(f"🔴 <b>{esc(c['name'])}</b> [{esc(c['severity'])}]\n    {esc(c['impact'])}")
    await update.message.reply_text("\n".join(lines)[:MAX_TELEGRAM_MSG_LEN], parse_mode=ParseMode.HTML)


async def cmd_dom(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Yakalanan HTML'lerden gizli param/endpoint/yorum çıkar (dom_analyzer)."""
    try:
        import dom_analyzer
        res = dom_analyzer.analyze_captured(limit=300)
    except Exception as e:  # noqa: BLE001
        await update.message.reply_text(f"⚠️ Hata: {esc(str(e))}")
        return
    if not res:
        await update.message.reply_text("HTML yanıtı bulunamadı (önce /browse ya da /scan çalıştır).")
        return
    lines = ["🧬 <b>DOM Yüzeyi</b>\n"]
    if res.get("endpoints"):
        lines.append(f"<b>Endpoint'ler ({len(res['endpoints'])}):</b>")
        for e in res["endpoints"][:20]:
            lines.append(f"  <code>{esc(e)}</code>")
    if res.get("hidden"):
        lines.append(f"\n<b>Gizli alanlar:</b> {esc(', '.join(res['hidden'][:20]))}")
    if res.get("comments"):
        lines.append(f"\n<b>İlginç yorumlar ({len(res['comments'])}):</b>")
        for c in res["comments"][:6]:
            lines.append(f"  <code>{esc(c[:120])}</code>")
    await update.message.reply_text("\n".join(lines)[:MAX_TELEGRAM_MSG_LEN], parse_mode=ParseMode.HTML)


async def cmd_poc(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Yakalanmış istekten PoC üret (curl+python). /poc <id>"""
    if not context.args:
        await update.message.reply_text("Kullanım: /poc <request_id>")
        return
    try:
        rid = int(context.args[0])
        import poc_generator
        poc = poc_generator.generate_from_db(rid)
    except (ValueError, Exception) as e:  # noqa: BLE001
        await update.message.reply_text(f"⚠️ Hata: {esc(str(e))}")
        return
    if not poc:
        await update.message.reply_text(f"#{context.args[0]} bulunamadı.")
        return
    msg = (f"📋 <b>PoC #{esc(context.args[0])}</b>\n\n"
           f"<b>curl:</b>\n<code>{esc(poc['curl'][:800])}</code>\n\n"
           f"<b>python:</b>\n<code>{esc(poc['python'][:900])}</code>")
    await update.message.reply_text(msg[:MAX_TELEGRAM_MSG_LEN], parse_mode=ParseMode.HTML)


async def cmd_skills(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Yüklü uzman zafiyet metodolojilerini listeler (skills_loader)."""
    try:
        import skills_loader
        skills = skills_loader.list_skills()
    except Exception as e:  # noqa: BLE001
        await update.message.reply_text(f"⚠️ Hata: {esc(str(e))}")
        return
    await update.message.reply_text(
        f"📚 <b>{len(skills)} uzman metodoloji yüklü</b>\n" +
        ", ".join(esc(s) for s in skills), parse_mode=ParseMode.HTML)


async def cmd_apk(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Otonom APK indir + static analiz + sil. /apk com.myntra.android"""
    if not context.args:
        await update.message.reply_text(
            "Kullanım: /apk <package> [root]\n"
            "Örn: /apk com.myntra.android myntra.com\n"
            "APK'yı otomatik indirir, static analiz eder (kod çalıştırmaz), "
            "sonra siler. Endpoint/secret/host çıkarır."
        )
        return

    package = context.args[0].strip()
    root = context.args[1].strip() if len(context.args) > 1 else ""

    await update.message.reply_text(
        f"📦 <b>APK analizi başlıyor:</b> {esc(package)}\n"
        "İndir → static analiz (güvenli, kod çalıştırılmaz) → sil.\n"
        "Bitince /subs ve /findings.",
        parse_mode=ParseMode.HTML,
    )

    import subprocess
    import os
    cmd = [sys.executable, "layer6_apkfetch.py", package]
    if root:
        cmd += ["--root", root]
    subprocess.Popen(
        cmd,
        cwd=os.path.dirname(os.path.abspath(__file__)),
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    await update.message.reply_text("✅ APK indir+analiz arka planda başladı.")


async def cmd_secrets(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """contains_secret=1 olan istekleri listeler (yakalanan olası sızıntılar)."""
    try:
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT id, url, secret_matches FROM requests "
                "WHERE contains_secret = 1 ORDER BY id DESC LIMIT 20"
            ).fetchall()
    except sqlite3.Error as e:
        logger.error("Secrets sorgusu başarısız: %s", e)
        await update.message.reply_text("⚠️ Veritabanı hatası.")
        return

    if not rows:
        await update.message.reply_text("Secret bulunan istek yok.")
        return

    lines = ["🔑 <b>Bulunan Secret'lar</b>\n"]
    for r in rows:
        lines.append(f"#{r['id']} <code>{esc(r['url'])[:90]}</code>\n"
                     f"    → {esc(r['secret_matches'])[:200]}")
    lines.append("\nDetay: /show &lt;id&gt;")
    await update.message.reply_text("\n".join(lines)[:MAX_TELEGRAM_MSG_LEN],
                                    parse_mode=ParseMode.HTML)


async def cmd_idor(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Yakalanmış bir isteği (requests tablosu) IDOR için test eder."""
    if not context.args:
        await update.message.reply_text(
            "Kullanım: /idor <request_id>\n"
            "request_id = /show ile gördüğün kayıt id'si.\n"
            "Sadece GET/GraphQL-query test edilir (güvenli)."
        )
        return
    try:
        req_id = int(context.args[0])
    except ValueError:
        await update.message.reply_text("Geçersiz id. Örn: /idor 42")
        return

    await update.message.reply_text(
        f"🔓 IDOR testi başlıyor (kayıt #{req_id})…\n"
        "Bitince /findings ile adaylara bak."
    )

    import subprocess
    import os
    subprocess.Popen(
        [sys.executable, "layer2_idor.py", "--db-id", str(req_id)],
        cwd=os.path.dirname(os.path.abspath(__file__)),
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    await update.message.reply_text("✅ IDOR testi arka planda başlatıldı.")


# --------------------------------------------------------------------------
# Arka plan bildirim job'u
# --------------------------------------------------------------------------

async def notify_new_escalations(context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Her NOTIFY_POLL_SECONDS'da bir çalışır: 'sent_to_ai' olup henüz
    bildirilmemiş (notified_at IS NULL) istekleri bulur, mesaj atar,
    sonra notified_at damgasını basar (tekrar bildirim atmamak için).
    """
    try:
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM requests "
                "WHERE triage_status = 'sent_to_ai' "
                "AND notified_at IS NULL "
                "AND ai_verdict IN ('idor', 'bac', 'business_logic', 'secret_exposure') "
                "ORDER BY created_at ASC LIMIT 10"
            ).fetchall()
    except sqlite3.Error as e:
        logger.error("Bildirim sorgusu başarısız: %s", e)
        return

    for row in rows:
        try:
            await context.bot.send_message(
                chat_id=context.job.data["chat_id"],
                text=_format_request_message(row),
                parse_mode=ParseMode.HTML,
            )
            with get_connection() as conn:
                conn.execute(
                    "UPDATE requests SET notified_at = datetime('now') WHERE id = ?",
                    (row["id"],),
                )
                conn.commit()
        except Exception as e:
            # Telegram API geçici hata verirse (rate limit, ağ vb.) bu isteği
            # bir sonraki turda tekrar denemek üzere notified_at'siz bırak.
            logger.error("Bildirim gönderilemedi (id=%s): %s", row["id"], e)


async def notify_new_recon_findings(context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    high/critical severity recon bulgularını (nuclei/idor) bir kez bildirir.
    notified_at damgasıyla tekrar bildirim engellenir.
    """
    try:
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM recon_findings "
                "WHERE notified_at IS NULL "
                "AND (severity IN ('high', 'critical') OR source = 'idor') "
                "ORDER BY found_at ASC LIMIT 10"
            ).fetchall()
    except sqlite3.Error as e:
        logger.error("Recon bildirim sorgusu başarısız: %s", e)
        return

    for row in rows:
        try:
            emoji = {"critical": "🔴", "high": "🟠"}.get(
                (row["severity"] or "").lower(), "🟡")
            msg = (
                f"{emoji} <b>Recon Bulgusu (#{row['id']})</b>\n"
                f"<b>Kaynak:</b> {esc(row['source'])} | <b>Severity:</b> {esc(row['severity'])}\n"
                f"<b>Ad:</b> {esc(row['name'])}\n"
                f"<b>Konum:</b> <code>{esc(row['matched_at'] or row['host'])}</code>\n\n"
                f"Tüm bulgular: /findings"
            )[:MAX_TELEGRAM_MSG_LEN]
            await context.bot.send_message(
                chat_id=context.job.data["chat_id"], text=msg,
                parse_mode=ParseMode.HTML,
            )
            with get_connection() as conn:
                conn.execute(
                    "UPDATE recon_findings SET notified_at = datetime('now') WHERE id = ?",
                    (row["id"],),
                )
                conn.commit()
        except Exception as e:
            logger.error("Recon bildirimi gönderilemedi (id=%s): %s", row["id"], e)


def main() -> None:
    token = _require_env("BUGBOUNTY_TG_TOKEN")
    chat_id = _require_env("BUGBOUNTY_TG_CHAT_ID")

    init_db()

    app = Application.builder().token(token).build()

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("stats", cmd_stats))
    app.add_handler(CommandHandler("pending", cmd_pending))
    app.add_handler(CommandHandler("show", cmd_show))
    app.add_handler(CommandHandler("mark", cmd_mark))
    app.add_handler(CommandHandler("scan", cmd_scan))
    app.add_handler(CommandHandler("report", cmd_report))
    app.add_handler(CommandHandler("progress", cmd_progress))
    app.add_handler(CommandHandler("recon", cmd_recon))
    app.add_handler(CommandHandler("browse", cmd_browse))
    app.add_handler(CommandHandler("subs", cmd_subs))
    app.add_handler(CommandHandler("findings", cmd_findings))
    app.add_handler(CommandHandler("secrets", cmd_secrets))
    app.add_handler(CommandHandler("source", cmd_source))
    app.add_handler(CommandHandler("chains", cmd_chains))
    app.add_handler(CommandHandler("dom", cmd_dom))
    app.add_handler(CommandHandler("poc", cmd_poc))
    app.add_handler(CommandHandler("skills", cmd_skills))
    app.add_handler(CommandHandler("apk", cmd_apk))
    app.add_handler(CommandHandler("idor", cmd_idor))

    app.job_queue.run_repeating(
        notify_new_escalations,
        interval=NOTIFY_POLL_SECONDS,
        first=5,
        data={"chat_id": chat_id},
    )
    app.job_queue.run_repeating(
        notify_new_recon_findings,
        interval=NOTIFY_POLL_SECONDS,
        first=10,
        data={"chat_id": chat_id},
    )

    logger.info("Telegram bot başladı, chat_id=%s", chat_id)
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
