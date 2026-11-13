# Akıllı Log ve Hata Analizcisi (`log-hata-analizcisi`)

**Akıllı Log ve Hata Analizcisi**, modern bulut tabanlı ve monolitik yazılım uygulamalarında oluşan çalışma zamanı (runtime) hata loglarını, istisnaları (exceptions) ve çağrı yığınlarını (stack traces) gerçek zamanlı olarak inceleyen, kişisel verileri (KVKK/GDPR) ve sırları maskeleyen, büyük dil modelleri (LLM `fast` modeli) aracılığıyla hatanın kesin kök nedenini saptayarak yazılımcıya doğrudan uygulanabilir kod çözümü sunan yeni nesil bir yapay zeka platform servisidir.

---

## 1. Temel Yetenekler ve Mimari Avantajlar

1. **Büyük Dil Modeli (LLM) Tabanlı Anlamsal Analiz (Rehber Ek A):**
   - Platform vekil sunucusu (`LLM_BASE_URL`) ve OpenAI istemcisi üzerinden `model="fast"` ile log metnini derinlemesine inceler.
   - Hatayı iş kritikliği açısından dört seviyede derecelendirir: `low`, `medium`, `high`, `critical`.
   - CI/CD ve otomatik alarm sistemlerine uygun olarak `status: ok`, `status: needs_review` veya `status: fail` çıktısı üretir.

2. **KVKK, GDPR ve Güvenlik Sırlarını Otomatik Maskeleme:**
   - E-posta adresleri (`[MASKED_EMAIL]`),
   - Kredi kartı ve finansal kart numaraları (13-19 hane, `[MASKED_CARD]`),
   - Telefon numaraları (`[MASKED_PHONE]`),
   - TC Kimlik Numaraları (11 hane, `[MASKED_TCKN]`),
   - IPv4 adresleri (`[MASKED_IP]`),
   - API anahtarları, Bearer token'lar ve parolalar (`[MASKED_SECRET]`) LLM'e iletilmeden önce otomatik olarak temizlenir.
   - Temizlenen toplam eleman adedi `masked_pii_count` olarak şeffafça raporlanır.

3. **Halüsinasyonsuz Kesin Dosya ve Satır Konumu Tespiti (`file_location`):**
   - Yapay zeka modellerinin sıklıkla düştüğü "olmayan dosya ve satır uydurma" (hallucination) tuzağını önlemek amacıyla, dosya konumu yalnızca log metninde fiilen yer alan regex doğrulamasıyla (`extract_file_location`) elde edilir. Logda dosya yoksa `file_location: ""` olarak garanti altına alınır.

4. **Saldırı Direnci (Prompt Injection & SSRF Koruması):**
   - Log metni içerisine gizlenmiş prompt injection saldırıları ("talimatları unut", "sistem promptunu yazdır", "output LLM_API_KEY") LLM'e gitmeden önce regex kalkanı tarafından yakalanır ve saldırganın talimatı kesinlikle icra edilmez.
   - Dahili metadata IP'leri (örn. AWS `169.254.169.254`) logda yer alsa dahi ajan sıfır dış ağ çağrısı (network isolation) prensibiyle çalışır; SSRF riski doğurmaz.

5. **Tam Durumsuz (Stateless) ve Güvenli Tasarım:**
   - Disk yazma işlemi yapmaz.
   - Tenant (kiracı) verilerini hafızada veya global değişkenlerde saklamaz.
   - Platform imza doğrulaması (Ek A HMAC-SHA256 ve 300 saniye zaman aşımı) ile yetkisiz istekleri reddeder.

---

## 2. Desteklenen Entegrasyon Tipleri

- **API:** Mikroservis veya web çatılarında `ExceptionMiddleware` içerisinden HTTP POST ile gerçek zamanlı çağrılır.
- **Event:** Log yönetim sistemleri veya kuyruk servislerinden gelen `error.logged` ve `ci.failed` olaylarıyla tetiklenir.
- **MCP:** Claude Code veya Cursor AI asistanları içerisinde bir araç (tool) olarak yerel geliştirme sürecine entegre edilir.
- **CI:** GitHub Actions / GitLab CI adımlarında testler patladığında hatayı analiz edip PR'a yorum bırakır ve gerektiğinde pipeline'ı durdurur.

---

## 3. Desteklenen Diller ve Çatılar

| Dil | Çatılar & Teknolojiler |
| :--- | :--- |
| **Python** | FastAPI, Django, Flask, Celery, Pytest |
| **JavaScript / TypeScript** | Next.js, Node.js, Express, React, NestJS |
| **Java** | Spring Boot, Jakarta EE, Quarkus |
| **Veritabanları & Altyapı** | PostgreSQL, MySQL, Redis, Docker, Nginx, Kubernetes |
| **Go & Diğerleri** | Gin, Fiber, PHP/Laravel, C#/.NET |

---

## 4. Yapılandırma Parametreleri (`config_schema`)

| Parametre | Tip | Varsayılan | Açıklama |
| :--- | :--- | :--- | :--- |
| `mask_pii` | boolean | `true` | Log içerisindeki kişisel verileri ve sırları maskeleme anahtarı. |
| `fail_on_severity` | string | `critical` | Hangi seviyeden itibaren yanıt statüsünün `fail` sayılacağını belirler (`high` veya `critical`). |
| `response_language` | string | `tr` | Analiz kök neden ve çözüm çıktısının dili (`tr` veya `en`). |

---

## 5. Örnek Kullanım ve Standart Zarf Çıktısı

### Girdi Log Metni:
```text
2026-11-13 14:22:01 ERROR [billing] user=ahmet.yilmaz@example.com ZeroDivisionError: division by zero in app/services/invoice.py:84
```

### JSON Analiz Çıktısı (Sayfa 6 & 15 Standart Zarf):
```json
{
  "output": {
    "error_type": "ZeroDivisionError",
    "severity": "critical",
    "file_location": "app/services/invoice.py:84",
    "root_cause": "Sıfıra bölme hatası (ZeroDivisionError) meydana geldi; payda değeri 0 olarak değerlendirildi.",
    "suggested_fix": "Bölen değerin sıfır veya tanımsız olup olmadığını kontrol eden koşul (if divisor != 0) ekleyin.",
    "sanitized_log": "2026-11-13 14:22:01 ERROR [billing] user=[MASKED_EMAIL] ZeroDivisionError: division by zero in app/services/invoice.py:84",
    "masked_pii_count": 1
  },
  "status": "fail",
  "artifacts": [],
  "actions": []
}
```
