# {{AGENT_NAME}} Ortak Entegrasyon İlkeleri

Bu doküman, **{{AGENT_NAME}}** (`{{AGENT_SLUG}}`) platform ajanının farklı geliştirme ortamlarına, yazılım çatılarına ve CI/CD işlem hatlarına güvenli, hataya dayanıklı ve standartlara uygun şekilde entegre edilmesi için gereken ortak mimari kuralları tanımlar.

---

## 1. Kanal Seçim Matrisi (Bölüm 3.2)

Uygulamanızın mimari gereksinimine göre doğru entegrasyon kanalını seçin:

| Kanal (Tip) | Ne Zaman Kullanılır? | Çağrı Yöntemi / SDK |
| :--- | :--- | :--- |
| **API** | Sunucu tarafında (backend) yakalanan istisnaları (unhandled exceptions) gerçek zamanlı analiz edip anında çözüm üretmek için. | `@platform/sdk` veya `POST https://api.platform.tld/v1/agents/{{AGENT_SLUG}}/invoke` |
| **Olay (Event)** | Asenkron log akışlarını veya hata kayıtlarını ana akışı bloklamadan incelemek için. | `platform.events.send("{{AGENT_SLUG}}", "error.logged", ...)` |
| **MCP** | Yerel IDE ortamında (Claude Code, Cursor) hata ayıklarken yapay zeka asistanının log analiz etmesi için. | `https://mcp.platform.tld/{{AGENT_SLUG}}` üzerinden HTTP/SSE MCP aracı |
| **CI** | Kod birleştirme (Pull Request) ve otomatik test adımlarında test/derleme hatalarını denetlemek için. | `platform-tld/agent-action@v1` GitHub Actions adımı |

---

## 2. Güvenlik ve Gizli Anahtar Yönetimi

> [!CAUTION]
> `PLATFORM_SECRET_KEY` ve `PLATFORM_SIGNING_SECRET` anahtarlarını **asla** istemci tarafı (frontend/browser) koduna eklemeyin, sohbete yapıştırmayın ve git repository'sine commit etmeyin.

1. **Ortam Değişkeni Zorunluluğu:** Anahtar daima `.env` dosyasından okunmalıdır.
2. **.gitignore Kontrolü:** Projenizin `.gitignore` dosyasında `.env` satırının bulunduğundan emin olun.
3. **Şablon Dosyası:** `.env.example` içinde yalnızca boş tanımlama bulundurun:
   ```bash
   PLATFORM_SECRET_KEY=
   PLATFORM_SIGNING_SECRET=
   ```
4. **Hassas Veri Kalkanı:** Ajan varsayılan olarak KVKK/PII maskeleme (`mask_pii: true`) uygulayarak e-posta, telefon, TCKN, kredi kartı ve API anahtarlarını temizler.

---

## 3. Dayanıklılık ve Hata Toleransı Kuralları

- **Zaman Aşımı (Timeout):** Sunucu tarafı API çağrıları için en fazla **2 saniye** (`timeout: 2.0s`) süre tanınmalıdır.
- **Fallback Güvencesi:** Ajan servisinin yanıt vermemesi veya zaman aşımına uğraması durumunda orijinal hata fırlatılmalı veya loglanmalı; ajan hatası ana uygulamanın çökmesine yol açmamalıdır.
- **Olay Asenkronluğu:** Olay (`error.logged`, `ci.failed`) gönderimleri fire-and-forget (arka plan işi) olarak çalışmalı, HTTP yanıtını geciktirmemelidir.

---

## 4. Desteklenen Operasyonlar

{{OPERATIONS}}

- **`analyze_log`**:
  - `log_text` (string, zorunlu, maks 8000 karakter): İncelenecek hata log metni veya çağrı yığını.
  - `framework` (string, opsiyonel, varsayılan: `"auto"`): Uygulama çatısı (örn. `fastapi`, `nextjs`, `spring`, `django`).
  - Çıktı: `error_type`, `severity`, `file_location`, `root_cause`, `suggested_fix`, `sanitized_log`, `masked_pii_count`.

---

## 5. Örnek İstek Girdisi

```json
{{SAMPLE_INPUT}}
```

---

## 6. Doğrulama Adımı

Entegrasyon tamamlandıktan sonra demo girdisi (`{{SAMPLE_INPUT}}`) ile sunucu tarafında test çağrısı yaparak yanıt zarfında `output` ve `status` alanlarının döndüğünü doğrulayın.
