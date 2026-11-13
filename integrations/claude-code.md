Bu projeye "{{AGENT_NAME}}" agent'ını entegre et. Operasyonlar: {{OPERATIONS}}

1. Projenin dilini ve framework'ünü tespit et (Next.js, Express, FastAPI, Django, Spring Boot, Laravel vb.).
2. Doğru kanalı seç:
   - Sunucu tarafı global hata yakalama (exception handler / middleware) için API: `@platform/sdk` veya doğrudan `POST https://api.platform.tld/v1/agents/{{AGENT_SLUG}}/invoke` uç noktası.
   - Asenkron log kaydı ve arka plan hata bildirimleri için Olay: `platform.events.send("{{AGENT_SLUG}}", "error.logged", ...)`
   - Sürekli entegrasyon ve derleme denetimi için CI: `platform-tld/agent-action@v1` GitHub Actions adımı.
   - Yerel geliştirici ve terminal hata ayıklama ortamı için MCP:
     ```bash
     claude mcp add --transport http {{AGENT_SLUG}} https://mcp.platform.tld/{{AGENT_SLUG}} --header "Authorization: Bearer $PLATFORM_SECRET_KEY"
     ```
3. Sunucu tarafında `PLATFORM_SECRET_KEY` ortam değişkenini oku, `.env` dosyasına `PLATFORM_SECRET_KEY=` satırını BOŞ olarak ekle ve `.env` dosyasının `.gitignore` içinde yer aldığını kontrol et. Anahtarı asla istemci (frontend) koduna, terminal çıktısına veya sohbete yazma.
4. Mevcut hata yakalama ve loglama katmanına `analyze_log` çağrısını 2 saniye zaman aşımı (`timeout: 2.0s`) ve fallback mekanizması ile ekle. Ajan servisinin gecikmesi veya yanıt vermemesi ana uygulama akışını kesinlikle bloklamasın.
5. Aşağıdaki örnek girdi ile uçtan uca bir entegrasyon testi yaz ve değiştirilen tüm dosyaları özetle:

```json
{{SAMPLE_INPUT}}
```
