# OpenAI Codex / CI Entegrasyonu: {{AGENT_NAME}}

Bu doküman, **{{AGENT_NAME}}** (`{{AGENT_SLUG}}`) ajanının projenizin `AGENTS.md` dosyasına eklenecek kurallarını, Codex görev istemlerini ve CI/API örneklerini tanımlar.

---

## 1. `AGENTS.md` Dosyasına Eklenecek Kurallar Bölümü

Aşağıdaki kural bloğunu projenizin kök dizinindeki `AGENTS.md` dosyasına ekleyin:

```markdown
## {{AGENT_NAME}} ({{AGENT_SLUG}}) Entegrasyon Kuralları

- **Kapsam:** {{AGENT_NAME}} çağrıları yalnızca sunucu tarafındaki servis veya ara yazılım (middleware) katmanından yapılabilir; istemci tarafında (frontend/browser) asla kullanılamaz.
- **Kimlik ve Güvenlik:**
  - `PLATFORM_SECRET_KEY` ortam değişkeni `.env` dosyasından okunmalıdır.
  - İstekler `X-Platform-Timestamp` ve `X-Platform-Signature` (HMAC-SHA256) başlıklarıyla imzalanmalıdır.
  - `.env` dosyasının `.gitignore` listesinde bulunduğu doğrulanmalıdır.
  - Sırlar ve anahtarlar kaynak kod deposuna veya loglara asla yazılmamalıdır.
- **Dayanıklılık:** API üzerinden yapılan `analyze_log` çağrıları için en fazla 2 saniye (`timeout: 2.0s`) zaman aşımı tanımlanmalı ve fallback mekanizması işletilmelidir. Ajan hatası ana akışı bloklayamaz.
- **Uç Nokta:** `POST https://api.platform.tld/v1/agents/{{AGENT_SLUG}}/invoke`
- **Operasyonlar:** {{OPERATIONS}}
```

---

## 2. Codex Kısa Görev İstem Şablonu

OpenAI Codex veya uyumlu yapay zeka asistanlarına doğrudan verilecek görev istemi:

```text
Bu projeye "{{AGENT_NAME}}" agent'ını entegre et. Operasyonlar: {{OPERATIONS}}.
Kanal olarak sunucu tarafı hata yakalama ara yazılımını (API) seç.
PLATFORM_SECRET_KEY anahtarını .env'den oku, .gitignore'u kontrol et.
2 saniye zaman aşımı ve try/except fallback mekanizmasını uygula.
Aşağıdaki örnek girdi ile entegrasyon testini hazırla:
{{SAMPLE_INPUT}}
```

---

## 3. GitHub Actions CI Entegrasyon Örneği (Bölüm 3.2)

Test adımları çöktüğünde `ci.failed` olayı veya `analyze_log` operasyonu üzerinden CI pipeline'ını yönetmek için `.github/workflows/ci.yml`:

```yaml
name: Test and Log Analysis

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Run Test Suite
        id: run_tests
        continue-on-error: true
        run: pytest -v > test_failure.log 2>&1

      - name: Analyze Failures with {{AGENT_NAME}}
        if: steps.run_tests.outcome == 'failure'
        env:
          PLATFORM_INVOKE_URL: "https://api.platform.tld/v1/agents/{{AGENT_SLUG}}/invoke"
          PLATFORM_SIGNING_SECRET: ${{ secrets.PLATFORM_SIGNING_SECRET }}
        run: |
          python -c "
          import os, json, time, hmac, hashlib, urllib.request

          with open('test_failure.log', 'r') as f:
              raw_log = f.read()[-4000:]

          payload = json.dumps({
              'operation': 'analyze_log',
              'input': {'log_text': raw_log, 'framework': 'pytest'},
              'config': {'fail_on_severity': 'critical', 'response_language': 'tr'}
          }).encode('utf-8')

          ts = str(int(time.time()))
          secret = os.environ['PLATFORM_SIGNING_SECRET'].encode('utf-8')
          sig = hmac.new(secret, f'{ts}.'.encode('utf-8') + payload, hashlib.sha256).hexdigest()

          req = urllib.request.Request(
              os.environ['PLATFORM_INVOKE_URL'],
              data=payload,
              headers={
                  'Content-Type': 'application/json',
                  'X-Platform-Timestamp': ts,
                  'X-Platform-Signature': sig
              }
          )
          with urllib.request.urlopen(req) as resp:
              res = json.loads(resp.read().decode('utf-8'))
              print('Analysis Output:', json.dumps(res, indent=2, ensure_ascii=False))
              if res.get('status') == 'fail':
                  raise SystemExit('CI failed: Critical error detected by {{AGENT_NAME}}')
          "
```
