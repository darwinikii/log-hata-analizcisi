# Akıllı Log ve Hata Analizcisi (`log-hata-analizcisi`)

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Spec](https://img.shields.io/badge/spec__version-1.1-green.svg)
![Python](https://img.shields.io/badge/python-3.12%20%7C%203.13-blue.svg)
![Tests](https://img.shields.io/badge/tests-10%2F10%20passed-brightgreen.svg)
![Evals](https://img.shields.io/badge/evals-22%2F22%20(100%25)-brightgreen.svg)
![Security](https://img.shields.io/badge/security-prompt__injection%20protected-orange.svg)

**Akıllı Log ve Hata Analizcisi**, uygulama hata loglarını ve çağrı yığınlarını (stack trace) analiz eden, kişisel verileri (KVKK) ve sırları maskeleyen, büyük dil modelleri (LLM `fast` modeli) aracılığıyla hatanın kesin kök nedenini belirleyip doğrudan uygulanabilir çözüm önerisi sunan yapay zeka tabanlı bir platform ajanıdır.

---

## 1. Mimari ve Temel Özellikler

- **Gerçek LLM Motoru (Rehber Ek A):** Platform vekil sunucusu (`LLM_BASE_URL`) ve `OpenAI` istemcisi üzerinden `model="fast"` ile akıllı kök neden analizi ve çözüm önerisi üretir.
- **Standart Yanıt Zarfı (Sayfa 6 & 15):** Uç nokta yanıtları `{output, status, artifacts, actions}` zarf standardına tam uyumludur.
- **Halüsinasyonsuz Konum Doğrulaması:** Dosya ve satır numarası yalnızca logda fiilen mevcutsa çıkarılır; modelin dosya uydurması regex katmanı ile engellenir, dosya yoksa daima `""` döner.
- **Kişisel Veri (KVKK) ve Sır Maskeleme:** E-postalar, kredi kartları (13-19 hane), TCKN (11 hane), telefon numaraları, IP adresleri ve API anahtarları LLM'e iletilmeden önce sansürlenir.
- **Prompt Injection Savunması:** Ajan talimatlarını ezmeye yönelik kötü niyetli girdiler ("talimatları unut", "sistem promptunu yazdır") LLM'e gitmeden saptanarak nötralize edilir.
- **SSRF Direnci & Sıfır Dış Ağ Çağrısı:** Ajan dış internete veya bulut metadata adreslerine (`169.254.169.254`) hiçbir ağ çağrısı yapmaz (`network: {allow: []}`).
- **Durumsuz (Stateless) Tasarım:** Disk yazımı yapılmaz, kiracı (tenant) verileri bellekte tutulmaz.
- **Birim Testleri & Mocking:** Test suite'i (`tests/test_contract.py`) harici ağ bağımlılığı olmadan deterministik ve hızlı çalışması için OpenAI API çağrılarını mock katmanı üzerinden doğrular.

---

## 2. Hızlı Başlangıç

### 2.1. Docker ile Çalıştırma
```bash
# İmajı derleyin
docker build -t log-hata-analizcisi:1.0.0 .

# Konteyneri başlatın
docker run -p 8080:8080 \
  -e PLATFORM_SIGNING_SECRET="gizli-imza-anahtari" \
  -e LLM_BASE_URL="http://llm-proxy:8000/v1" \
  -e LLM_API_KEY="platform-key" \
  log-hata-analizcisi:1.0.0
```

### 2.2. Yerel Geliştirme (Local Development)
```bash
# Bağımlılıkları yükleyin
pip install -r requirements.txt

# Çevre değişkenlerini ayarlayın
export PLATFORM_SIGNING_SECRET="gizli-imza-anahtari"
export LLM_BASE_URL="http://localhost:8000/v1"
export LLM_API_KEY="fast-token"
export PORT=8080

# Sunucuyu başlatın
uvicorn src.main:app --host 0.0.0.0 --port 8080 --reload
```

---

## 3. Ortam Değişkenleri

| Değişken | Zorunlu mu? | Varsayılan | Açıklama |
| :--- | :--- | :--- | :--- |
| `PLATFORM_SIGNING_SECRET` | Evet (Prod) | `""` | İsteklerin HMAC-SHA256 imzasını (`X-Platform-Signature`) doğrulamak için platform sırrı. |
| `LLM_BASE_URL` | Evet (Prod) | `http://platform-llm:8000/v1` | Platform LLM vekil (proxy) servis adresi. |
| `LLM_API_KEY` | Evet (Prod) | `platform-fast-token` | LLM servis yetkilendirme anahtarı. |
| `LLM_MODEL` | Hayır | `fast` | Kullanılacak model katmanı (`fast` / `standard`). |
| `PORT` | Hayır | `8080` | Servisin dinleyeceği HTTP portu. |

---

## 4. Testlerin Çalıştırılması

Tüm sözleşme testlerini (`/v1/invoke`) ve 22 değerlendirme senaryosunu çalıştırmak için:

```bash
pytest -v
```

Çıktı özeti:
```text
tests/test_contract.py::test_health PASSED                               [ 10%]
tests/test_contract.py::test_rejects_bad_signature PASSED                [ 20%]
tests/test_contract.py::test_rejects_old_timestamp PASSED                [ 30%]
tests/test_contract.py::test_unknown_operation_is_422 PASSED             [ 40%]
tests/test_contract.py::test_schema_validation PASSED                    [ 50%]
tests/test_contract.py::test_pii_and_credit_card_masking PASSED          [ 60%]
tests/test_contract.py::test_prompt_injection_resistance PASSED          [ 70%]
tests/test_contract.py::test_ssrf_resistance PASSED                      [ 80%]
tests/test_contract.py::test_tenant_header_isolation PASSED              [ 90%]
tests/test_contract.py::test_all_eval_cases PASSED                       [100%]

======================= 10 passed in 1.68s ========================
```

---

## 5. Dizin Yapısı

```
.
├── agent.yaml                 # Agent Pazaryeri v1.1 manifestosu
├── Dockerfile                 # Bölüm 2.6 uyumlu konteyner tanımı
├── requirements.txt           # Python kütüphane bağımlılıkları
├── src/
│   ├── __init__.py
│   └── main.py                # Saf LLM tabanlı FastAPI çekirdeği (/v1/invoke, Ek A, zarf yapısı)
├── tests/
│   └── test_contract.py       # Ek B sözleşme, imza, LLM mock ve güvenlik testleri
├── evals/
│   └── cases.yaml             # 4 grupta 22 adet kapsamlı test senaryosu (expect:)
├── integrations/
│   ├── common.md              # Ortak entegrasyon ilkeleri ve mimari seçim rehberi
│   ├── claude-code.md         # Claude Code CLI MCP entegrasyonu (Bölüm 3.4)
│   ├── codex.md               # OpenAI Codex ve GitHub Actions CI entegrasyonu
│   └── cursor.mdc             # Cursor AI editörü kural dosyası (Bölüm 3.4)
├── docs/
│   └── DESCRIPTION.md         # Detaylı Türkçe ürün dokümantasyonu
├── assets/
│   ├── icon.png               # 512x512 şeffaf ikon
│   ├── cover.png              # 1200x630 kapak görseli
│   └── screenshots/
│       ├── 1.png              # 1280x800 Dashboard ekran görüntüsü
│       ├── 2.png              # 1280x800 Güvenlik kalkanı ekran görüntüsü
│       └── 3.png              # 1280x800 IDE ve CI ekran görüntüsü
├── EVAL_REPORT.md             # Kapsamlı değerlendirme ve başarı raporu
├── README.md                  # Proje ana dokümantasyonu
└── .gitignore                 # Güvenlik ve önbellek yoksayma kuralları
```

---

## 6. Güvenlik ve Gizlilik Taahhüdü

1. **Sırların Korunması:** Gizli anahtarlar asla commit edilmez, `.env` dosyasından okunur.
2. **KVKK / GDPR Uyumu:** Kullanıcı e-postaları, kredi kartları ve kimlik numaraları LLM'e iletilmeden önce temizlenir.
3. **Stateless Mimari:** Servis hiçbir kiracı verisini diskte veya kalıcı bellekte saklamaz.
