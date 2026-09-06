# Modular — Türkçe başlangıç rehberi

Modular, web projelerinin kaynak kodunu inceleyen yerel bir CLI aracıdır. Güvenlik, erişilebilirlik, SEO ve site kalitesi bulgularını kanıt, kaynak konumu ve düzeltme önerisiyle raporlar. İsteğe bağlı tarayıcı denetimi, oluşturulmuş sayfa üzerinden ek kanıt toplar.

Statik tarama için AI modeli, API anahtarı, ücretli hesap veya ağ bağlantısı gerekmez. Tarama kaynak kodunu değiştirmez; düzeltmeleri rapordaki kanıtları değerlendirerek siz uygularsınız.

[English README](../README.md) · [Tüm dokümanlar](./README.md) · [CLI referansı](./cli.md)

## İlk taramanızı çalıştırın

Node.js **22.12 veya üzeri** ve npm gerekir. Depoyu klonladıktan veya indirdikten sonra terminali Modular dizininde açın:

```console
node bin/modular.js --version
npm run demo
```

Bu komutlar kaynak depodan çalışır; statik tarama için `npm install` gerekmez. [Demo proje](../examples/README.md), bulguları görebilmeniz için kasıtlı eksikler içeren sentetik bir sitedir. İlk raporu `examples/basic-site/Modular/00-overview.md` dosyasından açın.

Kendi web projenizi taramak için yolu değiştirin:

```console
node bin/modular.js check all --root "path/to/your/website" --json --sarif
```

Windows'ta boşluk içeren yolları çift tırnak içine alın:

```powershell
node bin/modular.js check all --root "D:\Projects\My Website" --json --sarif
```

Raporlar, seçtiğiniz web projesinin `Modular/` dizinine yazılır. Çıktı için boş bir dizin veya daha önce Modular tarafından oluşturulmuş rapor dizini kullanılmalıdır.

Araç desteklenen **web projelerini** kabul eder. Statik HTML ve yaygın JavaScript web çatıları desteklenir; tek başına CLI, yalnızca backend içeren servis veya yerel mobil uygulama web projesi kontrolünü geçmez. Monorepoda web uygulamasını içeren kökü seçin. [Kapsam ve sınırlar](./coverage.md) tespit koşullarını açıklar.

## Komutu her dizinden kullanın

Modular deposunda `npm link` çalıştırdıktan sonra:

```console
modular check security --root "path/to/site"
modular check mysite --root "path/to/site"
modular check all --root "path/to/site" --json --sarif
modular doctor --root "path/to/site"
```

`security` güvenlik modülünü, `mysite` site kalitesi modülünü, `all` ikisini çalıştırır. `doctor`, yapılandırma ve statik çalıştırma hazırlığını kontrol eder; tarayıcı paketlerinin veya tarayıcı ikililerinin kurulu olduğunu doğrulamaz.

Kaynak depodan ve yerel `.tgz` arşivinden kurulum desteklenir. npm kayıt sisteminde yayımlanmış bir sürüm olduğu varsayılmamalıdır. Ayrıntılar ve PowerShell komut sorunları için [kurulum](./getting-started.md) ve [sorun giderme](./troubleshooting.md) rehberlerine bakın.

## Raporu doğru okuyun

Birleşik tarama şu dosyaları üretir:

```text
Modular/
├── 00-overview.md
├── 01-security-report.md
├── 02-security-action-plan.md
├── 03-site-report.md
├── 04-site-action-plan.md
├── modular-results.json       # --json ile
└── modular-results.sarif      # --sarif ile
```

Önce genel bakıştan taramanın kapsamını ve tamamlanma durumunu kontrol edin. Ardından ayrıntılı raporda kanıtı ve kaynak satırını inceleyin. Bulgu doğrulandığında düzeltmeyi uygulayın ve aynı taramayı yeniden çalıştırın.

Önem derecesi, güven seviyesi ve elle inceleme gereksinimi farklı bilgilerdir. Elle inceleme gerektiren bir sinyal, tek başına doğrulanmış açık sayılmaz. Tamamlanan tarama sitenin güvenli veya erişilebilir olduğunu kanıtlamaz; skor da doğruluk yüzdesi değildir.

Markdown insan tarafından inceleme, JSON otomasyon, SARIF uyumlu kod tarama sistemleri için hazırlanır. Raporlar kaynak kodu parçaları ve dosya yolları içerebilir; paylaşmadan önce içeriklerini gözden geçirin. [Rapor rehberi](./reports.md) skorları, sayımları ve eksik kapsamı açıklar.

## CI için bir politika seçin

Varsayılan tarama, bulgular olsa da tamamlandığında `0` döndürür. Yüksek ve kritik bulguların CI'yi durdurmasını isterseniz:

```console
modular check all --root "path/to/site" --fail-on high --fail-on-incomplete --json --sarif
```

| Çıkış kodu | Anlamı |
|---|---|
| `0` | İstenen işlem tamamlandı; etkin eşikler aşılmadı |
| `1` | Yürütme hatası veya tamamlanamayan istenmiş denetim |
| `2` | Geçersiz kullanım, yapılandırma veya desteklenmeyen proje |
| `3` | Etkin bulgu eşiği aşıldı |

Bastırılmamış elle inceleme bulguları da eşiklere katılır. `--fail-on-incomplete`, kapsam içindeki kaynak dosyalarının eksik okunmasını ayrıca başarısız sayar. Ayrıntılı çıkış davranışı [CLI referansında](./cli.md) yer alır.

`.modular.json` ile ayarları paylaşabilir, gözden geçirilmiş bir baseline ile yalnızca yeni bulguları veya önem derecesi artışlarını engelleyebilirsiniz. Baseline oluşturmadan önce mevcut bulguları inceleyin. [Yapılandırma rehberi](./configuration.md) ve [GitHub Actions örneği](./ci.md) bu akışı gösterir.

## İsteğe bağlı tarayıcı denetimi

Güvenilir bir bağımlılık ağacında Playwright ve Axe ile uygun bir tarayıcı kurulmalıdır. Mevcut `dist` build çıktısını taramak için:

```console
modular check mysite --root "path/to/site" --runtime --runtime-static-dir dist --runtime-spa-fallback --browser-channel chrome
```

Modular build veya uygulama backend'i başlatmaz. Statik önizlemedeki oturum hataları, yanıt başlıkları ve yerel gecikmeler doğrudan üretim ortamını temsil etmez. Uzak hedef/kaynak erişimi `--allow-remote`, bağımlılık advisory sorgusu `--dependency-audit` ile ayrıca açılır. Kurulum, rota örneklemesi ve kapsam için [tarayıcı denetimi rehberini](./runtime.md) okuyun.

## Geliştirme ve paylaşım

```console
npm ci --ignore-scripts
npm run release:check
```

Bu kontrol kaynak dosyası sınırlarını, testleri, TypeScript API'sini, CLI'yi, paket içeriğini ve çevrimdışı arşiv kurulumunu doğrular. Gerçek tarayıcı entegrasyonu ayrı CI işinde çalışır. Yerel tarayıcı testleri ve yeni kural ekleme süreci [katkı rehberindedir](../CONTRIBUTING.md).

[API rehberi](./api.md) · [GitHub'a hazırlık](./GITHUB.md) · [Sürüm yayımlama](../RELEASING.md) · [Güvenlik bildirimi](../SECURITY.md) · [MIT lisansı](../LICENSE)
