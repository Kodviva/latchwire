# Latchwire — Tasarım Belgesi

Tarih: 2026-10-20 · Durum: Onaylandı (2026-10-20) · Konsept panosu: https://claude.ai/artifact/HC7LgxeMCVQ1o1gHgENJDb

> Bu belgedeki **[Karar: Claude]** etiketli maddeler, kullanıcının açıkça söylemediği ve tasarımcının verdiği kararlardır. Etiketsiz maddeler kullanıcının kendi tercihleridir.

## 1. Ne ve neden

Latchwire, WireGuard özel anahtarını bir donanım güvenlik cihazının (ilk sürümde YubiKey) **içinde** tutan, açık kaynaklı bir WireGuard istemcisidir. Özel anahtar cihazda üretilir, cihazdan hiç çıkmaz; ne diske ne belleğe yazılır.

Klasik WireGuard'da özel anahtar bilgisayarda bir dosyadır: fark edilmeden kopyalanabilir, laptop çalınırsa her sunucuda değiştirilmesi gerekir. Latchwire'da anahtar kopyalanamaz; kart takılı değilse tünel kurulamaz.

**Temel özellik:** Protokol değişmez. Sunucu tarafında hiçbir değişiklik, eklenti ya da güncelleme gerekmez; OPNsense, pfSense, Linux, MikroTik dahil her standart WireGuard sunucusuyla çalışır. Sunucu yalnızca açık anahtarı görür.

**Kimin için:** İlk günden GitHub'daki herkes için halka açık bir proje. Hedef kitle: kendi VPN'ini yöneten teknik kullanıcılar, küçük/orta şirket BT ekipleri, uyumluluk gereği cihaza bağlı kimlik isteyen kurumlar.

**Proje adı:** Latchwire. `latchwire.com` alındı. "WireGuard" adı marka koruması altında (Jason A. Donenfeld); ürün adında kullanılmaz, yalnızca "WireGuard® uyumlu" ifadesi ve footer'da marka notu kullanılır.

## 2. Hedefler

1. YubiKey PIV (firmware 5.7+, X25519) ile çalışan, standart WireGuard sunucularına bağlanan masaüstü istemci: macOS, Windows, Linux. **[Karar: Claude]** — platform seçimi.
2. Değiştirilebilir **donanım arka ucu (KeyProvider) mimarisi**: yeni bir donanım türü, çekirdeğe dokunmadan eklenebilmeli.
3. Basit kurulum akışı: kartı tak → anahtarı kartta üret → açık anahtarı sunucuya ekle → PIN gir, bağlan (konsept panosundaki 3 ekran).
4. Yedekleme modeli: anahtar kopyalanamadığından yedek = ikinci kart, sunucuda ikinci eş (peer). Uygulama bunu kurulumda önerir.
5. Çok dilli uygulama ve tanıtım sitesi: TR, EN, ES, PT-BR, DE, FR, RU, ZH-Hans, JA, KO. **[Karar: Claude]** — dil listesi. Arapça (RTL) sonraki aşamaya.
6. Tanıtım sitesi `latchwire.com` üzerinde.
7. **Ağ tarafında resmî WireGuard istemcileriyle tam eşitlik** (her üç platformda): adres, rotalar, tüm trafiği tünelden geçirme (`0.0.0.0/0`, `::/0`), platforma özgü DNS, sızıntı korumalı kill switch, aynı anda birden çok tünel, oturum açılışında ve güvenilmeyen ağlarda otomatik bağlanma (on-demand).
8. **Kapsam tek, yayın esnek:** üç platform, 10 dil ve site v1 kapsamında birlikte geliştirilir ve hazır hâle getirilir. Aynı gün yayın şartı yok; bir platform (ör. Store onayı bekleyen Windows) hazır olunca ayrıca yayınlanabilir.
9. **Lisans: Apache-2.0.** Katkı modeli DCO (`Signed-off-by`), CLA yok. **[Karar: Claude]** — DCO.

Ekip büyüklüğü ve son tarih belirlenmedi; plan, kalemleri paralel yürütülebilecek parçalara bölmelidir.

## 3. Hedef olmayanlar (v1'de yok)

- **2. sınıf arka uçlar** (TPM / Windows Hello, Secure Enclave / Touch ID, FIDO2 hmac-secret / WebAuthn PRF passkey). Mimari bunlara izin verir ama v1'de **uygulanmaz**. Bu sınıfta anahtar donanımla şifreli saklanır ama kullanımda RAM'e açılır; "kopyalanamaz" iddiasını taşımaz.
- OpenPGP kart ve PKCS#11 arka uçları: v1.x (v1'den hemen sonra), v1 değil.
- Mobil (iOS/Android). Not: NFC her el sıkışmada (≈2 dk) dokunma gerektireceği için mobilde yalnızca USB-C ile takılı anahtar mantıklı.
- Sunucu bileşeni, mesh/koordinasyon sunucusu, hesap sistemi, bulut servisi.
- Protokol değişikliği.
- Telemetri.

## 4. Anti-hedefler (çalışsa bile başarısızlık sayılır)

- Özel anahtarın herhangi bir anda diske, belleğe, log'a ya da swap'a çıkması.
- Sunucu tarafında değişiklik gerektirmesi.
- Güvenlik iddialarının abartılması: 1. sınıf ile 2. sınıf (ileride eklenirse) arayüzde ve sitede açıkça farklı etiketlenmeli.
- Kurulumun teknik olmayan bir BT yöneticisini kaçıracak kadar zor olması.
- Kullanıcının PIN'inin uygulama tarafından saklanması.

## 5. Teknik çekirdek

### 5.1 Kriptografik dayanak
WireGuard, Noise IK el sıkışmasında kalıcı (static) anahtarla yalnızca X25519 anahtar anlaşması (DH) yapar. Şifreleme, geçici anahtarlar ve oturum anahtarları yazılımda kalır. Kalıcı özel anahtarın kullanıldığı noktalar:

- **ss** = DH(kalıcı_özel, eşin_kalıcı_açık) — eş başına bir kez hesaplanır ve önbelleğe alınır (wireguard-go bunu zaten "precomputedStaticStatic" olarak tutar). Latchwire bunu eş eklenirken / bağlanırken kartla bir kez hesaplar.
- **es / se** = DH(kalıcı_özel, karşı tarafın_geçici_açık) — **her el sıkışmada** kartla bir işlem (başlatan rolünde yanıt işlenirken, yanıtlayan rolünde başlatma işlenirken).

Önbelleğe alınan `ss` bellekte durur; bu kabul edilen bir ödünleşimdir: belleği okuyan bir saldırgan `ss`'yi alsa bile, her el sıkışmadaki geçici-anahtar DH'si kart olmadan yapılamayacağı için tünel kuramaz. Bu özellik güvenlik modeli belgesinde açıkça yazılmalı.

El sıkışma sıklığı ≈2 dakikada bir, eş başına. Kart işlem süresi (onlarca–birkaç yüz ms) veri trafiğini etkilememeli; el sıkışma işlemesi veri yolunu bloklamamalı.

### 5.2 Taban
- **wireguard-go** (Go, MIT) üzerinde minimal bir yama/çatal. **[Karar: Claude]** — Go ve wireguard-go. Gerekçe: kullanıcı alanında çalışır, üç masaüstü platformunu destekler, MIT lisanslı. Linux çekirdek modülü karta erişemediği için kullanılmaz.
- Yama, `NoisePrivateKey` ile yapılan tüm DH çağrılarını bir `KeyProvider` arayüzüne yönlendirir. Yama küçük tutulmalı ki upstream'e kolay rebase edilsin.
- Windows'ta TUN için Wintun (imzalı, dağıtılabilir DLL; değiştirilmez).

### 5.3 KeyProvider arayüzü (kavramsal)
- `PublicKey() → [32]byte`
- `X25519(peerPublic [32]byte) → ([32]byte, error)` — tek kriptografik işlem
- `Describe()` → cihaz tipi, seri, slot, **sınıf (tier 1/2)**
- Yaşam döngüsü olayları: cihaz takıldı/çıkarıldı, PIN gerekli, PIN hatalı (kalan hak sayısıyla).
- Arayüz, 2. sınıf arka uçların ileride aynı yere takılabileceği şekilde tasarlanır; v1'de yalnızca PIV uygulaması var.

### 5.4 YubiKey PIV arka ucu (v1)
- Anahtar **kartta üretilir** (X25519, PIV firmware 5.7+). Dışarıdan anahtar içe aktarma **v1'de yok** **[Karar: Claude]** — üretim kartta olmazsa "kopyalanamaz" iddiası doğrulanamaz.
- Varsayılan slot: **retired key management slot 82** (82–95 arası seçilebilir). 9a/9c/9d/9e varsayılan olarak kullanılmaz, çünkü kullanıcılar bunları macOS/Windows akıllı kart girişi için kullanıyor. **[Karar: Claude]**
- PIN politikası: oturum başına bir kez (kart takılı ve güç almaya devam ettiği sürece).
- Dokunma politikası: v1'de yalnızca **"hiç"**. **[Karar: Claude]** — YubiKey'de "önbellekli" dokunma yalnızca ~15 saniye geçerlidir; el sıkışma ≈2 dakikada bir olduğundan "önbellekli" de pratikte her el sıkışmada dokunma demektir. PIN ve dokunma politikaları anahtar üretilirken kalıcı olarak belirlenir; sonradan değiştirmek anahtarı yeniden üretip her sunucuya yeniden eklemeyi gerektirir. Uygulama içinde kartın zorlamadığı bir "bağlanırken onay" adımı varsa, bu donanım güvencesi gibi **sunulmaz**. Konsept panosundaki "Bağlanırken bir kez" seçeneği kaldırılacak.
- **Fabrika ayarlı kart:** Kartta varsayılan PIN/PUK veya varsayılan management key varsa, anahtar üretmeden önce uygulama PIN ve PUK'u değiştirmeyi **zorunlu** tutar ve management key'i ykman ile uyumlu "PIN korumalı management key" moduna geçirir. Böylece kullanıcıdan 24 baytlık anahtar istenmez, ykman kullanıcılarının kartı bozulmaz. Kartta özel (PIN korumasız) bir management key varsa kullanıcıdan o istenir. **[Karar: Claude]** — not: anahtar üretimi PIN değil management key gerektirir; ekran metinleri buna göre yazılır.
- **Dolu slot:** Uygulama varsayılan olarak ilk boş retired slotu seçer; dolu bir slotun üzerine, ne olduğu gösterilip açık onay alınmadan **asla** yazmaz. **[Karar: Claude]**
- **Uyku/uyanma:** Uykuda USB gücü kesilip kart sıfırlanırsa uyanınca PIN yeniden istenir; bu v1'de kabul edilir. Otomatik bağlanma (hedef 7) oturum açıldıktan sonra çalışır; oturum açılmadan önce bağlanma ve "PIN istemeyen" (PIN policy never) anahtar v1'de yok, çünkü kart işlemi kullanıcı oturumundaki ajanda yapılır. **[Karar: Claude]**
- PIN uygulama tarafından **saklanmaz**; sadece kullanıcıdan alınıp karta iletilir. Kalan PIN hakkı arayüzde gösterilir; 1 hak kaldığında açık uyarı verilir.
- Başka bir uygulama karta erişip PIN doğrulamasını düşürürse (ör. Yubico Authenticator, ykman) uygulama PIN'i yeniden ister; bu normal akış olarak ele alınır, hata olarak değil.
- **v1.x adayı:** PIV attestation (f9 slotu) ile "bu anahtar gerçekten YubiKey'de üretildi" kanıtının dışa aktarılması.

### 5.5 Kart çıkarılınca
Kart çıkarıldığında (PC/SC olayı) oturum anahtarları **hemen** sıfırlanır ve tünel kapanır. **[Karar: Claude]** — konsept panosundaki "en geç 3 dakika" metni bu karara göre güncellenecek.

### 5.6 Süreç yapısı
- **Ayrıcalıklı servis (daemon):** TUN arayüzü, wireguard-go cihazı, ağ ayarları. macOS'ta launchd daemon, Windows'ta servis, Linux'ta systemd.
- **Kullanıcı oturumundaki anahtar ajanı:** Kart erişimi (PC/SC) ve PIN girişi, oturum açmış kullanıcının bağlamında çalışan bir ajanda yapılır; daemon her X25519 işlemini kimliği doğrulanmış yerel IPC üzerinden bu ajana sorar. **[Karar: Claude]** — üç platformda tek tip mimari. Gerekçe: Windows'ta SYSTEM servisinin kullanıcının kartına erişimi (hızlı kullanıcı değiştirme, RDP ile yönlendirilen kartlar) belirsiz; PIN zaten kullanıcıdan geliyor. Sonucu: tünel yalnızca kullanıcı oturumu açıkken ve ajan çalışırken kurulabilir; bu, v1'in masaüstü odağıyla uyumlu.
- **Kullanıcı arayüzü:** menü çubuğu / sistem tepsisi uygulaması (ajanı barındırabilir) + `latchwire` komut satırı aracı.
- **Yetki:** Tünel ekleme/silme ve yapılandırma değişikliği yalnızca yöneticilere (macOS `admin`, Windows Administrators, Linux `sudo`/belirlenen grup) açıktır. Bağlan/kes ve PIN girişi, kartı takan aktif oturum kullanıcısına açıktır. wireguard-windows modeline yakın. **[Karar: Claude]**
- macOS dağıtımı App Store dışından (Developer ID + notarization). App Store / NetworkExtension v1 kapsamı dışı. **[Karar: Claude]**

### 5.7 Yapılandırma
- Standart WireGuard `.conf` içe aktarılabilir; `PrivateKey` satırı yok sayılır/olmamalıdır.
- Özel anahtar yerine anahtar referansı tutulur: cihaz tipi + seri + slot (ör. `piv://40727512/82`). Biçimin tam sözdizimi yapıcıya bırakılmıştır.
- Bir tünel birden fazla karta bağlanabilir (yedek kart); her kart sunucuda ayrı bir eştir ve kendi tünel IP'sine sahiptir (WireGuard aynı AllowedIPs'i iki eşe veremez).

## 6. Kullanıcı deneyimi (konsept panosundaki akış)

1. **Kartı tak ve oluştur:** uyumlu cihazlar listelenir (model, seri, firmware). Slot ve dokunma ayarı, PIN istenerek anahtar kartta üretilir.
2. **Açık anahtarı ekle:** açık anahtar, kopyalanabilir `[Peer]` bloğu, QR, sunucu `.conf` içe aktarma, "yedek kart için de oluştur".
3. **Tüneller:** durum, bağlı kart, son el sıkışma, bağlan/kes. Kart çıkınca anında kesilir ve açıklayıcı mesaj gösterilir.

Görsel yön: koyu tema, amber vurgu rengi (#F2B544), Space Grotesk + Inter + JetBrains Mono. **[Karar: Claude]**

## 7. Tanıtım sitesi

- `latchwire.com`, statik site, 10 dilde, dil seçici; URL başına dil (ör. `/tr/`, `/en/`). **[Karar: Claude]**
- Bölümler: ana başlık ("VPN anahtarın kopyalanamaz olsun"), 3 adım, klasik WireGuard karşılaştırma tablosu, desteklenen donanım (v1 / yakında / yol haritası ayrı etiketli), kurulum komutları, footer'da marka notu.
- Uydurma istatistik, sahte müşteri logosu, sahte kullanıcı yorumu **yok**.
- Site teknolojisi yapıcıya bırakılmıştır.

## 8. Çeviri

- Uygulama metinleri ve site için tek bir çeviri kaynağı biçimi; çoğul ve yer tutucu destekli (ICU MessageFormat benzeri).
- Kaynak dil İngilizce, ilk çeviri Türkçe (kullanıcı tarafından gözden geçirilir); diğer diller topluluk katkısına açık.

## 9. Dağıtım

- **macOS:** Apple Developer hesabı mevcut. Developer ID ile imzalı + notarize; Homebrew cask ve doğrudan indirme.
- **Windows:** Microsoft Store üzerinden (Store başvurusu yapıldı, aktif olması bekleniyor). Ayrı bir kod imzalama sertifikası alınmayacak; imzalamayı Store üstlenir. winget, Store kaydına yönlendirir. Store aktif olana kadar Windows sürümü yayınlanamaz; hedef 8 gereği bu diğer platformları bekletmez.
- **Linux:** `.deb`, `.rpm`, tarball.
- Tekrarlanabilir derleme (reproducible build) ve imzalı sürümler hedeflenir.

## 10. Güvenlik belgeleri (v1 ile birlikte)

- Tehdit modeli: neye karşı korur (dosya/disk kopyalama, çalınan laptop, yedekten sızma), neye karşı korumaz (kart takılıyken makineyi ele geçiren zararlı yazılımın tüneli kullanması, oturum anahtarlarının bellekte olması, önbelleğe alınan `ss`).
- Güvenlik açığı bildirme politikası (`SECURITY.md`).

## 11. Yapıcıya bırakılanlar

- Masaüstü arayüz çatısı (Go ile uyumlu, menü çubuğu/tepsi desteği olan bir çözüm tercih edilir).
- PC/SC erişim kütüphanesi ve X25519 PIV komutlarının uygulanma biçimi.
- IPC mekanizması, yapılandırma dosya biçiminin sözdizimi, depo klasör yapısı.
- Site teknolojisi ve barındırma.
- Test stratejisi (gerçek YubiKey ile entegrasyon testleri dahil).

## 12. İlk risk/doğrulama noktaları (plan öncesi kısa deneme önerilir)

1. YubiKey PIV X25519 ECDH'sinin, wireguard-go el sıkışmasında beklenen çıktıyı ürettiğinin kanıtı (gerçek kartla, standart bir WireGuard sunucusuna bağlanarak).
2. Daemon ↔ kullanıcı oturumu ajanı IPC'sinin üç platformda el sıkışma süresini makul tuttuğunun ölçülmesi (kart işlemi + IPC).
3. Kart çıkarma olayının üç platformda güvenilir şekilde algılanması.
4. **Microsoft Store paketlemesi:** Store'un kabul ettiği paket biçiminin (MSIX ya da Store'da yayınlanan Win32 yükleyici) bir Windows servisini ve Wintun ağ sürücüsünü kurmaya izin verip vermediği. MSIX sürücü kurulumunu desteklemeyebilir; Win32 yükleyici yolu ise yükleyicinin ayrıca imzalanmasını gerektirebilir. Bu doğrulanmadan Windows dağıtım planı kesinleşmez; sonuç "ayrı imza sertifikası almayacağız" kararını etkileyebilir.
5. **Tam ağ eşitliği kapsamı:** kill switch, çoklu tünel ve on-demand her platformda ayrı iş; resmî wireguard-windows ve wireguard-apple uygulamalarının bu bölümleri (lisansları uygunsa) referans alınmalı. Tek seferde yayın hedefiyle birlikte bu, v1 takvimini en çok uzatan kalemdir.
