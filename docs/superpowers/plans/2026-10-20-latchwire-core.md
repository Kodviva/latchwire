# Latchwire Çekirdek (Plan 1/5) — Uygulama Planı

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** YubiKey PIV içindeki X25519 anahtarıyla standart bir WireGuard sunucusuna bağlanan çalışan çekirdek: yamalı wireguard-go, PIV arka ucu, kullanıcı oturumu ajanı, ayrıcalıklı servis ve `latchwire` komut satırı (macOS + Linux).

**Architecture:** wireguard-go, kalıcı anahtarı bir `StaticKey` arayüzü arkasına alan küçük bir yamayla `third_party/` altında tutulur. Ayrıcalıklı servis (daemon) tünelleri yönetir; her X25519 işlemini, kartı ve PIN girişini sahiplenen kullanıcı oturumu ajanına yerel unix soketi üzerinden sorar. Ajan kartları 1 saniyede bir yoklar; kart çıkınca servis tüneli kapatır.

**Tech Stack:** Go 1.25, wireguard-go (commit `2631ce99a06f27120d581611cf125d68bc6aa565`), `github.com/go-piv/piv-go/v2` v2.6.0 (PC/SC; Linux'ta `libpcsclite-dev` + `pcscd`), `golang.org/x/sys/unix`, `golang.org/x/term`, wireguard-go `tun/netstack` (yalnızca testler).

**Spec:** `docs/superpowers/specs/2026-10-20-latchwire-design.md`

**Bu planın kapsamı dışında (sonraki planlar):** Plan 2 tam ağ eşitliği (DNS, tam tünel, kill switch, çoklu tünel, on-demand, Windows ağı); Plan 3 masaüstü arayüz + i18n; Plan 4 site; Plan 5 paketleme/imza. Bu plan yalnızca macOS ve Linux'ta, `Address` + `AllowedIPs` rotalarıyla minimal ağ kurar.

## Global Constraints

- Go modül yolu: `github.com/Kodviva/latchwire`; `go 1.25`. Depo kökü: `~/Developer/latchwire`. Lisans: Apache-2.0; katkı modeli DCO (`Signed-off-by`).
- wireguard-go `third_party/wireguard-go` altında, `go.mod`'da `replace golang.zx2c4.com/wireguard => ./third_party/wireguard-go`. Yama minimal; her değişiklik `third_party/wireguard-go/PATCHES.md`'de listelenir. Upstream `go test ./...` yamadan sonra da geçmeli.
- Özel anahtar hiçbir zaman diske, log'a, IPC mesajına yazılmaz. IPC'de yalnızca açık anahtarlar ve X25519 çıktısı taşınır; X25519 çıktısı ve PIN asla log'lanmaz.
- PIN uygulama tarafından saklanmaz (struct alanı, dosya, ortam değişkeni yok); yalnızca prompt callback'inden alınıp karta iletilir.
- **Varsayılan PIN asla denenmez.** `VerifyPIN`/`SetPIN` yalnızca kullanıcının o an girdiği PIN ile çağrılır. "Fabrika ayarlı kart" tespiti yalnızca varsayılan management key ile yapılır (management key doğrulamasının PIN deneme sayacı yoktur). Spec §5.4'teki "varsayılan PIN/PUK tespiti" bu şekilde daraltılmıştır.
- PIV gereksinimleri: firmware ≥ 5.7.0; algoritma X25519; `PINPolicyOnce`; `TouchPolicyNever`; slotlar yalnızca retired `0x82`–`0x95`; varsayılan = ilk boş slot; dolu slota yalnızca açık `--force` ile yazılır; yalnızca kartta üretilmiş (`Origin` = generated) anahtarlar kullanılır.
- KeyRef biçimi: `piv://<seri-ondalık>/<slot-2-hane-küçük-hex>`, ör. `piv://40727512/82`.
- Kart işlem sınırları: her kart işlemine 3 sn zaman aşımı; **yalnızca yanıtlayan rolündeki** işlemler (gelen başlatma paketleri) 5 işlem/sn, ani patlama 10 ile sınırlanır. Ön hesaplama ve kendi başlattığımız el sıkışmalar sınırlanmaz; böylece sahte başlatma seli meşru el sıkışmaları aç bırakamaz.
- Kart çıkarma → tünel kapanışı ≤ 2 sn (yoklama aralığı 1 sn).
- Servis soketi: `/var/run/latchwire.sock`, mod `0666`; yetki her çağrıda karşı tarafın uid'siyle (peer credentials) kontrol edilir. Tünel ekleme/silme: yalnızca yönetici (uid 0; macOS `admin` grubu; Linux `sudo`, `wheel` veya `latchwire` grubu). Bağlan/kes/durum: yönetici veya kayıtlı ajanın uid'si.
- Tünel yapılandırma deposu: Linux `/etc/latchwire/tunnels/`, macOS `/Library/Application Support/Latchwire/tunnels/`; dosyalar `0600 root`.
- Kullanıcıya görünen tüm metinler `internal/msg/en.go` içinde sabit olarak tutulur (Plan 3'te i18n'e taşınacak); kod içinde dağınık metin yok.
- CLI bağımlılıksız: stdlib `flag` ile alt komutlar.

## Review Focus

1. **Kimliği doğrulanmamış başlatma (initiation) seli:** Açık anahtar herkese açık olduğu için saldırgan geçerli `mac1` ile başlatma paketleri gönderip her birinde kart işlemi tetikleyebilir. Beklenen: yanıtlayan bütçesi fazlasını reddeder, kendi el sıkışmalarımız etkilenmez, tünel çalışmaya devam eder. → Task 2 `TestLimitRejectsBurst`, `TestInitiatorNotLimited`; Task 7 `TestInitiationFloodDoesNotStarveHandshake`.
2. **El sıkışma sırasında ajan bağlantısı kopar / kart yoktur:** Beklenen: `SharedSecret` hata döner, panik yok, el sıkışma düşer; kart dönünce `RecomputeStaticStatic` ile toparlanır. → Task 1 `TestStaticKeyErrorNoPanic`, `TestRecomputeStaticStatic`; Task 7 `TestAgentDisconnectFailsHandshakeCleanly`.
3. **Yanlış PIN:** Beklenen: deneme hakkı kullanıcıya gösterilir, yazılım kendi kendine tekrar denemez, 1 hak kaldığında açık uyarı, 0'da hiç sorulmaz. → Task 6 `TestWrongPINDoesNotLoop`, `TestLastRetryWarns`, `TestBlockedPINNeverPrompts`.
4. **İki kart takılı:** Beklenen: KeyRef'teki seri numarası hangi kartı gösteriyorsa o kullanılır; "ilk bulunan kart" asla. → Task 4 `TestOpenSelectsBySerial`.
5. **Başka uygulama PIN doğrulamasını düşürür** (Yubico Authenticator, ykman): Beklenen: bir sonraki işlemde PIN bir kez yeniden sorulur, hata olarak değil normal akış olarak. → Task 6 `TestReverificationAfterExternalReset`.

---

### Task 1: Depo iskeleti + wireguard-go `StaticKey` yaması

**Files:**
- Create: `go.mod`, `LICENSE` (Apache-2.0 tam metin), `CONTRIBUTING.md` (DCO), `README.md` (tek paragraf + spec bağlantısı), `.gitignore`
- Create: `third_party/wireguard-go/` (commit `2631ce99a06f` kopyası, MIT `LICENSE` korunur), `third_party/wireguard-go/PATCHES.md`
- Create: `third_party/wireguard-go/device/statickey.go`
- Modify: `third_party/wireguard-go/device/device.go` (`staticIdentity`, `SetPrivateKey` ~229-283), `device/peer.go:96`, `device/noise-protocol.go:360,558`, `device/uapi.go:88-89`
- Test: `third_party/wireguard-go/device/statickey_test.go`

**Interfaces:**
- Produces (package `golang.zx2c4.com/wireguard/device`):
  - `type KeyUse int` — `UseStaticStatic` (ön hesap: `device.go:270`, `peer.go:96`), `UseInitiator` (`ConsumeMessageResponse`, `noise-protocol.go:558`), `UseResponder` (`ConsumeMessageInitiation`, `noise-protocol.go:360`)
  - `type StaticKey interface { PublicKey() NoisePublicKey; SharedSecret(peer NoisePublicKey, use KeyUse) ([NoisePublicKeySize]byte, error) }`
  - `func (device *Device) SetStaticKey(k StaticKey) error` — `nil` anahtarı temizler; `SetPrivateKey` aynı mantığı yazılım anahtarıyla bu fonksiyon üzerinden çalıştırır.
  - `func (device *Device) RecomputeStaticStatic() (failed int)` — her eş için `precomputedStaticStatic`'i yeniden hesaplar; başarısız eş sayısını döner.
  - `staticIdentity.privateKey` alanı `staticIdentity.key StaticKey` olur; yazılım anahtarı dahili `softStaticKey{sk NoisePrivateKey}` tipiyle sarılır.

- [ ] **Step 1:** `git init`, `go mod init github.com/Kodviva/latchwire`, wireguard-go'yu belirtilen commit'te `third_party/wireguard-go`'ya kopyala (`.git` hariç), `replace` satırını ekle, LICENSE/CONTRIBUTING/README/.gitignore yaz. `cd third_party/wireguard-go && go test ./...` → PASS (yamasız temel çizgi).
- [ ] **Step 2: Failing testleri yaz** — `statickey_test.go` (mevcut `randDevice` yardımcısını kullan; `countingKey` yazılım anahtarını sarar ve çağrıları sayar):

```go
func TestStaticKeyInitiatorCalls(t *testing.T)   // istemci countingKey; NewPeer + 1 tam el sıkışma (istemci başlatır) → uses == [UseStaticStatic, UseInitiator]
func TestStaticKeyResponderCalls(t *testing.T)   // countingKey yanıtlayan tarafta → uses == [UseStaticStatic, UseResponder]
func TestHandshakeKeysMatchSoftware(t *testing.T) // aynı özel anahtar SetPrivateKey vs SetStaticKey(countingKey) → üretilen keypair'lerin send/receive anahtarları birebir eşit
func TestUAPIOmitsPrivateKeyForStaticKey(t *testing.T) // SetStaticKey sonrası IpcGet çıktısında "private_key=" yok; SetPrivateKey sonrası var
func TestStaticKeyErrorNoPanic(t *testing.T)     // SharedSecret her zaman hata → CreateMessageInitiation/ConsumeMessageInitiation hata/nil döner, panik yok, keypair yok
func TestRecomputeStaticStatic(t *testing.T)     // önce hata veren, sonra düzelen anahtar: RecomputeStaticStatic() == 0 sonrası el sıkışma başarılı
```

- [ ] **Step 3:** `go test ./device/ -run 'StaticKey|Recompute|UAPIOmits|MatchSoftware'` → FAIL (`SetStaticKey undefined`).
- [ ] **Step 4:** Yamayı uygula: `statickey.go`'da arayüz + `KeyUse` + `softStaticKey`; dört kullanım yerini ilgili `KeyUse` ile `device.staticIdentity.key.SharedSecret(...)` yap (anahtar `nil` ise `errNoStaticKey`); `SetPrivateKey(sk)` → `SetStaticKey(softStaticKey{sk})` (eşitlik kısa devresi yalnızca iki tarafın da `softStaticKey` olduğu durumda); `uapi.go` `private_key`'i yalnızca anahtar `softStaticKey` ise yazar; `RecomputeStaticStatic` peers kilidi + her eşin handshake kilidi altında çalışır. `PATCHES.md`'ye değişen her dosya ve nedenini yaz. `softStaticKey.SharedSecret` `use` parametresini yok sayar.
- [ ] **Step 5:** `cd third_party/wireguard-go && go test ./...` → tamamı PASS (yeni + upstream).
- [ ] **Step 6: Commit** — `git add -A && git commit -s -m "feat(wg): StaticKey abstraction over wireguard-go static private key"`

### Task 2: KeyProvider arayüzü, wireguard adaptörü (sınırlar dahil), test anahtarı

**Files:**
- Create: `internal/keyprovider/provider.go`, `internal/keyprovider/wgadapter/adapter.go`, `internal/keyprovider/softkey/softkey.go`
- Test: `internal/keyprovider/wgadapter/adapter_test.go`

**Interfaces:**
- Consumes: `device.StaticKey`, `device.KeyUse` (Task 1).
- Produces (package `keyprovider`):
  - `type Tier int` (`Tier1 = 1`, `Tier2 = 2`)
  - `type Description struct { Kind string; Model string; Serial uint32; Slot uint8; Tier Tier }`
  - `type Provider interface { PublicKey() [32]byte; X25519(ctx context.Context, peer [32]byte) ([32]byte, error); Describe() Description }`
  - `var ErrUnavailable, ErrPINRequired, ErrPINBlocked, ErrRateLimited, ErrLowOrderPoint error`
- Produces (package `wgadapter`):
  - `type Limits struct { ResponderPerSecond float64; ResponderBurst int; Timeout time.Duration }`; `var DefaultLimits = Limits{5, 10, 3 * time.Second}`
  - `func New(p keyprovider.Provider, l Limits) device.StaticKey` — her çağrı `l.Timeout` ile; yalnızca `UseResponder` token bucket'tan geçer (`golang.org/x/time/rate`); tümü-sıfır çıktıda `ErrLowOrderPoint`.
- Produces (package `softkey`, **yalnızca testler için**): `func New() (*Key, error)`, `func FromPrivate(sk [32]byte) *Key`; `Describe().Kind == "soft-test"`.

- [ ] **Step 1: Failing testler:**

```go
func TestLimitRejectsBurst(t *testing.T)        // DefaultLimits: 10 eşzamanlı UseResponder geçer, 11.'si ErrRateLimited
func TestLimitRefills(t *testing.T)             // patlama sonrası 200ms bekle → 1 UseResponder daha geçer
func TestInitiatorNotLimited(t *testing.T)      // responder bütçesi tükenmişken UseInitiator ve UseStaticStatic geçer
func TestTimeout(t *testing.T)                  // 5s uyuyan sağlayıcı → çağrı ~3s'de context.DeadlineExceeded ile döner
func TestAdapterMatchesCurve25519(t *testing.T) // softkey ile SharedSecret == curve25519.X25519(sk, peer)
func TestAdapterRejectsLowOrder(t *testing.T)   // tümü sıfır peer → ErrLowOrderPoint
```

- [ ] **Step 2:** `go test ./internal/keyprovider/...` → FAIL.
- [ ] **Step 3:** Uygula (`golang.org/x/time/rate` yeni bağımlılık olarak kabul).
- [ ] **Step 4:** `go test ./internal/keyprovider/...` → PASS.
- [ ] **Step 5: Commit** — `feat: key provider interface and wireguard adapter with responder limits`

### Task 3: KeyRef + tünel yapılandırması

**Files:**
- Create: `internal/keyref/keyref.go`, `internal/config/config.go`, `internal/msg/en.go`
- Test: `internal/keyref/keyref_test.go`, `internal/config/config_test.go`

**Interfaces:**
- Produces: `type keyref.Ref struct { Serial uint32; Slot uint8 }`; `func keyref.Parse(s string) (Ref, error)`; `func (r Ref) String() string`.
- Produces (package `config`):
  - `type Identity struct { Ref keyref.Ref; Addresses []netip.Prefix }`
  - `type Peer struct { PublicKey [32]byte; PresharedKey *[32]byte; Endpoint string; AllowedIPs []netip.Prefix; PersistentKeepalive int }`
  - `type Tunnel struct { Name string; ListenPort int; MTU int; DNS []netip.Addr; Identities []Identity; Peers []Peer }`
  - `func Parse(name string, r io.Reader) (*Tunnel, error)`; `func (t *Tunnel) UAPI() string` (listen_port + peer'lar; **private_key asla**)
  - `var ErrPrivateKeyNotAllowed, ErrNoIdentity error`
- Sözdizimi: standart wg-quick `.conf`. Spec §5.7 "PrivateKey yok sayılır/olmamalıdır" der; bu plan **reddetmeyi** seçer, çünkü sessizce yok saymak kullanıcının elinde hâlâ bir yazılım anahtarı olduğunu gizler. Tek kimlik kısayolu: `[Interface]` içinde `KeyRef` + `Address`. Birden fazla kart: her biri ayrı `[Identity]` bölümü (`KeyRef`, `Address`); bu durumda `[Interface]`'te `KeyRef`/`Address` olmaz. Sıra = tercih sırası. `DNS` ayrıştırılır, bu planda uygulanmaz.

- [ ] **Step 1: Failing testler:**

```go
func TestRefRoundTrip(t *testing.T)        // "piv://40727512/82" → {40727512, 0x82} → aynı string
func TestRefRejectsBadSlot(t *testing.T)   // "piv://1/9a", "piv://1/96", "piv://1/81", "pkcs11://x" → hata
func TestParseShorthand(t *testing.T)      // [Interface] KeyRef+Address, 1 [Peer] → 1 Identity, alanlar dolu
func TestParseIdentities(t *testing.T)     // 2 [Identity] → sırası korunmuş 2 Identity
func TestParseRejectsPrivateKey(t *testing.T) // herhangi bir yerde PrivateKey satırı → errors.Is(err, ErrPrivateKeyNotAllowed)
func TestParseRejectsNoIdentity(t *testing.T) // KeyRef yok → ErrNoIdentity
func TestUAPINeverContainsPrivateKey(t *testing.T) // UAPI() çıktısında "private_key" yok; public_key hex, endpoint, allowed_ip doğru
```

- [ ] **Step 2:** FAIL doğrula. **Step 3:** Uygula; hata metinleri `internal/msg/en.go`'dan. **Step 4:** PASS. **Step 5: Commit** — `feat: keyref and tunnel config parsing`

### Task 4: YubiKey PIV arka ucu

**Files:**
- Create: `internal/keyprovider/piv/card.go` (dar `card` arayüzü + piv-go sarmalayıcı), `internal/keyprovider/piv/generate.go`, `internal/keyprovider/piv/provider.go`, `internal/keyprovider/piv/backend.go`
- Test: `internal/keyprovider/piv/generate_test.go`, `internal/keyprovider/piv/provider_test.go` (sahte `card`), `internal/keyprovider/piv/hardware_test.go` (`//go:build hardware`)

**Interfaces:**
- Consumes: `keyprovider.Provider`, `keyref.Ref`.
- Produces (package `piv`):
  - `type Device struct { Serial uint32; Firmware string; Reader string; Supported bool }`; `func List() ([]Device, error)` (`Supported` = firmware ≥ 5.7.0)
  - `func Open(serial uint32) (*Card, error)` — `ErrNotFound`
  - `type GenerateOptions struct { Slot uint8 /*0 = ilk boş*/; PIN string; ManagementKey []byte; NewPIN, CurrentPUK, NewPUK string; Force bool }`
  - `func (c *Card) Generate(o GenerateOptions) (keyref.Ref, [32]byte, error)`
  - `func (c *Card) Provider(ref keyref.Ref, prompt func(retriesLeft int) (string, error)) (keyprovider.Provider, error)`
  - `type Backend struct{}` with `Serials() ([]uint32, error)` and `Provider(ref, prompt)` (agent bunu kullanır)
  - `var ErrNotFound, ErrFirmwareTooOld, ErrSlotOccupied, ErrNoFreeSlot, ErrFreshCard, ErrManagementKeyRequired, ErrImportedKey, ErrNotX25519 error`
- `Generate` sırası: firmware kontrolü → management key çözümü (verilen anahtar; yoksa `Metadata(PIN)` içindeki PIN korumalı anahtar; yoksa varsayılan management key geçerliyse **fabrika kartı**: `NewPIN`/`NewPUK` (6–8 karakter) zorunlu, yoksa `ErrFreshCard`; `SetPIN(PIN, NewPIN)`, `SetPUK(CurrentPUK, NewPUK)`, rastgele 32 bayt AES-256 management key, ykman uyumlu PIN korumalı saklama; hiçbiri değilse `ErrManagementKeyRequired`) → slot seçimi → `GenerateKey(X25519, PINPolicyOnce, TouchPolicyNever)`.

- [ ] **Step 1: Failing testler (sahte kart):**

```go
func TestGenerateRejectsOldFirmware(t *testing.T)   // 5.6.0 → ErrFirmwareTooOld
func TestGenerateAutoSlotPicksFirstFree(t *testing.T) // 0x82,0x83 dolu → 0x84; KeyRef.Slot == 0x84
func TestGenerateRefusesOccupiedSlot(t *testing.T)  // Slot 0x82 dolu, Force=false → ErrSlotOccupied; GenerateKey hiç çağrılmadı
func TestGenerateUsesPolicies(t *testing.T)         // GenerateKey'e giden Key{AlgorithmX25519, PINPolicyOnce, TouchPolicyNever}
func TestFreshCardRequiresNewPIN(t *testing.T)      // varsayılan mgmt key geçerli, NewPIN boş → ErrFreshCard; SetPIN/GenerateKey çağrılmadı
func TestFreshCardHardens(t *testing.T)             // NewPIN/NewPUK dolu → SetPIN, SetPUK, SetManagementKey(32 bayt), SetMetadata sırasıyla çağrıldı
func TestNeverVerifiesDefaultPIN(t *testing.T)      // tüm Generate yollarında VerifyPIN/SetPIN'e giden eski PIN yalnızca o.PIN; "123456" asla (o.PIN farklıyken)
func TestProviderRejectsImportedKey(t *testing.T)   // KeyInfo.Origin = imported → ErrImportedKey
func TestProviderRejectsNonX25519(t *testing.T)     // KeyInfo.Algorithm = EC256 → ErrNotX25519
func TestOpenSelectsBySerial(t *testing.T)          // iki sahte okuyucu (seri 40727512, 40727513) → Open(40727513) ikinciyi açar
```

- [ ] **Step 2:** FAIL doğrula. **Step 3:** Uygula; `card` arayüzü yalnızca kullanılan piv-go yöntemlerini içerir; X25519 işlemi `*piv.X25519PrivateKey.ECDH(*ecdh.PublicKey)`. **Step 4:** `go test ./internal/keyprovider/piv/` → PASS.
- [ ] **Step 5: Donanım testi** (`hardware_test.go`; `LATCHWIRE_HW_SERIAL` ve `LATCHWIRE_HW_SLOT` yoksa `t.Skip`; yazma yalnızca `LATCHWIRE_HW_ALLOW_WRITE=1` ile; PIN `LATCHWIRE_HW_PIN`'den, testte asla sabit değer yok):

```go
func TestHardwareGenerateAndECDH(t *testing.T) // Generate → rastgele geçici e; kart.X25519(E_pub) == curve25519.X25519(e, kart_pub)
```

Run: `LATCHWIRE_HW_SERIAL=… LATCHWIRE_HW_SLOT=95 LATCHWIRE_HW_ALLOW_WRITE=1 LATCHWIRE_HW_PIN=… go test -tags hardware ./internal/keyprovider/piv/ -run Hardware -v` → PASS; ardından `ykman --device <seri> piv info` ilgili slotu X25519 olarak gösterir. (Yürütücü bu adımı kullanıcıya bırakır; PIN'i kullanıcı girer.)
- [ ] **Step 6: Commit** — `feat: YubiKey PIV X25519 backend`

### Task 5: IPC protokolü ve yetki

**Files:**
- Create: `internal/ipc/ipc.go` (çerçeve + mesaj), `internal/ipc/peercred_darwin.go`, `internal/ipc/peercred_linux.go`, `internal/ipc/admin_darwin.go`, `internal/ipc/admin_linux.go`
- Test: `internal/ipc/ipc_test.go`

**Interfaces:**
- Produces (package `ipc`):
  - `type Message struct { ID uint64 \`json:"id"\`; Method string \`json:"method,omitempty"\`; Params json.RawMessage \`json:"params,omitempty"\`; Result json.RawMessage \`json:"result,omitempty"\`; Error *Error \`json:"error,omitempty"\` }`; `type Error struct { Code, Message string }`
  - `type Conn` — çift yönlü: `func (c *Conn) Call(ctx, method string, params, result any) error`, `func (c *Conn) Handle(method string, fn func(ctx context.Context, uid uint32, params json.RawMessage) (any, error))`, `func (c *Conn) Serve(ctx) error`, `func (c *Conn) PeerUID() uint32`
  - `func Dial(path string) (*Conn, error)`; `func Listen(path string) (net.Listener, error)` (mod `0666`); `func Accept(l net.Listener) (*Conn, error)`
  - `func PeerUID(c *net.UnixConn) (uint32, error)`; `func IsAdmin(uid uint32) (bool, error)`
- Çerçeve: satır sonuyla ayrılmış JSON, mesaj başına en fazla 64 KiB; aşarsa bağlantı kapanır.
- Yöntem adları (sabitler `ipc` paketinde): ajan→servis `agent.register {serials}`, `agent.event {type, serial}` (`card_inserted` | `card_removed` | `pin_ready`); servis→ajan `key.public {ref}` → `{public}`, `key.x25519 {ref, peer}` → `{shared}` (32 bayt değerler base64); CLI→servis `tunnel.add {name, config}`, `tunnel.remove {name}`, `tunnel.connect {name}`, `tunnel.disconnect {name}`, `tunnel.status` → `[{name, state, identity, lastHandshake}]`.

- [ ] **Step 1: Failing testler:**

```go
func TestCallRoundTrip(t *testing.T)        // iki uçtan da Call/Handle aynı bağlantıda çalışır (çift yönlü)
func TestOversizeMessageCloses(t *testing.T) // 65 KiB satır → bağlantı kapanır, sunucu çökmez
func TestPeerUIDIsCaller(t *testing.T)      // geçici dizindeki sokete bağlan → PeerUID == os.Getuid()
func TestIsAdminRoot(t *testing.T)          // IsAdmin(0) == true
```

- [ ] **Step 2–4:** FAIL → uygula (`golang.org/x/sys/unix`: Linux `GetsockoptUcred(SO_PEERCRED)`, macOS `GetsockoptXucred(LOCAL_PEERCRED)`) → PASS.
- [ ] **Step 5: Commit** — `feat: bidirectional local IPC with peer credentials`

### Task 6: Kullanıcı oturumu ajanı

**Files:**
- Create: `internal/agent/agent.go`, `internal/agent/prompt_tty.go`
- Test: `internal/agent/agent_test.go` (sahte `Backend` + `softkey`)

**Interfaces:**
- Consumes: `ipc.Conn`, `keyprovider.Provider`, `keyref.Ref`, `piv.Backend` (arayüz olarak).
- Produces (package `agent`):
  - `type Backend interface { Serials() ([]uint32, error); Provider(ref keyref.Ref, prompt func(retriesLeft int) (string, error)) (keyprovider.Provider, error) }`
  - `type Prompter interface { PIN(d keyprovider.Description, retriesLeft int) (string, error); Warn(msg string) }`
  - `func New(socketPath string, b Backend, p Prompter, poll time.Duration) *Agent`; `func (a *Agent) Run(ctx context.Context) error`
  - `func NewTTYPrompter() Prompter` (`golang.org/x/term` ile yankısız)
- Davranış: bağlanınca `agent.register`; her `poll`'da (üretimde 1 sn) seri listesi farkını `agent.event` ile bildirir; `key.public` / `key.x25519` isteklerini ilgili sağlayıcıyla yanıtlar; ilk başarılı PIN sonrası `pin_ready`. PIN yalnızca bir servis isteği sırasında sorulur. Yanlış PIN o isteği hata ile bitirir; tekrar sormak yalnızca bir sonraki istekte olur. Kalan hak 1 ise sormadan önce `Warn(msg.LastPINRetry)`; 0 ise hiç sormadan `ErrPINBlocked`. Karttan "güvenlik durumu sağlanmadı" (doğrulama düştü) gelirse aynı istek içinde **bir kez** yeniden sorar.

- [ ] **Step 1: Failing testler:**

```go
func TestRegistersAndReportsCards(t *testing.T)        // sahte backend [A] → [A,B] → [B]: card_inserted B, card_removed A olayları sırayla
func TestX25519ViaIPC(t *testing.T)                    // servis tarafından key.x25519 → softkey sonucu ile eşit
func TestWrongPINDoesNotLoop(t *testing.T)             // sahte kart yanlış PIN → istek hata; Prompter.PIN tam 1 kez çağrıldı
func TestLastRetryWarns(t *testing.T)                  // kalan hak 1 → Warn, sonra PIN
func TestBlockedPINNeverPrompts(t *testing.T)          // kalan hak 0 → ErrPINBlocked; PIN 0 kez çağrıldı
func TestReverificationAfterExternalReset(t *testing.T) // doğrulama düşmüş → aynı istekte PIN 1 kez daha, sonra başarı
func TestPINNotLogged(t *testing.T)                     // log çıktısı yakalanır; girilen PIN dizesi hiçbir satırda yok
```

- [ ] **Step 2–4:** FAIL → uygula → `go test ./internal/agent/` PASS.
- [ ] **Step 5: Commit** — `feat: user-session agent owning cards and PIN prompts`

### Task 7: Servis (tünel yöneticisi) + minimal ağ yapılandırması

**Files:**
- Create: `internal/daemon/manager.go`, `internal/daemon/remotekey.go`, `internal/daemon/store.go`, `internal/netcfg/netcfg.go`, `internal/netcfg/netcfg_darwin.go`, `internal/netcfg/netcfg_linux.go`
- Test: `internal/daemon/manager_test.go` (netstack + gerçek IPC + sahte ajan backend'i), `internal/netcfg/netcfg_test.go` (komut kaydedici)

**Interfaces:**
- Consumes: `device.StaticKey`, `SetStaticKey`, `RecomputeStaticStatic` (Task 1); `wgadapter.New`, `wgadapter.DefaultLimits` (Task 2); `config.Tunnel`, `UAPI` (Task 3); `ipc` (Task 5).
- Produces (package `daemon`):
  - `type TUNFactory func(name string, mtu int) (tun.Device, netcfg.Configurer, error)`
  - `type Options struct { Socket string; StoreDir string; TUN TUNFactory; Bind func() conn.Bind; IsAdmin func(uid uint32) (bool, error) /*nil = ipc.IsAdmin*/ }`
  - `func NewManager(o Options) *Manager`; `func (m *Manager) Serve(ctx context.Context) error`
  - Tünel durumları: `"disconnected" | "connecting" | "connected" | "card_removed" | "error"`
- Produces (package `netcfg`): `type Configurer interface { Apply(iface string, addrs, routes []netip.Prefix) error; Remove() error }`; `func New(run func(name string, args ...string) error) Configurer`; `var ErrFullTunnelUnsupported` (`0.0.0.0/0` veya `::/0` → Plan 2'ye kadar açık hata).
- Bağlanma: kayıtlı ajanların kartları arasından tünelin **ilk** mevcut kimliği seçilir → `key.public` ile açık anahtar alınır → `remoteKey` (her `X25519`'u `key.x25519` IPC çağrısına çeviren `keyprovider.Provider`) `wgadapter.New(remoteKey, wgadapter.DefaultLimits)` ile sarılır → `device.NewDevice` → `SetStaticKey` → `IpcSet(t.UAPI())` → `Configurer.Apply(kimlik adresleri, tüm AllowedIPs)` → `Up`.
- `card_removed` (aktif kimliğin serisi): `device.Close()` + `Configurer.Remove()`, durum `card_removed`. `card_inserted` aynı seri ve durum `card_removed` ise otomatik yeniden bağlan. `pin_ready` → `RecomputeStaticStatic()`.
- Yetki: `tunnel.add/remove` yalnızca `IsAdmin`; `connect/disconnect/status` yönetici veya kayıtlı ajan uid'si; diğer herkes `Error{Code:"forbidden"}`.

- [ ] **Step 1: Failing testler** (sunucu: stok wireguard-go cihazı, yazılım özel anahtarı, netstack üzerinde HTTP 200 dönen dinleyici; istemci: Manager + netstack TUNFactory + aynı süreçte sahte backend'li `agent.Agent`, geçici dizinde gerçek soket):

```go
func TestConnectHTTPOverTunnel(t *testing.T)            // tunnel.add + connect → istemci netstack üzerinden sunucuya GET → 200; status "connected"
func TestCardRemovalTearsDownWithin2s(t *testing.T)     // sahte backend kartı kaldırır → ≤2s içinde status "card_removed", GET başarısız
func TestCardReinsertReconnects(t *testing.T)           // kart geri → status "connected", GET → 200
func TestAgentDisconnectFailsHandshakeCleanly(t *testing.T) // ajan bağlantısı kapatılır → yeni el sıkışma hatası, panik yok, servis ayakta
func TestInitiationFloodDoesNotStarveHandshake(t *testing.T) // istemcinin açık anahtarına geçerli mac1'li 200 başlatma/sn → UseResponder sağlayıcı çağrıları ≤ 5/sn (+10 patlama); istemcinin kendi başlattığı el sıkışma 5s içinde tamamlanır
func TestNonAdminCannotAddTunnel(t *testing.T)          // IsAdmin=false enjekte → tunnel.add "forbidden"
func TestSelectsFirstPresentIdentity(t *testing.T)      // 2 [Identity]; yalnızca ikinci kart takılı → ikinci kimlik kullanılır
```

```go
func TestDarwinApplyCommands(t *testing.T)   // kaydedilen komutlar: ifconfig utunN inet 10.0.0.2 10.0.0.2 alias; route -q -n add -inet 10.0.0.0/24 -interface utunN
func TestLinuxApplyCommands(t *testing.T)    // ip address add 10.0.0.2/32 dev X; ip link set X up; ip route add 10.0.0.0/24 dev X
func TestFullTunnelRejected(t *testing.T)    // 0.0.0.0/0 → ErrFullTunnelUnsupported, hiç komut çalışmadı
```

- [ ] **Step 2–4:** FAIL → uygula → `go test ./internal/daemon/ ./internal/netcfg/` PASS (`-race` ile de).
- [ ] **Step 5: Commit** — `feat: tunnel manager with remote hardware key and card-removal teardown`

### Task 8: `latchwire` komut satırı + uçtan uca doğrulama

**Files:**
- Create: `cmd/latchwire/main.go`, `cmd/latchwire/devices.go`, `cmd/latchwire/keygen.go`, `cmd/latchwire/tunnel.go`
- Test: `cmd/latchwire/deps_test.go`, `cmd/latchwire/keygen_test.go`

**Interfaces:**
- Consumes: Task 3–7'nin tümü.
- Komutlar: `latchwire devices`, `latchwire keygen --serial N [--slot 82] [--force]`, `latchwire pubkey <keyref>`, `latchwire agent`, `latchwire daemon` (root), `latchwire add <ad> <dosya>`, `latchwire remove <ad>`, `latchwire up <ad>`, `latchwire down <ad>`, `latchwire status`.
- `keygen`: PIN'i TTY'den sorar; kart fabrika ayarındaysa (`ErrFreshCard`) yeni PIN/PUK'u iki kez sorar ve neden gerektiğini `msg.FreshCardExplain` ile açıklar; `ErrSlotOccupied`'da slotun içeriğini gösterir ve `--force` olmadan durur. Başarıda KeyRef'i, açık anahtarı (base64) ve sunucuya eklenecek `[Peer]` bloğunu basar.

- [ ] **Step 1: Failing testler:**

```go
func TestBinaryDoesNotLinkSoftkey(t *testing.T) // `go list -deps ./cmd/latchwire` çıktısında ".../keyprovider/softkey" yok
func TestKeygenPrintsPeerBlock(t *testing.T)    // sahte kartla keygen çıktısı "[Peer]\nPublicKey = <b64>\nAllowedIPs = [TÜNEL IP'Sİ]/32" içerir
```

- [ ] **Step 2–4:** FAIL → uygula → `go test ./...` PASS; `go vet ./...` temiz; `GOOS=linux go build ./...` ve `GOOS=darwin go build ./...` başarılı.
- [ ] **Step 5: Elle donanım doğrulaması (kullanıcı yapar; PIN'i kullanıcı girer):**
  1. `latchwire devices` → iki YubiKey, `Supported: yes`.
  2. `latchwire keygen --serial 40727512` → slot 82 (9a/9d'ye dokunulmaz; `ykman piv info` 9a/9d sertifikalarının yerinde olduğunu gösterir).
  3. Açık anahtarı test için OPNsense'te yeni bir eş olarak ekle; tünel dosyasını yaz (`KeyRef = piv://40727512/82`).
  4. `sudo latchwire daemon` (bir terminal), `latchwire agent` (ikinci terminal), `sudo latchwire add ofis ofis.conf`, `latchwire up ofis` → PIN istenir → `ping` sunucu tünel IP'si başarılı.
  5. Kartı çık → `latchwire status` ≤ 2 sn içinde `card_removed`; tak → PIN ile yeniden `connected`.
- [ ] **Step 6: Commit** — `feat: latchwire CLI`

### Task 9: Güvenlik belgeleri

**Files:**
- Create: `SECURITY.md` (bildirim adresi `[GÜVENLİK E-POSTASI]` yer tutucusu, desteklenen sürümler), `docs/threat-model.md`

- [ ] **Step 1:** `docs/threat-model.md`'yi spec §10 ve §5.1'den yaz: korur (dosya/disk kopyalama, çalınan laptop, yedekten sızma); korumaz (kart takılıyken makineyi ele geçiren zararlı yazılımın tüneli kullanması, bellekteki oturum anahtarları, bellekte önbelleğe alınan `ss` ve bunun neden tünel kurmaya yetmediği); başlatma seli ve sınırlayıcı değerleri (5/sn, patlama 10, 3 sn); "varsayılan PIN asla denenmez" kuralı; 1. sınıf / 2. sınıf ayrımı.
- [ ] **Step 2:** `README.md`'ye "Durum: çekirdek, yalnızca macOS/Linux CLI" ve threat model bağlantısını ekle.
- [ ] **Step 3: Commit** — `docs: threat model and security policy`
