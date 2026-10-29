# Unlocking an Echo Show 8 (athena) that starts on an old, unsupported build

> **Device:** Echo Show 8 (2nd gen, `athena`, MT8183)
> **Where I started:** Fire OS 7.5.5.1 (PS7551/2335), stuck on the Amazon setup screen, no ADB at all
> **Where I ended:** PS75741/7082, bootloader unlocked, TWRP 3.7.0, LineageOS 18.1
>
> This is the path that worked for me. It is invasive — do it on your own device and keep a
> full raw backup of every partition.

## The short version

The exploit tool is not the problem — **the firmware version is**. The tool only knows how
to attack builds it has profiles for, and the old one isn't among them. On a locked unit the
only way forward is to **get to PS75741 first**, and the way to do that is to first get a
shell (ADB) on the old build.

## Phase 1 — Getting a shell on the old build

The device exposes a **MediaTek pre-boot mode** over USB for a few seconds during every
power-on. It performs a tiny text handshake, and answering it brings up a factory test
daemon on a serial port.

That daemon has a memory-corruption flaw. It can be driven into running an arbitrary ARM
binary — not as root, but as the `system` user. That is enough to reach **one** thing: the
raw **user-data partition**, which holds `/data`. Everything else on the eMMC is out of
reach at this privilege level, and that limitation shapes the whole approach.

On that partition live two things worth changing:

- the **persistent properties** file, where the USB configuration is stored (whether the
  gadget exposes ADB or just file transfer), and
- the **ADB authorization file**, which tells the daemon which computers are trusted.

Writing the USB property is conceptually simple — it is a small protobuf blob on a known
block. Writing the authorization file is harder, for two reasons that cost me a lot of time:

1. **You must not reuse an existing inode.** My first attempt wrote into an inode that
   looked free but actually belonged to a live system file that the kernel rewrites on every
   boot. The ADB daemon read a short, wrong file and kept refusing the PC. The fix was to
   pick a genuinely free inode from the allocation bitmap and repoint the directory entry
   at it.
2. **The file needs a SELinux label.** The daemon will only trust a file carrying the
   `adb_keys_file` security context, which on ext4 is an extended attribute stored inside
   the inode. Without it, a perfectly correct key file is ignored.

One useful discovery: the filesystem on my unit does **not** use metadata checksums, so a
lot of the "you need to fix directory checksums" advice that circulates is simply not
applicable here. It is worth checking before you chase that.

Once the USB configuration and the key file are in place, a normal boot brings the device up
with ADB authorized — and from there you have a regular shell.

## Phase 2 — Escaping the setup wizard

Setting the usual "device provisioned" and "setup complete" flags is not enough: the Amazon
setup application is registered as the home screen, and it is protected against being
disabled or uninstalled.

The trick is that the **real** launcher is a different application — the Alexa multimodal
launcher — and it can be started directly. Launching it puts you on the actual home screen,
with working touch navigation, without any Amazon account.

## Phase 3 — Moving to a supported build

This is where most people get stuck, and where I burned the most time.

The obvious route — boot into recovery and sideload the official update — **did not work on
my unit**: the recovery's ADB daemon does not read the authorization file from the
user-data partition, so it always reports the computer as unauthorized.

A second attempt — planting a recovery command file that points at the update package — did
make recovery read the package, but the installer aborted almost instantly. I never got a
clear reason for it.

What finally worked was **making the device update itself**: the stock OTA application runs
on a scheduler, and that scheduled job can be triggered from the shell. With Wi-Fi connected,
the application downloaded the package and rebooted into recovery, which applied
**PS75741/7082** through the normal, supported path.

One trap worth knowing: the update package refuses to install over a **newer** build. An
older full package will be rejected by its own date check, so don't try to push an older
release over a newer one.

## Phase 4 — Unlocking

On 7082 the exploit finally has a matching profile. The tool ships a helper that reads the
device's `libc` and daemon binaries over the factory protocol and locates the four code
fragments the exploit chain needs. On 7082 those offsets turned out to be identical to the
ones for 7080, so no manual profile editing was necessary.

Running the exploit can print an `Unsendable` warning. That is not a failure — it is address
randomisation placing the target where the protocol's framing cannot encode it. The tool
reboots and tries again by itself; on my unit it succeeded on the second attempt.

Once it reports success, it flashes the preloader, the unlocked bootloader, a custom
recovery, and the remaining firmware images — each verified by hash — and reboots into TWRP.

## Phase 5 — After the unlock

Before flashing anything else, **take raw backups of every partition** from the recovery —
boot, system, vendor, user data, metadata, cache, and the small firmware partitions. They
are exact, restorable images, and they saved me when a root patch later left the device
boot-looping.

From there, LineageOS 18.1 flashes cleanly with the standard routine: format data, wipe
system and cache, flash the ROM, format data again, reboot.

A few honest notes about that ROM: it is a first release, SELinux runs permissive, deep
sleep is disabled, the battery always reports 100%, and the mute key doubles as the power
button. It works, but treat it as a project, not a daily driver.

## Lessons worth passing on

- The exploit was never the blocker — **the version gap was**.
- Back up raw partitions before every step; they are your undo button.
- The factory payload runs as `system`, so anything touching the bootloader, the recovery or
  the boot image needs the exploit's root, not the payload.
- If a send hangs with no CPU usage, the factory daemon is in a bad state — power-cycle and
  start clean.
- Always start the catcher **before** powering the device on; the pre-boot window is only a
  few seconds.

Credit for the tool, the firmware images and the ROM goes to **R0rt1z2, bengris32 and
jackmthws**.

---

# Versão em português

> **Desbloqueando um Echo Show 8 (athena) que começa num build antigo e sem suporte**
>
> **Aparelho:** Echo Show 8 (2ª geração, `athena`, MT8183)
> **Onde comecei:** Fire OS 7.5.5.1 (PS7551/2335), preso na tela da conta Amazon, sem ADB
> **Onde terminei:** PS75741/7082, bootloader destravado, TWRP 3.7.0, LineageOS 18.1
>
> O problema nunca foi o exploit — foi a **versão do firmware**. A ferramenta só ataca
> builds para os quais tem perfil, e o build antigo não está entre eles. Em aparelho
> travado, o caminho é **chegar primeiro no PS75741** — e, para isso, primeiro conseguir um
> shell (ADB) no build antigo.
>
> **Fase 1 — conseguir shell:** o aparelho expõe um **modo de pré-boot da MediaTek** por USB
> nos primeiros segundos de cada boot. Respondendo ao handshake dele, sobe um daemon de
> fábrica com uma falha de memória que permite executar um binário ARM — não como root, mas
> como usuário `system`. Isso dá acesso a **uma** coisa: a partição de dados do usuário
> (onde ficam `/data`). Nela estão as propriedades persistentes (configuração USB: ADB ou só
> transferência) e o arquivo de autorização do ADB. Escrever a propriedade é simples; o
> arquivo de autorização tem duas armadilhas: **não reutilizar inode existente** (o primeiro
> que tentei pertencia a um arquivo vivo do sistema e era reescrito a cada boot) e **dar a
> ele o rótulo SELinux correto**, senão a chave é ignorada. Detalhe útil: o sistema de
> arquivos do meu aparelho **não usa checksums de metadados**, então muita recomendação de
> "consertar o checksum do diretório" simplesmente não se aplica.
>
> **Fase 2 — sair do assistente:** marcar "dispositivo provisionado" e "configuração
> concluída" não basta — o app de configuração da Amazon é o home registrado e é protegido.
> O truque é iniciar o **launcher real** (o multimodal da Alexa), que sobe a tela inicial de
> verdade, com toque funcionando e sem conta Amazon.
>
> **Fase 3 — atualizar:** sideload no recovery **não funcionou** no meu aparelho (o daemon
> do recovery não lê o arquivo de autorização do `/data`). A via do arquivo de comando de
> recovery fez o recovery ler o pacote, mas o instalador abortou quase na hora. O que
> funcionou foi **fazer o aparelho se atualizar**: o app de OTA da Amazon roda por
> agendamento, e esse job pode ser disparado pelo shell. Com Wi-Fi, ele baixou e aplicou o
> **PS75741/7082** pelo caminho normal. Armadilha: o pacote recusa instalar sobre build
> **mais novo** (checagem de data).
>
> **Fase 4 — desbloquear:** no 7082 o exploit tem perfil. O utilitário do tool lê a `libc` e
> o daemon do aparelho pelo protocolo de fábrica e acha os quatro trechos de código da
> cadeia — no 7082 idênticos aos do 7080. Se aparecer `Unsendable`, é o ASLR; o tool
> reinicia e repete sozinho. Ao dar certo, ele grava preloader, bootloader destravado,
> recovery custom e os demais firmwares (todos verificados por hash) e reinicia no TWRP.
>
> **Fase 5 — depois:** **faça backups crus de todas as partições** antes de qualquer flash —
> foi o que me salvou de um bootloop depois de um patch de root. O LineageOS 18.1 grava com
> a rotina padrão (format data → wipe system/cache → flash → format data → reboot). Avisos
> do ROM: primeira versão, SELinux permissivo, deep sleep desligado, bateria sempre 100%,
> botão Mudo vira Power.
>
> **Lições:** o exploit nunca foi o problema — a diferença de versão era; backup cru é o
> botão de desfazer; o payload de fábrica roda como `system`, então bootloader/recovery/boot
> exigem o root do exploit; se o envio travar sem CPU, o daemon está em mau estado —
> power-cycle; e sempre inicie o catcher **antes** de ligar o aparelho.
>
> Créditos ao **R0rt1z2, bengris32 e jackmthws** pelo tool, firmwares e ROM.
