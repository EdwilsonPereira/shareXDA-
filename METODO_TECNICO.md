# Método técnico — como o ADB foi habilitado sem root

Este documento descreve **como** funciona a cirurgia no ext4 do `userdata` que permite
habilitar o ADB em um build travado, e as demais descobertas (OOBE, OTA, gadgets).
Os números de bloco/inode são **da minha unidade** — no seu aparelho eles mudam; o
procedimento para descobri-los está na seção 1.

---

## 0. Limite de privilégio (importante)

O payload que roda no modo META (via `meta_tst`) executa como **`system` (uid 1000)**.
Ele consegue abrir **apenas** o dispositivo de bloco da `userdata`:

| Caminho | Resultado |
|---|---|
| `.../by-name/userdata` | ✅ OK |
| `.../by-name/lk`, `misc`, `recovery`, `boot` | ❌ EACCES |
| `/data`, `/cache` (montagens) | ❌ (não montados no META) |

Por isso todo o trabalho de "habilitar ADB" é feito **lendo e escrevendo blocos crus** da
partição `userdata`. Qualquer coisa que exija `lk`/`misc`/`boot` precisa do root do exploit.

---

## 1. Descobrir a geometria e os números no SEU aparelho

1. Rode `build_v23.py` e depois `run_dump.py` (catcher + power-cycle). Isso despeja os
   primeiros 256 KB de `userdata` em `userdata_dump.bin`.
2. Rode `parse_ext4.py`. Ele lê o superbloco (offset 1024), os descritores de grupo
   (bloco 1) e faz o walk dos inodes/diretórios, imprimindo:
   - o tamanho do bloco (`s_log_block_size`), inodes por grupo, tamanho do inode;
   - o inode da raiz (`/data` = inode 2) e o bloco do diretório raiz;
   - o caminho até `/data/misc/adb`.
3. Para ler blocos específicos: `build_blk.py <bloco> <n> <tag>` + `run_blk.py`
   (ou `build_blk_target.py <partição> <bloco> <n> <tag>` para outras partições).

### Valores que encontrei (exemplo, NÃO copie)

| Item | Valor |
|---|---|
| block size | 4096 |
| inodes/group | 8208 |
| inode size | 256 |
| `s_feature_ro_compat` | `0x17B` → **METADATA_CSUM desligado** |
| raiz `/data` | inode 2, dir no bloco 740 |
| tabela de inodes grupo 0 | bloco 227 |
| `/data/misc` | inode 164161 |
| `/data/misc/adb` | inode 164205, dir no bloco 655917 |
| tabela de inodes grupo 20 | bloco 655362 |
| bitmap de blocos grupo 20 | bloco 655360 |
| bitmap de inodes grupo 20 | bloco 655361 |
| `persistent_properties` | inode 57459, dados no bloco 519807 |

---

## 2. Propriedades persistentes (USB config)

O arquivo `/data/property/persistent_properties` é um **protobuf**: uma sequência de
mensagens `Property { name = 1; value = 2; }`, cada uma precedida de `0x0A <len>`.

O que foi injetado:

```
persist.sys.usb.config      = mtp,adb
persist.service.adb.enable  = 1
persist.service.debuggable  = 1
```

Além de (tentativa) `persist.sys.boot.oobe = 0`. **Atenção:** o sistema **reescreve**
`persist.sys.boot.oobe` para `1` a cada boot — essa propriedade não serve para pular o OOBE.

O `parse_props.py` lê o bloco e imprime os pares; o `build_inject_properties.py` e o
`make_props_fr0.py` geram o payload que regrava o bloco **e** o inode com o novo tamanho.

---

## 3. O arquivo de autorização do ADB (`adb_keys`)

### 3.1 O erro clássico: reaproveitar inode

O primeiro que tentei foi o inode **164165**, que parecia livre. Ele **pertence a um arquivo
vivo do sistema** — o kernel o reescreve a cada boot (modo `0440`, `size 153`, extent
`656331`). O `adbd` lia 153 bytes de lixo e ficava `unauthorized`.

### 3.2 O certo: inode realmente livre

Lendo a **bitmap de inodes** do grupo, escolha um bit 0. No meu caso: inode **164832**
(`164832 - 164161 = 671` → byte 83, bit 7 → máscara `0x80`).

### 3.3 O inode a gravar

| Campo | Valor |
|---|---|
| modo | `0o100644` |
| uid/gid | `1000` (system) / `2000` (shell) |
| size | tamanho da chave (722 bytes com `\n`) |
| links | 1 |
| flags | `0x80000` (extents) |
| i_block | extent header `0xF30A` + 1 extent → bloco livre (ex.: 655931) |

### 3.4 O xattr SELinux (inline)

Com `i_extra_isize = 0x20`, o espaço `0x80..0x9F` são campos extras e o **xattr inline**
começa em `0xA0`:

```
0xA0: 00 00 02 EA              magic  EXT4_XATTR_MAGIC (0xEA020000)
0xA4: 07 06 40 00 ...          entry: name_len=7, name_index=6 (security),
                               value_offs=64, value_size=28, name="selinux"
0xBC: 00 00 00 00              terminador
0xE4: "u:object_r:adb_keys_file:s0\0"
```

Sem esse atributo, o `adbd` **ignora** o arquivo mesmo com a chave certa.

### 3.5 Diretório e bitmaps

- No bloco do diretório `/data/misc/adb` (ex.: 655917), o dirent `adb_keys` tem o campo
  inode nos **4 primeiros bytes** da entrada — troque para o inode escolhido.
- Ligue o bit do inode na **bitmap de inodes** e o bit do bloco de dados na **bitmap de
  blocos** — sempre **read-modify-write** (leia o bloco, mude o byte, grave de volta).

### 3.6 Verificação

```
adb kill-server
adb devices      -> G091GM07119600EP    device
adb shell id     -> uid=2000(shell) ...
```

---

## 4. Sair do OOBE

`device_provisioned` / `user_setup_complete` **não bastam**: o app de configuração da Amazon
(`com.amazon.kindle.otter.oobe`) é o home registrado e é um **pacote protegido**
(`pm disable` / `pm uninstall` são recusados).

O launcher **real** é outro:

```
com.amazon.paladin/.app.MMLauncherActivity
```

Iniciá-lo (`am start -n ...`) sobe a interface da Alexa com toque funcional, sem conta.
Descubra componentes com `dumpsys package com.android.launcher3` (ele lista os candidatos a
HOME).

> O app de Settings (`com.android.settings`) **crasha** neste firmware com
> `null/preference-settings.json` — por isso Wi-Fi/configurações não abrem por ele.

---

## 5. Atualizar para o build suportado

### 5.1 O que NÃO funcionou

- **`adb sideload`** no recovery: o adbd do recovery é `unauthorized` e **não lê**
  `/data/misc/adb/adb_keys`.
- **`/cache/recovery/command` manual** (criar o arquivo `--update_package=...` via ext4 do
  cache): o recovery **leu** o comando (o `last_install` registrou o path), mas o instalador
  abortou na hora com `error: 26` / `time_total: 0`. Não resolvido.

### 5.2 O que funcionou: o job do updater oficial

O app `com.amazon.device.software.ota` tem jobs no `JobScheduler` (um periódico de 1 h, um
de 12 h e um diário). O de 12 h não exige `deviceIdle`:

```
adb shell cmd jobscheduler run -f com.amazon.device.software.ota 10
adb shell cmd jobscheduler run -f com.amazon.device.software.ota 0
```

Com Wi-Fi conectado, o serviço baixou o pacote e reiniciou no recovery, que aplicou o
**PS75741/7082** pelo fluxo normal (`uncrypt` + BCB).

> O pacote tem **checagem de data**: um full OTA mais antigo que o build atual aborta com
> *"Can't install this package over newer build"*.

---

## 6. O exploit (Saiyaku)

- O payload de root (stage2) tem tabela interna de perfis por *incremental*. No 7551 ele
  imprimia `No profile for incremental ..., trying latest athena-PS75741.7081N`.
- No **7082** o perfil bate. O `extract_gadgets.py` lê `libc.so` e `meta_tst` pelo protocolo
  e acha os 4 gadgets (`rx_pivot`, `eight_pop`, `pop_r3_r7`, `svc_mmap2`). No 7082 eles são
  **idênticos aos do 7080**.
- `Unsendable` = ASLR caindo em bytes que o frame não codifica (`0x55`/`0x5A`/`0xA5`). O
  tool reinicia e repete; no meu caso, 2 tentativas.
- `Party time!` = root + flash (preloader, lk, TWRP, tee, spmfw, sspm, cam_vpu — cada um com
  verificação SHA-256) + reboot para o TWRP.

---

## 7. Pós-unlock

### 7.1 Backup raw (faça antes de qualquer flash)

Do TWRP (root, adb sem auth):

```
adb pull /dev/block/platform/bootdevice/by-name/boot     backup\boot.img
adb pull /dev/block/platform/bootdevice/by-name/system   backup\system.img
...
```

`adb pull` de bloco devolve a imagem **exata** (o `dd` via pipe no `cmd.exe` pode corromper
— foi o que aconteceu comigo; compare o SHA-256 com o do aparelho).

### 7.2 LineageOS

```
twrp format data
twrp wipe system
twrp wipe cache
adb push lineage-18.1-...athena.zip /sdcard/
adb shell twrp install /sdcard/lineage-18.1-...athena.zip
twrp format data
adb reboot
```

### 7.3 Se algo der errado

- **Bootloop após patch de boot**: restaure o `boot.img` do backup (`dd` no TWRP).
- **Sem TWRP**: o `unbrick.py` do tool regrava LK/TWRP/firmwares pelo **preloader** e marca o
  BCB como `boot-recovery`.

---

## 8. Referência rápida dos scripts

| Script | Função |
|---|---|
| `build_v23.py` / `run_dump.py` | dump de 256 KB do `userdata` |
| `parse_ext4.py` | walk do ext4 (superbloco → inodes → dirs) |
| `build_blk.py` / `build_blk_target.py` | payload que lê N blocos de 4 KB |
| `run_blk.py` | catcher + envia `stage2_blk.elf` |
| `parse_blk.py` / `parse_props.py` / `validate_state.py` | parsers |
| `build_fix_adb_final.py` / `run_fix.py` | **o fix do ADB** (inode livre + xattr) |
| `build_inject_properties.py` / `make_props_fr0.py` | properties (USB config) |
| `run_payload.py` / `attach_payload.py` / `alive.py` | utilitários do META |
| `build_probe_parts.py` | sonda de acesso às partições |
