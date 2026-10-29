# scripts/ — o que é cada um e como adaptar

> Estes scripts **importam os módulos do Saiyaku** (`device.py`, `meta.py`, `exploit.py`, …).
> Copie todos eles para a pasta `analysis/` dentro do pacote `saiyaku-athena-v1.1.x`.

> **Os números de bloco/inode são da MINHA unidade.** No seu aparelho eles mudam — rode
> `build_v23.py` + `parse_ext4.py` primeiro e ajuste as constantes nos builders.

---

## 1. Leitura e análise

| Script | O que faz | Como rodar |
|---|---|---|
| `build_v23.py` | gera o payload que despeja 256 KB do `userdata` | `py analysis\build_v23.py` |
| `run_dump.py` | catcher + envia o payload; salva `userdata_dump.bin` | `py -u analysis\run_dump.py` |
| `parse_ext4.py` | walk do ext4: superbloco, descritores, inodes, diretórios | `py analysis\parse_ext4.py` |
| `build_blk.py` | payload que lê N blocos de 4 KB de `userdata` | `py analysis\build_blk.py <bloco> <n> <tag>` |
| `build_blk_target.py` | idem, com partição configurável | `py analysis\build_blk_target.py <dev> <bloco> <n> <tag>` |
| `run_blk.py` | catcher + envia o `stage2_blk.elf` gerado | `py -u analysis\run_blk.py` |
| `parse_blk.py` | parse de inodes de um dump | `py analysis\parse_blk.py` |
| `parse_props.py` | parse do protobuf de `persistent_properties` | `py analysis\parse_props.py` |
| `validate_state.py` | confere inode/dirent/xattr de um dump | `py analysis\validate_state.py` |
| `build_probe_parts.py` | sonda quais partições o payload alcança | `py analysis\build_probe_parts.py` |

---

## 2. O fix do ADB

| Script | O que faz |
|---|---|
| `build_fix_adb_final.py` | gera o payload que: liga o bit do inode livre, liga o bit do bloco, grava a chave, grava o inode com o xattr `adb_keys_file`, e troca o inode do dirent `adb_keys` |
| `run_fix.py` | catcher + envia o fix |

### Constantes a ajustar (topo do `build_fix_adb_final.py`)

```python
NEW_INO        # inode livre escolhido na bitmap
BBM_BLOCK, BBM_OFF, BBM_BIT    # bitmap de blocos + byte/bit do bloco de dados
IBM_BLOCK, IBM_OFF, IBM_BIT    # bitmap de inodes + byte/bit do inode
CONTENT_BLOCK  # bloco de dados livre para a chave
INODE_BLOCK, INODE_OFF         # tabela de inodes do grupo + offset do inode
DIR_BLOCK, DIRENT_OFF          # bloco do diretório /data/misc/adb + offset do dirent adb_keys
```

Os arquivos de conteúdo/inode usados por ele (`fixed_adb_content_655931.bin`,
`selinux_labeled_adb_inode_164165.bin`) ficam na pasta `analysis/` — se você não os tem,
gere o inode com o layout da seção 3.4 do `METODO_TECNICO.md`.

---

## 3. Properties (configuração USB)

| Script | O que faz |
|---|---|
| `build_inject_properties.py` | gera o payload que grava o bloco de properties + o inode 57459 com o novo tamanho |
| `make_props_fr0.py` | gera a variante com `persist.sys.factoryreset = 0` |

Fluxo: rode `parse_props.py` no bloco atual → edite os pares → gere o payload → rode
`py -u analysis\run_blk.py` depois de copiar o `.elf` resultante para `stage2_blk.elf`.

---

## 4. Utilitários do META

| Script | Uso |
|---|---|
| `alive.py` | diz qual porta COM responde ao `meta_tst` |
| `attach_payload.py` | envia um ELF a um META **já em execução** (sem power-cycle) |
| `run_payload.py` | envia um ELF arbitrário a um META novo |
| `run_robust.py` | catcher com retry do preloader |
| `meta_run.py` | helpers de espera/drain |

---

## 5. Regras de ouro

1. **Catcher SEMPRE antes do power-cycle** — a janela do preloader dura poucos segundos.
2. **Nenhum processo segurando a COM** quando for abrir outra (mate `py`/`python`).
3. Se o envio travar com CPU ~0, o `meta_tst` está contaminado → power-cycle.
4. Cada payload termina em power-cycle para voltar ao boot normal.
5. Faça **backup raw** de `boot`, `system`, `vendor`, `userdata` antes de flashar qualquer
   coisa — é o seu botão de desfazer.
