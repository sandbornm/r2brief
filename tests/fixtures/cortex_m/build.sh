#!/usr/bin/env bash
# Rebuild the Cortex-M triage fixtures. Runs inside `rust:1.93.0-slim`:
#   docker run --rm -v "$PWD/tests/fixtures/cortex_m":/fx -w /fx rust:1.93.0-slim ./build.sh
# Writes bin/<name> (stripped, ranked), bin/<name>.sym (symbols kept, truth
# only) and manifest.json with each fixture's expected user main.
set -euo pipefail
cd "$(dirname "$0")"
export CARGO_INCREMENTAL=0 SOURCE_DATE_EPOCH=0
rustup target add thumbv6m-none-eabi thumbv7m-none-eabi thumbv7em-none-eabihf >/dev/null 2>&1
rustup component add llvm-tools >/dev/null 2>&1
TOOLS="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin"
OUT="$PWD/bin"
WORK="${CARGO_TARGET_DIR:-/tmp/fx-target}"
rm -rf "$OUT" && mkdir -p "$OUT"
: > /tmp/fx-rows.tsv

emit() {  # emit <name> <elf> <truth-symbol-regex>
  local name=$1 elf=$2 pattern=$3
  "$TOOLS/llvm-strip" --strip-debug -o "$OUT/$name.sym" "$elf"
  # Like arm-none-eabi-strip: drop symbols and debug info, keep .comment.
  "$TOOLS/llvm-strip" --strip-all --keep-section=.comment -o "$OUT/$name" "$elf"
  local line
  line=$("$TOOLS/llvm-nm" "$OUT/$name.sym" | awk -v pat="$pattern" '$2 ~ /[tT]/ && $3 ~ pat {print $1, $3; exit}')
  [ -n "$line" ] || { echo "no truth symbol $pattern in $name" >&2; exit 1; }
  printf '%s\t%s\t%s\n' "$name" "${line%% *}" "${line#* }" >> /tmp/fx-rows.tsv
}

for target in thumbv6m-none-eabi thumbv7m-none-eabi thumbv7em-none-eabihf; do
  short=${target%%-*}
  for opt in o0 release oz; do
    for pre in nopre pre; do
      args=(--target "$target" --target-dir "$WORK/fw-$opt-$pre")
      [ "$pre" = pre ] && args+=(--features pre_init)
      case $opt in
        o0) profile=debug ;;
        release) profile=release; args+=(--release) ;;
        oz) profile=release; args+=(--release); export CARGO_PROFILE_RELEASE_OPT_LEVEL=z ;;
      esac
      (cd fw && cargo build -q --locked "${args[@]}")
      unset CARGO_PROFILE_RELEASE_OPT_LEVEL
      elf="$WORK/fw-$opt-$pre/$target/$profile/fw_demo"
      # The user function is `__cortex_m_rt_main` unless it was inlined into `main`.
      if "$TOOLS/llvm-nm" "$elf" | grep -q '__cortex_m_rt_main17h'; then pat='__cortex_m_rt_main17h'; else pat='^main$'; fi
      emit "cmrt-$short-$opt-$pre" "$elf" "$pat"
    done
  done
done

declare -A truth=(
  [tail_exit]='^fw_user_main$' [two_bl]='^fw_user_main$' [cbz_loop]='^fw_user_main$'
  [reset_b_main]='^main$' [bw_next]='^fw_user_loop$' [inlined_loop]='^main$'
  [pre_init_tail]='^fw_user_main$' [local_label]='^fw_user_main$'
)
for shape in tail_exit two_bl cbz_loop reset_b_main bw_next inlined_loop pre_init_tail local_label; do
  (cd fwasm && cargo build -q --locked --release --target thumbv7m-none-eabi --features "$shape" --target-dir "$WORK/edge-$shape")
  emit "edge-${shape//_/-}" "$WORK/edge-$shape/thumbv7m-none-eabi/release/fw_edge" "${truth[$shape]}"
done

sort /tmp/fx-rows.tsv | awk -F'\t' '
  BEGIN { print "{"; print "  \"fixtures\": {" }
  { a = $2; sub(/^0+/, "", a); printf "%s    \"%s\": {\"symbol\": \"%s\", \"user_main\": \"0x%s\"}", (NR > 1 ? ",\n" : ""), $1, $3, a }
  END { print ""; print "  },"; print "  \"note\": \"Expected user main per fixture, from the symbol twin bin/<name>.sym. Regenerate with build.sh.\""; print "}" }
' > manifest.json
du -ch "$OUT"/* | tail -1
