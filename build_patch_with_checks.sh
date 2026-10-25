#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

set -o pipefail

ncpu=$(grep -c processor /proc/cpuinfo)
HEAD=$(git rev-parse HEAD)
rc=0

get_build_targets() {
  local targets=()
  local f cfile base

  for f in $(git diff --name-only HEAD~.."$HEAD"); do
    case "$f" in
      tools/*|Documentation/*|samples/*|scripts/*|usr/*)
        continue
        ;;
      *.c)
        if [ -f "$f" ]; then
          targets+=("${f%.c}.o")
        fi
        ;;
    esac
  done

  if [ ${#targets[@]} -eq 0 ]; then
    for f in $(git diff --name-only HEAD~.."$HEAD"); do
      case "$f" in
        *.h)
          base=$(basename "$f")
          local dir
          dir=$(dirname "$f")
          for cfile in $(git grep -l "$base" -- "$dir/*.c" 'net/core/*.c' 2>/dev/null | head -n 5); do
            if [ -f "$cfile" ]; then
              targets+=("${cfile%.c}.o")
            fi
          done
          ;;
      esac
    done
  fi

  printf '%s\n' "${targets[@]}" | sed '/^$/d' | sort -u | tr '\n' ' '
}

clean_targets() {
  local out=$1
  shift
  local t
  for t in "$@"; do
    rm -f "$out/$t"
  done
}

clean_up_output() {
  local file=$1
  sed -i '/arch\/x86\/boot.* warning: symbol .* was not declared. Should it be static?/d' "$file"
  sed -i '/error: bad constant expression/d' "$file"
}

run_targeted_build() {
  local name=$1
  local output_dir=$2
  local cc=$3
  local extra_make_args=$4
  local disable_rust=$5

  local tmpfile_o
  local tmpfile_n
  tmpfile_o=$(mktemp)
  tmpfile_n=$(mktemp)

  git checkout -q "$HEAD"
  local targets_after
  targets_after=$(get_build_targets)
  if [ -z "$targets_after" ] && ! git diff --name-only HEAD~.."$HEAD" | grep -q -E "Kconfig$"; then
    echo "  [$name] No kernel C targets touched, skip"
    rm -f "$tmpfile_o" "$tmpfile_n"
    return 0
  fi

  if [ ! -f "$output_dir/.config" ] || \
     [ ! -f "$output_dir/include/generated/utsrelease.h" ] || \
     git diff --name-only HEAD~.."$HEAD" | grep -q -E "Kconfig$"
  then
    if [ -n "$PATCHES_CONFIG" ]; then
      KCONFIG_ALLCONFIG="$PATCHES_CONFIG" make CC="$cc" $extra_make_args O="$output_dir" allnoconfig >/dev/null
    else
      make CC="$cc" $extra_make_args O="$output_dir" allmodconfig >/dev/null
    fi
    ./scripts/config --file "$output_dir/.config" -d werror
    ./scripts/config --file "$output_dir/.config" -d drm_werror
    ./scripts/config --file "$output_dir/.config" -d kvm_werror
    if [ "$disable_rust" = "1" ]; then
      ./scripts/config --file "$output_dir/.config" -d rust
    fi
    make CC="$cc" $extra_make_args O="$output_dir" -j "$ncpu" olddefconfig modules_prepare >/dev/null
  fi

  git checkout -q HEAD~
  local targets_before
  targets_before=$(get_build_targets)
  if [ -n "$targets_before" ]; then
    clean_targets "$output_dir" $targets_before
    make CC="$cc" $extra_make_args O="$output_dir" -Oline -j "$ncpu" $targets_before 2> >(tee "$tmpfile_o" >&2) >/dev/null
  fi
  clean_up_output "$tmpfile_o"
  local incumbent
  incumbent=$(grep -i -c "\(warn\|error\)" "$tmpfile_o" || true)

  git checkout -q "$HEAD"
  targets_after=$(get_build_targets)
  local build_rc=0
  if [ -n "$targets_after" ]; then
    clean_targets "$output_dir" $targets_after
    make CC="$cc" $extra_make_args O="$output_dir" -Oline -j "$ncpu" $targets_after 2> >(tee "$tmpfile_n" >&2) >/dev/null || build_rc=1
  fi
  clean_up_output "$tmpfile_n"
  local current
  current=$(grep -i -c "\(warn\|error\)" "$tmpfile_n" || true)

  echo "  [$name] Errors and warnings before: $incumbent this patch: $current"

  if [ "$current" -gt "$incumbent" ] || [ "$build_rc" -ne 0 ]; then
    echo "  [$name] FAIL: New errors/warnings or build failure" 1>&2
    diff -U 0 "$tmpfile_o" "$tmpfile_n" 1>&2 || true
    rm -f "$tmpfile_o" "$tmpfile_n"
    return 1
  fi

  rm -f "$tmpfile_o" "$tmpfile_n"
  return 0
}

echo "=== Targeted build checks for $(git log -1 --pretty='%h ("%s")' "$HEAD") ==="
if [ -n "$PATCHES_CONFIG" ]; then
  run_targeted_build "custom_config" "build_allmodconfig_warn/" "ccache gcc" "W=1 C=1" "1" || rc=1
else
  run_targeted_build "build_allmodconfig_warn" "build_allmodconfig_warn/" "ccache gcc" "W=1 C=1" "1" || rc=1
  run_targeted_build "build_clang" "build_clang/" "ccache clang" "LLVM=1 W=1" "0" || rc=1
  run_targeted_build "build_32bit" "build_32bit/" "ccache gcc" "ARCH=i386 W=1" "0" || rc=1
fi

exit $rc
