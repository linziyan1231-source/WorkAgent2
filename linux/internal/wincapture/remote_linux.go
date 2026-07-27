//go:build linux

package wincapture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"time"
)

const (
	remoteInventoryLimit         = 512 * 1024 * 1024
	remoteEvidenceLimit          = 64 * 1024 * 1024
	remoteReadOnlyCommandTimeout = 12 * time.Hour
	remoteReadOnlyWaitDelay      = 5 * time.Second
)

// remoteTransport has one deliberately narrow capability.  The production
// implementation always invokes the same SSH destination and the same static
// read-only Bash program. Tests replace it with an in-memory transport.
type remoteTransport interface {
	run(context.Context, string, []string, io.Writer, int64) (stderrSummary, error)
}

type stderrSummary struct {
	Bytes    int64
	SHA256   string
	Exceeded bool
}

type sshTransport struct{}

func (sshTransport) run(ctx context.Context, action string, arguments []string, output io.Writer, maxOutput int64) (stderrSummary, error) {
	if action != "inventory" && action != "exclusions" && action != "oauth" && action != "tar" {
		return stderrSummary{}, errors.New("invalid remote read-only action")
	}
	if maxOutput < 1 {
		return stderrSummary{}, errors.New("invalid remote output bound")
	}
	commandContext, cancel := context.WithTimeout(ctx, remoteReadOnlyCommandTimeout)
	defer cancel()
	encoded := sshCommandArguments(action, arguments)
	command := exec.CommandContext(commandContext, "/usr/bin/ssh", encoded...)
	command.WaitDelay = remoteReadOnlyWaitDelay
	command.Stdin = newStaticScriptReader()
	limited := &boundedWriter{destination: output, remaining: maxOutput}
	command.Stdout = limited
	stderr := newDigestWriter(1024 * 1024)
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		if errors.Is(commandContext.Err(), context.DeadlineExceeded) {
			return stderr.summary(), fmt.Errorf("remote read-only %s timed out", action)
		}
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			code := exitError.ExitCode()
			if code >= 91 && code <= 97 {
				return stderr.summary(), fmt.Errorf("remote read-only %s failed (class %d)", action, code)
			}
		}
		return stderr.summary(), fmt.Errorf("remote read-only %s failed", action)
	}
	if limited.exceeded {
		return stderr.summary(), errors.New("remote read-only output exceeded its configured bound")
	}
	return stderr.summary(), nil
}

func sshCommandArguments(action string, arguments []string) []string {
	encoded := make([]string, 0, len(arguments)+13)
	encoded = append(encoded,
		"-T", "-oBatchMode=yes", "-oClearAllForwardings=yes", "-oForwardAgent=no", "-oForwardX11=no", "-oPermitLocalCommand=no", "-oRequestTTY=no",
		"reference-host", "--", "/usr/bin/bash", "-s", "--", action,
	)
	for _, argument := range arguments {
		encoded = append(encoded, hex.EncodeToString([]byte(argument)))
	}
	return encoded
}

type boundedWriter struct {
	destination io.Writer
	remaining   int64
	exceeded    bool
}

func (writer *boundedWriter) Write(payload []byte) (int, error) {
	original := len(payload)
	if int64(len(payload)) > writer.remaining {
		payload = payload[:writer.remaining]
		writer.exceeded = true
	}
	if len(payload) > 0 {
		written, err := writer.destination.Write(payload)
		writer.remaining -= int64(written)
		if err != nil {
			return written, err
		}
		if written != len(payload) {
			return written, io.ErrShortWrite
		}
	}
	if writer.exceeded {
		return original, errors.New("bounded remote output exceeded")
	}
	return original, nil
}

type digestWriter struct {
	hash      hashWriter
	bytes     int64
	remaining int64
	exceeded  bool
}

type hashWriter interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
}

func newDigestWriter(limit int64) *digestWriter {
	return &digestWriter{hash: sha256.New(), remaining: limit}
}

func (writer *digestWriter) Write(payload []byte) (int, error) {
	original := len(payload)
	writer.bytes += int64(original)
	kept := payload
	if int64(len(kept)) > writer.remaining {
		kept = kept[:writer.remaining]
		writer.exceeded = true
	}
	_, _ = writer.hash.Write(kept)
	writer.remaining -= int64(len(kept))
	if writer.exceeded {
		return len(kept), errors.New("bounded remote stderr exceeded")
	}
	return original, nil
}

func (writer *digestWriter) summary() stderrSummary {
	return stderrSummary{Bytes: writer.bytes, SHA256: hex.EncodeToString(writer.hash.Sum(nil)), Exceeded: writer.exceeded}
}

func inventoryArguments(source Source) []string {
	arguments := []string{source.SourcePath, source.Kind, strconv.FormatInt(source.MaxFiles, 10), strconv.FormatInt(source.MaxBytes, 10)}
	for _, exclusion := range source.Exclusions {
		arguments = append(arguments, exclusion.Path)
	}
	return arguments
}

func exclusionArguments(source Source) []string {
	arguments := []string{source.SourcePath, strconv.Itoa(len(source.Exclusions))}
	for _, exclusion := range source.Exclusions {
		arguments = append(arguments, exclusion.Path, exclusion.Type)
	}
	return arguments
}

func tarArguments(source Source) []string {
	arguments := []string{source.SourcePath, source.Kind}
	for _, exclusion := range source.Exclusions {
		arguments = append(arguments, exclusion.Path)
	}
	return arguments
}

func oauthArguments(evidence OAuthEvidence) []string {
	return []string{evidence.SourcePath, strconv.FormatInt(evidence.MaxFiles, 10), strconv.FormatInt(evidence.MaxBytes, 10)}
}

// The script accepts only hex-encoded data arguments. It never evaluates a
// path, creates a file, redirects to a filesystem object, or invokes a Windows
// mutation primitive. Its external programs are limited to find, stat,
// sha256sum, and tar; all other operations are Bash builtins.
const readOnlyRemoteScript = `set -euo pipefail
export LC_ALL=C
action=${1-}
shift || true

decode() {
  local encoded=${1-} result='' byte index
  [[ $encoded =~ ^([0-9a-f][0-9a-f])*$ ]] || return 91
  for ((index=0; index<${#encoded}; index+=2)); do
    byte=${encoded:index:2}
    [[ $byte != 00 ]] || return 91
    printf -v byte '%b' "\\x$byte"
    result+=$byte
  done
  REPLY=$result
}

safe_absolute() {
  local value=$1 component rest
  [[ $value == /* && $value != / && $value != */ && $value != *$'\n'* && $value != *$'\r'* ]] || return 91
  rest=${value#/}
  while [[ -n $rest ]]; do
    component=${rest%%/*}
    [[ -n $component && $component != . && $component != .. ]] || return 91
    if [[ $rest == */* ]]; then rest=${rest#*/}; else rest=; fi
  done
}

safe_relative() {
  local value=$1 component rest=$1
  [[ -n $value && $value != /* && $value != */ && $value != *$'\n'* && $value != *$'\r'* ]] || return 91
  while [[ -n $rest ]]; do
    component=${rest%%/*}
    [[ -n $component && $component != . && $component != .. ]] || return 91
    if [[ $rest == */* ]]; then rest=${rest#*/}; else rest=; fi
  done
}

literal_find_pattern() {
  local value=$1
  value=${value//\\/\\\\}
  value=${value//\*/\\*}
  value=${value//\?/\\?}
  value=${value//\[/\\[}
  REPLY=$value
}

metadata() {
  local target=$1 raw
  raw=$(/usr/bin/stat --printf='%f %s %Y %h %d %i %b %B' -- "$target") || return 92
  read -r MODEHEX SIZE MTIME NLINK DEVICE INODE BLOCKS BLOCK_SIZE <<<"$raw"
  [[ $MODEHEX =~ ^[0-9a-f]+$ && $SIZE =~ ^[0-9]+$ && $MTIME =~ ^-?[0-9]+$ && $NLINK =~ ^[0-9]+$ && $DEVICE =~ ^[0-9]+$ && $INODE =~ ^[0-9]+$ && $BLOCKS =~ ^[0-9]+$ && $BLOCK_SIZE =~ ^[1-9][0-9]*$ ]] || return 92
  MODE=$((16#$MODEHEX))
  PERM=$((MODE & 0777))
  TYPE=$((MODE & 16#f000))
  PHYSICAL_SIZE=$((BLOCKS*BLOCK_SIZE))
  ((PHYSICAL_SIZE >= 0 && (BLOCKS == 0 || PHYSICAL_SIZE/BLOCK_SIZE == BLOCKS))) || return 92
}

hash_file() {
  local output
  output=$(/usr/bin/sha256sum -- "$1") || return 92
  if [[ ${output:0:1} == \\ ]]; then HASH=${output:1:64}; else HASH=${output:0:64}; fi
  [[ $HASH =~ ^[0-9a-f]{64}$ ]] || return 92
}

hash_file_stable() {
  local target=$1 expected_device=${2-} before after
  metadata "$target" || return
  ((TYPE == 32768 && NLINK == 1)) || return 95
  [[ -z $expected_device || $DEVICE == "$expected_device" ]] || return 95
  ((SIZE == 0 || PHYSICAL_SIZE >= SIZE)) || return 97
  before="$MODEHEX $SIZE $MTIME $NLINK $DEVICE $INODE $BLOCKS $BLOCK_SIZE"
  hash_file "$target" || return
  STABLE_HASH=$HASH
  metadata "$target" || return
  after="$MODEHEX $SIZE $MTIME $NLINK $DEVICE $INODE $BLOCKS $BLOCK_SIZE"
  [[ $before == "$after" ]] || return 94
}

inventory_entry() {
  local entry=$1 source=$2 relative digest='' before after
  if [[ $entry == "$source" ]]; then relative=.; else relative=${entry#"$source"/}; fi
  metadata "$entry" || return
	(( (MODE & 07000) == 0 )) || return 93
	((ENTRY_COUNT < MAX_FILES)) || return 97
	ENTRY_COUNT=$((ENTRY_COUNT+1))
	before="$MODEHEX $SIZE $MTIME $NLINK $DEVICE $INODE $BLOCKS $BLOCK_SIZE"
	case $TYPE in
	  32768)
	      [[ $NLINK == 1 ]] || return 96
	      ((SIZE == 0 || PHYSICAL_SIZE >= SIZE)) || return 97
	      ((SIZE <= MAX_BYTES-BYTE_COUNT)) || return 97
	      BYTE_COUNT=$((BYTE_COUNT+SIZE))
      hash_file "$entry" || return
      digest=$HASH
      metadata "$entry" || return
      after="$MODEHEX $SIZE $MTIME $NLINK $DEVICE $INODE $BLOCKS $BLOCK_SIZE"
      [[ $before == "$after" ]] || return 94
      kind=f
      ;;
	  16384) kind=d; digest= ;;
	  40960)
	      [[ $NLINK == 1 ]] || return 96
	      kind=l
	      digest=
	      ;;
	  *) return 93 ;;
	esac
	physical_size=$PHYSICAL_SIZE
	if [[ $kind == d ]]; then canonical_size=0; else canonical_size=$SIZE; fi
	printf 'E\0%s\0%s\0%o\0%s\0%s\0%s\0%s\0%s\0%s\0%s\0' "$relative" "$kind" "$PERM" "$canonical_size" "$MTIME" "$digest" "$DEVICE" "$INODE" "$NLINK" "$physical_size"
	if [[ $kind == l ]]; then
	  /usr/bin/find "$entry" -maxdepth 0 -printf '%l\0'
	  metadata "$entry" || return
	  after="$MODEHEX $SIZE $MTIME $NLINK $DEVICE $INODE $BLOCKS $BLOCK_SIZE"
	  [[ $before == "$after" ]] || return 94
	else
	  printf '\0'
	fi
}

case $action in
  inventory)
    (($# >= 4)) || exit 91
    decode "$1"; source=$REPLY; shift
    decode "$1"; expected_kind=$REPLY; shift
    decode "$1"; max_files=$REPLY; shift
    decode "$1"; max_bytes=$REPLY; shift
    safe_absolute "$source"
    [[ $expected_kind == file || $expected_kind == directory ]]
    [[ $max_files =~ ^[1-9][0-9]*$ && $max_bytes =~ ^[0-9]+$ ]]
	((max_files <= 20000000 && max_bytes <= 1099511627776)) || exit 91
	MAX_FILES=$max_files MAX_BYTES=$max_bytes ENTRY_COUNT=0 BYTE_COUNT=0
    exclusions=()
    for encoded in "$@"; do decode "$encoded"; safe_relative "$REPLY"; exclusions+=("$REPLY"); done
    if [[ $expected_kind == file ]]; then
      (($# == 0))
      metadata "$source"
      ((TYPE == 32768))
      printf 'WAI1\0'
      inventory_entry "$source" "$source"
    else
      metadata "$source"
      ((TYPE == 16384))
      find_args=("$source" -xdev)
      if ((${#exclusions[@]})); then
        find_args+=( '(' -false )
		for relative in "${exclusions[@]}"; do
		  literal_find_pattern "$source/$relative"
		  find_args+=( -o -path "$REPLY" )
		done
        find_args+=( ')' -prune -o -print0 )
      else
        find_args+=( -print0 )
      fi
      printf 'WAI1\0'
      /usr/bin/find "${find_args[@]}" | while IFS= read -r -d '' entry; do inventory_entry "$entry" "$source"; done
    fi
    ;;
  exclusions)
    (($# >= 2)) || exit 91
    decode "$1"; source=$REPLY; shift
    decode "$1"; count=$REPLY; shift
    safe_absolute "$source"
    [[ $count =~ ^[0-9]+$ ]]
    (($# == count*2))
    printf 'WAX1\0'
    if ((count == 0)); then exit 0; fi
    metadata "$source"; ((TYPE == 16384)); source_device=$DEVICE
    index=0
    while (($#)); do
      decode "$1"; relative=$REPLY; shift
      decode "$1"; exclusion_type=$REPLY; shift
      safe_relative "$relative"
      target="$source/$relative"
      metadata "$target"
      ((TYPE == 16384)) && [[ $DEVICE == "$source_device" ]] || exit 95
      root_metadata="$MODEHEX $SIZE $MTIME $NLINK $DEVICE $INODE $BLOCKS $BLOCK_SIZE"
      root_mode=$MODEHEX; root_mtime=$MTIME; root_inode=$INODE
      marker=-
      case $exclusion_type in
        node_modules) [[ ${relative##*/} == node_modules ]] ;;
        python_venv)
          [[ ${relative##*/} == .venv || ${relative##*/} == venv ]]
          hash_file_stable "$target/pyvenv.cfg" "$source_device"; marker=$STABLE_HASH
          if metadata "$target/Scripts" && ((TYPE == 16384)) && [[ $DEVICE == "$source_device" ]]; then :; elif metadata "$target/bin" && ((TYPE == 16384)) && [[ $DEVICE == "$source_device" ]]; then :; else exit 95; fi
          ;;
        python_bytecode_cache) [[ ${relative##*/} == __pycache__ ]] ;;
        pytest_cache) [[ ${relative##*/} == .pytest_cache ]] ;;
        mypy_cache) [[ ${relative##*/} == .mypy_cache ]] ;;
        ruff_cache) [[ ${relative##*/} == .ruff_cache ]] ;;
        download_cache) [[ ${relative##*/} == .cache ]] ;;
        npm_cache) [[ ${relative##*/} == .npm ]] ;;
        pnpm_store) [[ ${relative##*/} == .pnpm-store ]] ;;
        external_backend_venv)
          [[ $relative == backend/.venv ]]
          hash_file_stable "$target/pyvenv.cfg" "$source_device"; marker=$STABLE_HASH
          if metadata "$target/Scripts" && ((TYPE == 16384)) && [[ $DEVICE == "$source_device" ]]; then :; elif metadata "$target/bin" && ((TYPE == 16384)) && [[ $DEVICE == "$source_device" ]]; then :; else exit 95; fi
          ;;
        *) exit 95 ;;
      esac
      metadata "$target"
      [[ "$MODEHEX $SIZE $MTIME $NLINK $DEVICE $INODE $BLOCKS $BLOCK_SIZE" == "$root_metadata" ]] || exit 94
      printf 'X\0%s\0%s\0%s\0%s\0%s\0%s\0' "$index" "$exclusion_type" "$root_mode" "$root_mtime" "$root_inode" "$marker"
      ((index+=1))
    done
    ;;
  oauth)
    (($# == 3)) || exit 91
    decode "$1"; source=$REPLY; shift
    decode "$1"; max_files=$REPLY; shift
    decode "$1"; max_bytes=$REPLY; shift
    safe_absolute "$source"
    [[ $max_files =~ ^[1-9][0-9]*$ && $max_bytes =~ ^[0-9]+$ ]]
	((max_files <= 1000000 && max_bytes <= 68719476736)) || exit 91
    metadata "$source"; ((TYPE == 16384)); source_device=$DEVICE
    printf 'WAO1\0'
	record_count=0 byte_count=0
    /usr/bin/find "$source" -xdev -print0 | while IFS= read -r -d '' entry; do
      metadata "$entry"
      [[ $DEVICE == "$source_device" ]] || exit 95
      if ((TYPE == 16384)); then continue; fi
      ((TYPE == 32768 && NLINK == 1)) || exit 93
	  ((record_count < max_files && SIZE <= max_bytes-byte_count)) || exit 97
	  record_count=$((record_count+1))
	  byte_count=$((byte_count+SIZE))
      relative=${entry#"$source"/}
      path_digest=$(printf '%s' "$relative" | /usr/bin/sha256sum); path_digest=${path_digest:0:64}
      hash_file_stable "$entry" "$source_device"; content_digest=$STABLE_HASH
      printf 'A\0%s\0%s\0%s\0%s\0' "$path_digest" "$SIZE" "$MTIME" "$content_digest"
    done
    ;;
  tar)
    (($# >= 2)) || exit 91
    decode "$1"; source=$REPLY; shift
    decode "$1"; expected_kind=$REPLY; shift
    safe_absolute "$source"
    [[ $expected_kind == file || $expected_kind == directory ]]
    parent=${source%/*}; base=${source##*/}; [[ -n $parent ]] || parent=/
    exclusions=()
    for encoded in "$@"; do decode "$encoded"; safe_relative "$REPLY"; exclusions+=("$REPLY"); done
    metadata "$source"
    if [[ $expected_kind == file ]]; then ((TYPE == 32768 && $# == 0)); else ((TYPE == 16384)); fi
    tar_args=(--format=posix --sparse --numeric-owner --no-acls --no-xattrs --no-selinux --one-file-system --no-wildcards --anchored)
    for relative in "${exclusions[@]}"; do tar_args+=(--exclude="$base/$relative"); done
    /usr/bin/tar "${tar_args[@]}" -C "$parent" -cf - -- "$base"
    ;;
  *) exit 91 ;;
esac
`

func newStaticScriptReader() io.Reader { return &scriptReader{payload: readOnlyRemoteScript} }

type scriptReader struct {
	payload string
	offset  int
}

func (reader *scriptReader) Read(buffer []byte) (int, error) {
	if reader.offset == len(reader.payload) {
		return 0, io.EOF
	}
	count := copy(buffer, reader.payload[reader.offset:])
	reader.offset += count
	return count, nil
}
