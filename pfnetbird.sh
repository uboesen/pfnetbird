#!/usr/bin/env bash
#
# pfnetbird.sh 1.0.0 - maintain NetBird on pfSense, the community way.
# Installs, updates or uninstalls NetBird on a pfSense firewall over SSH.
#
# Source:  https://github.com/uboesen/pfnetbird
# License: MIT, Copyright (c) 2026 Ulrik Boesen
# See README for usage, requirements and credits.
#
# Differs from pfnetbird.ps1 on purpose: --ascii, and ACB/Log rows (Safety).

# SC2317 (unreachable command) is off for the whole file: every menu action is started through
# run_action "$@" (a function name passed as an argument), which shellcheck cannot follow.
# shellcheck disable=SC2317
set -Eeuo pipefail

if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 2) )); then
  printf 'ERROR: pfnetbird needs bash 4.2 or newer (this is bash %s).\n' "$BASH_VERSION" >&2
  exit 2
fi

SCRIPT_VERSION='1.0.0'
REPO_API='https://api.github.com/repos/netbirdio/pfsense-netbird'
URL_PREFIX='https://github.com/netbirdio/pfsense-netbird/releases/download/'
REMOTE_DIR='/tmp/pfnetbird'
CONFIG_XML='/cf/conf/config.xml'
IDENTITY_FILE='/var/db/netbird/config.json'
MIN_FREEBSD=15
# Auto-update (cron on the firewall). The cron command is constant on purpose (install_cron_job matches by it).
AUTO_DIR='/root/pfnetbird'
AUTO_RUNNER="$AUTO_DIR/pfnetbird-auto.php"
AUTO_CMD="/usr/bin/nice -n20 /usr/local/bin/php -f $AUTO_RUNNER"
AUTO_LOCK='/tmp/pfnetbird-auto.lock'
AUTO_BUSY='/tmp/pfnetbird-client.busy'
AUTO_DEFAULT_TIME='03:30'   # default (clear of rc.periodic: 03:01 daily, 04:15 Sat, 05:30 1st)

# Options
HOST_GIVEN=0      # --host was given
HOST_TWICE=0      # --host was given more than once (checked in check_host_arg)
HOST_ARG=''       # --host [user@]host: the host part; connect straight away (cleared once used)
HOST_USER=''      # the user@ part of --host ('' = ask)
KEY_GIVEN=0
KEY_FILE=''       # --key: private key (or .pub) path on the client ('' = plain ssh login)
KEY_NAME=''       # basename of KEY_FILE; the only part shown or logged

# Run-wide state. The ssh session is the coproc SSH (SSH[0] = read, SSH[1] = write).
SESSION_PID=''
TOK=''
SEQ=0
DOWNLOADED=0
CTX_BACKUP=''
CTX_IDENTITY=''
TMP_FILE=''
R_OUT=()
R_CODE=0
REMOTE_QUIET=0   # 1 = remote output is never logged, not even on error
ACB_CODE=''      # new | legacy | '' (unknown); read by acb_preflight
ACB_OK=0
ACB_TXT=''
ACB_DONE=0
ACB_PENDING=0
BACKUP_DONE=0
BACKUP_SKIPPED=0 # 1 when the user chose Skip (no backup) in the last take_backup
BACKUP_ENC=no
UN_ASSIGNED=0    # uninstall check: wt0 assigned as a pfSense interface
UN_IF=''
UN_DESC=''
UN_FW=0
UN_NAT=0
UN_ONAT=0
MENU_UN='none'   # menu number of "Uninstall NetBird", 'none' when hidden
MENU_AU='none'   # menu number of "Auto-update (cron)", 'none' when hidden
MENU_LOG=4       # menu number of "Logging"
# Auto-update state read by auto_read (STATE_VARS carries it from the refresh subshell).
AU_READ=0; AU_JOBS=0; AU_MIN=''; AU_HOUR=''; AU_MDAY=''; AU_MONTH=''; AU_WDAY=''; AU_EXACT=0
AU_RUNNER_SHA=''; AU_TZ=''; AU_SNAPS=0; AU_LAST_TIME=''; AU_LAST_RESULT=''; AU_LAST_DETAIL=''; AU_LAST_TO=''; AU_HASDIR=0
AU_RSTATE=''     # runner state: missing | current | other (set by auto_runner_state)

# Copies of the coproc fds (coproc fds are not inherited into ( ) subshells, these are).
SSH_W=''
SSH_R=''
SSH_ERR_FILE=''     # private temp copy of ssh's stderr during the login (removed by disconnect_remote)
# ACT numbers the menu actions: markers are __PFNB_<tok>_<ACT>_<SEQ>, because SEQ changes
# made inside an action subshell are lost.
ACT=0
ACT_RC=0
RC_OLDER=11      # action exit status: the Older release item was chosen (the list is read in the parent)
RC_NAV=10        # action exit status: only navigation happened (Back), nothing to read
IN_ACTION=0      # 1 inside a menu action subshell
SOFT_FAIL=0      # 1 while the login handshake runs (timeouts return instead of exit)
LOG_ON=1         # session log switch (default on)
LOG_FILE=''      # path of this connection's log; set in the parent, used from subshells too
LOG_WHY=''       # reason log_open last failed (the text in the parentheses of the warning)
LOG_QUIET=0      # 1: log_open does not print its warning (the Logging menu item reports the failure itself)
LOG_DAY=''       # yyyyMMdd of the connection start (fixed at login, used for the log file name)
LOG_MUTE=0       # 1 while a screen is drawn (it is summarised in one log line instead)
CONNECTED=0
CONN_RC=0
SESSION_RC=0
HOST_ERR=''
RESOLVE_ERR=''
GH_ERR=''
REL_LIMITED=0
OLDER_RC=0
OLD_N=0
OLD_TAGS=()
OLD_VERS=()
OLD_BLKS=()
IR_RESULT=''
LOGIN_OK=0
JOB_LOST=0
CONN_HOST=''
CONN_USER=''
STATE_FILE=''
STATE_STAGE=0    # 0 nothing read, 1 box, 2 NetBird state, 3 release info
# State read by a refresh (it runs in a subshell and hands these to the parent via STATE_FILE).
STATE_VARS=(BOX_VERSION BOX_EDITION BOX_ARCH BOX_ABI BOX_MAJOR BOX_HOST BOX_FQDN
  NB_INSTALLED NB_CLIENT NB_PKG NB_CLIENT_VER ACB_CODE ACB_OK ACB_TXT
  AU_READ AU_JOBS AU_MIN AU_HOUR AU_MDAY AU_MONTH AU_WDAY AU_EXACT AU_RUNNER_SHA AU_TZ AU_SNAPS
  AU_LAST_TIME AU_LAST_RESULT AU_LAST_DETAIL AU_LAST_TO AU_HASDIR
  REL_TAG REL_CL_NAME REL_CL_URL REL_CL_DIGEST REL_CL_VER REL_CL_VERCLEAN
  REL_UI_NAME REL_UI_URL REL_UI_DIGEST REL_UI_VER REL_UI_VERCLEAN)

# Input patterns (ERE). No leading '-' is possible in either.
RE_HOST='^(\[[0-9A-Fa-f.]*:[0-9A-Fa-f:.]*\](:[0-9]{1,5})?|[A-Za-z0-9][A-Za-z0-9._:-]*)$'
RE_USER='^[A-Za-z0-9._][A-Za-z0-9._-]*$'

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
if [[ -t 1 && -z ${NO_COLOR:-} ]]; then
  C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'; C_OFF=$'\033[0m'
else
  C_GREEN=''; C_YELLOW=''; C_RED=''; C_OFF=''
fi

# Terminal UI "1b" (frames), output layer.
#
# Glyphs are byte escapes (never $'\u...', that needs bash 4.2). Messages in this script may use
# them; ui_map turns them into ASCII on screen when ASCII mode is on, and log_line always does
# (the session log is ASCII). The map is 1:1 per glyph and is applied BEFORE measuring or padding:
#
#   Unicode  ASCII     Unicode  ASCII
#   ✓        +         │        |
#   ▲        !         ─        -
#   ✗        x         ┌ ├ └    +
#   ●        *         →        ->
#   ·        /         ›        >
#   …        ...       —        -
#   spinner ⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏  ->  - \ | /   (own frame set, not part of ui_map)
#
# Mode: --ascii > PFNETBIRD_ASCII=1 > auto (see ui_init). Width is fixed at 78 columns.
# Colour is only on a status glyph and its status word; NO_COLOR or a non-TTY keeps the glyphs.
# Measuring uses ${#} (display characters, not bytes); padding is printf '%*s' of spaces only,
# never %-Ns on text that may hold glyphs. Helpers return through printf -v (no forks).
U_OK=$'\xe2\x9c\x93'; U_WARN=$'\xe2\x96\xb2'; U_ERR=$'\xe2\x9c\x97'; U_DOT=$'\xe2\x97\x8f'
U_MID=$'\xc2\xb7'; U_ELL=$'\xe2\x80\xa6'; U_EM=$'\xe2\x80\x94'; U_V=$'\xe2\x94\x82'
U_H=$'\xe2\x94\x80'; U_TL=$'\xe2\x94\x8c'; U_TJ=$'\xe2\x94\x9c'; U_BL=$'\xe2\x94\x94'
U_ARR=$'\xe2\x86\x92'; U_GT=$'\xe2\x80\xba'
# The same map as sed expressions for the session log (always ASCII, byte-exact).
LOG_SED=(-e "s#$U_OK#+#g" -e "s#$U_WARN#!#g" -e "s#$U_ERR#x#g" -e "s#$U_DOT#*#g"
  -e "s#$U_MID#/#g" -e "s#$U_ELL#...#g" -e "s#$U_EM#-#g" -e "s#$U_V#|#g" -e "s#$U_H#-#g"
  -e "s#$U_TL#+#g" -e "s#$U_TJ#+#g" -e "s#$U_BL#+#g" -e "s#$U_ARR#->#g" -e "s#$U_GT#>#g")

UI_W=78            # fixed frame width
UI_ASCII=1         # 1 = ASCII glyphs (safe default until ui_init decides)
UI_BYTES=0         # 1 = this shell counts bytes (no usable UTF-8 locale): sanitise to printable ASCII
ASCII_FLAG=0       # --ascii
UI_FRAME=0         # 1 while a frame is open
UI_STEP=0          # 1 while a step is open: info/warn/fail are buffered (set by the step code)
UI_NOTE_K=(); UI_NOTE_T=()   # buffered messages of the open step (kind, text)
UI_AFTER=()        # lines printed right after the frame closes (for example `netbird status -d`)
UI_KVW=13          # label column of ui_kv
UI_TTY=0           # 1 = stdout is a terminal and TERM is not dumb: the spinner may draw and the screen is cleared
UI_LEAD=''         # the frame prefix while a frame is open, else '' (for read -p prompts)
UI_SN=''; UI_SD=''; UI_ST0=0   # open step: name, running detail, start (SECONDS)
UI_SPID=''         # pid of the spinner ticker ('' = none)
UI_TOTAL=0         # sum of the finished step times of this action
UI_FAILT=''        # closing text if the action dies now (set per stage with ui_stage)
UI_SPIN=('-' '\' '|' '/')   # spinner frames (ui_init sets the braille set in Unicode mode)
U_SPIN=($'\xe2\xa0\x8b' $'\xe2\xa0\x99' $'\xe2\xa0\xb9' $'\xe2\xa0\xb8' $'\xe2\xa0\xbc'
  $'\xe2\xa0\xb4' $'\xe2\xa0\xa6' $'\xe2\xa0\xa7' $'\xe2\xa0\x87' $'\xe2\xa0\x8f')
# Colour markers, see ui_c. Control bytes \002-\005 only: never \001 (bash CTLESC, pattern
# substitution is buggy with it in bash 4.1-4.3) and never \177 (CTLNUL).
UI_MG=$'\002'; UI_MY=$'\003'; UI_MR=$'\004'; UI_ME=$'\005'
UI_MK=$UI_MG$UI_MY$UI_MR$UI_ME
G_OK='+'; G_WARN='!'; G_ERR='x'; G_DOT='*'; G_ELL='...'; G_V='|'; G_H='-'; G_TL='+'; G_TJ='+'; G_BL='+'
UI_PFX='|  '       # prefix of a frame line (glyph, so ui_init sets it again)

# Picks the glyph set once, before anything is drawn. Unicode only when the terminal can show it:
# not --ascii, not PFNETBIRD_ASCII=1, not TERM=dumb/linux, the locale charmap is UTF-8 (without
# `locale`: LC_ALL > LC_CTYPE > LANG) and this shell really counts a glyph as ONE character (an
# ungenerated xx.UTF-8 locale makes bash count bytes).
ui_init() {
  local cm='' probe=$U_OK
  UI_ASCII=0
  UI_BYTES=0
  if (( ${#probe} != 1 )); then UI_BYTES=1; fi
  if (( ASCII_FLAG )) || [[ ${PFNETBIRD_ASCII:-} == 1 ]]; then
    UI_ASCII=1
  else
    case ${TERM:-} in dumb|linux) UI_ASCII=1 ;; esac
    if (( ! UI_ASCII )); then
      if command -v locale >/dev/null 2>&1; then cm=$(locale charmap 2>/dev/null) || cm=''; fi
      if [[ -z $cm ]]; then cm=${LC_ALL:-${LC_CTYPE:-${LANG:-}}}; fi
      cm=${cm,,}
      if [[ $cm != *utf-8* && $cm != *utf8* ]]; then UI_ASCII=1; fi
    fi
  fi
  if (( UI_BYTES )); then UI_ASCII=1; fi
  if (( UI_ASCII )); then
    G_OK='+'; G_WARN='!'; G_ERR='x'; G_DOT='*'; G_ELL='...'
    G_V='|'; G_H='-'; G_TL='+'; G_TJ='+'; G_BL='+'
  else
    G_OK=$U_OK; G_WARN=$U_WARN; G_ERR=$U_ERR; G_DOT=$U_DOT; G_ELL=$U_ELL
    G_V=$U_V; G_H=$U_H; G_TL=$U_TL; G_TJ=$U_TJ; G_BL=$U_BL
  fi
  UI_PFX="$G_V  "
  UI_TTY=0
  if [[ -t 1 && ${TERM:-} != dumb ]]; then UI_TTY=1; fi
  if (( UI_ASCII )); then UI_SPIN=('-' '\' '|' '/'); else UI_SPIN=("${U_SPIN[@]}"); fi
  return 0
}

# ui_map <var> <text>: text with the glyphs of the map above (ASCII mode) or unchanged (Unicode).
ui_map() {
  local _ms=$2
  if (( UI_ASCII )); then
    _ms=${_ms//"$U_OK"/+};   _ms=${_ms//"$U_WARN"/!}; _ms=${_ms//"$U_ERR"/x};  _ms=${_ms//"$U_DOT"/*}
    _ms=${_ms//"$U_MID"/"/"}; _ms=${_ms//"$U_ELL"/...}; _ms=${_ms//"$U_EM"/-}; _ms=${_ms//"$U_V"/|}
    _ms=${_ms//"$U_H"/-};    _ms=${_ms//"$U_TL"/+};  _ms=${_ms//"$U_TJ"/+};  _ms=${_ms//"$U_BL"/+}
    _ms=${_ms//"$U_ARR"/->}; _ms=${_ms//"$U_GT"/>}
  fi
  printf -v "$1" '%s' "$_ms"
}

# ui_sanitize <var> <text>: one line, no control characters (that includes the colour markers, so a
# remote string can never inject colour or terminal escapes: descriptions, host names, result details). Byte-counting mode keeps printable ASCII only.
ui_sanitize() {
  local _zs=${2//$'\t'/ }
  if (( UI_BYTES )); then _zs=${_zs//[![:print:]]/}; else _zs=${_zs//[[:cntrl:]]/}; fi
  printf -v "$1" '%s' "$_zs"
}

# ui_clean <var> <text>: ui_sanitize for text with several lines; the newlines survive.
ui_clean() {
  local _cv=$1 _cl _co='' _cn=0
  while IFS= read -r _cl; do
    ui_sanitize _cl "$_cl"
    if (( _cn )); then _co+=$'\n'; fi
    _co+=$_cl
    _cn=$(( _cn + 1 ))
  done <<<"$2"
  printf -v "$_cv" '%s' "$_co"
}

# Colour markers. ui_c wraps TEXT in a marker pair; ui_len / ui_pad / ui_kv / ui_menu2 measure
# without them and ui_paint turns them into real colour (or nothing) only when printing.
# Remote strings must go through ui_sanitize BEFORE they are built into a marked string.
# kind: ok (green) | warn (yellow) | fail (red) | anything else = plain.
ui_c() {
  local _cm=''
  case $2 in
    ok)   _cm=$UI_MG ;;
    warn) _cm=$UI_MY ;;
    fail) _cm=$UI_MR ;;
  esac
  if [[ -n $_cm ]]; then printf -v "$1" '%s' "$_cm$3$UI_ME"; else printf -v "$1" '%s' "$3"; fi
}

ui_paint() {
  local _ps=$2
  _ps=${_ps//"$UI_MG"/$C_GREEN}; _ps=${_ps//"$UI_MY"/$C_YELLOW}
  _ps=${_ps//"$UI_MR"/$C_RED};   _ps=${_ps//"$UI_ME"/$C_OFF}
  printf -v "$1" '%s' "$_ps"
}

# ui_len <var> <text>: display length (characters, colour markers not counted).
ui_len() {
  local _ls=$2
  _ls=${_ls//[$UI_MK]/}
  printf -v "$1" '%d' "${#_ls}"
}

# ui_pad <var> <text> <width> [r]: pad with spaces to <width> display columns (r = right-align).
ui_pad() {
  local _pt=$2 _pw=$3 _pc _pp=''
  ui_len _pc "$_pt"
  if (( _pc < _pw )); then printf -v _pp '%*s' $(( _pw - _pc )) ''; fi
  if [[ ${4:-} == r ]]; then _pt=$_pp$_pt; else _pt=$_pt$_pp; fi
  printf -v "$1" '%s' "$_pt"
}

# ui_shorten <var> <text> <max>: middle ellipsis when longer than <max>. Plain text only (no markers).
ui_shorten() {
  local _st=$2 _sm=$3 _sb _sl _sr
  if (( _sm < 1 )); then _sm=1; fi
  if (( ${#_st} > _sm )); then
    _sb=$(( _sm - ${#G_ELL} ))
    if (( _sb < 2 )); then
      _st=${G_ELL:0:_sm}
    else
      _sl=$(( (_sb + 1) / 2 ))
      _sr=$(( _sb - _sl ))
      _st=${_st:0:_sl}$G_ELL${_st: -_sr}
    fi
  fi
  printf -v "$1" '%s' "$_st"
}

# ui_wrap <var> <text> [hang] [first-prefix] [next-prefix]: wraps to UI_W columns including the
# prefix (default the frame prefix; both prefixes must be equally wide). Each input line keeps its
# leading indent, continuation lines get <hang> extra spaces ("auto": the width of a list marker
# such as `1. ` or `- ` at the start of the line, else 0). Words longer than a line are broken.
# Lines are sanitised; text already in the glyph set of the mode (run ui_map first). Result: the
# finished lines joined with newlines (no trailing newline).
ui_wrap() {
  local _v=$1 _text=$2 _hang=${3:-0} _p1=${4-$UI_PFX} _pn=${5-${4-$UI_PFX}}
  local _avail=$(( UI_W - ${#_p1} ))
  local _line _lead _rest _cind _cur _have _w _room _sep _b _p _n=0 _out='' _pad _h
  local -a _bl=() _words=() _tok=()
  if [[ -z $_text ]]; then printf -v "$_v" '%s' ''; return 0; fi
  while IFS= read -r _line; do
    ui_sanitize _line "$_line"
    _lead=${_line%%[! ]*}
    _rest=${_line#"$_lead"}
    if [[ -z $_rest ]]; then
      _bl+=('')
    elif (( ${#_line} <= _avail )); then
      _bl+=("$_line")
    else
      _h=$_hang
      if [[ $_hang == auto ]]; then
        _h=0
        if [[ $_rest =~ ^([0-9]+[.\)]|[a-z][.\)]|[-*])\ + ]]; then _h=${#BASH_REMATCH[0]}; fi
      fi
      printf -v _pad '%*s' "$_h" ''
      _cind=$_lead$_pad
      _cur=$_lead
      _have=0
      # A number and its unit ("120 s", "30 s") stay together: they are merged into one token.
      read -r -a _tok <<<"$_rest"
      _words=()
      for _w in "${_tok[@]}"; do
        if (( ${#_words[@]} )) && [[ ${_words[${#_words[@]}-1]} =~ ^\(?[0-9]+([.,][0-9]+)?$ ]] \
           && [[ $_w =~ ^(s|ms|min|h|d|KB|MB|GB|TB|kB)[\).,\;:]*$ ]]; then
          _words[${#_words[@]}-1]+=" $_w"
        else
          _words+=("$_w")
        fi
      done
      for _w in "${_words[@]}"; do
        if [[ $_w == http://* || $_w == https://* || $_w =~ ^[0-9a-fA-F]{64}$ ]] && (( ${#_cur} + _have + ${#_w} > _avail )); then
          # A URL or a hash is never broken: it gets a line of its own and may run past the width.
          if (( _have )); then _bl+=("$_cur"); fi
          _bl+=("$_cind$_w")
          _cur=$_cind
          _have=0
          continue
        fi
        while :; do
          if (( _have )); then _sep=' '; else _sep=''; fi
          if (( ${#_cur} + ${#_sep} + ${#_w} <= _avail )); then
            _cur+=$_sep$_w
            _have=1
            break
          fi
          if (( _have )); then
            if (( ${#_w} > _avail - ${#_cind} )); then
              # Unbreakable word (a path): start it on this line, so a leading glyph is not left alone.
              _room=$(( _avail - ${#_cur} - 1 ))
              if (( _room >= 1 )); then
                _bl+=("$_cur ${_w:0:_room}")
                _w=${_w:_room}
                _cur=$_cind
                _have=0
                if [[ -z $_w ]]; then break; fi
                continue
              fi
            fi
            _bl+=("$_cur")
            _cur=$_cind
            _have=0
            continue
          fi
          _room=$(( _avail - ${#_cur} ))
          if (( _room < 1 )); then _room=1; fi
          _bl+=("$_cur${_w:0:_room}")
          _w=${_w:_room}
          _cur=$_cind
          if [[ -z $_w ]]; then break; fi
        done
      done
      if (( _have )); then _bl+=("$_cur"); fi
    fi
  done <<<"$_text"
  for _b in ${_bl[@]+"${_bl[@]}"}; do
    if (( _n )); then _p=$_pn; else _p=$_p1; fi
    if [[ -z $_b ]]; then _p=${_p%"${_p##*[! ]}"}; fi
    if (( _n )); then _out+=$'\n'; fi
    _out+=$_p$_b
    _n=$(( _n + 1 ))
  done
  printf -v "$_v" '%s' "$_out"
}

# Frames: open on the right (no right border). One frame per screen or action.
# Rules for callers: never call die / die_session inside $(...) while a frame is open (the abort
# would be printed into the capture); never call ui_blank right before ui_section (it adds its own
# blank line); every action subshell starts with the frame state reset (see run_action).
# ui_open <title> [right]: `┌─ title ─────── right`, filled with ─ to 78 columns. Too long: the
# right part is shortened in the middle (drop `(fqdn)` yourself first to keep the user@host).
ui_open() {
  local _t _r='' _fill _room
  if (( UI_FRAME )); then ui_abort; fi
  ui_spin_stop
  UI_STEP=0; UI_NOTE_K=(); UI_NOTE_T=(); UI_FAILT=''; UI_TOTAL=0
  ui_map _t "$1"; ui_sanitize _t "$_t"
  if (( $# > 1 )); then ui_map _r "$2"; ui_sanitize _r "$_r"; fi
  UI_FRAME=1
  UI_LEAD=$UI_PFX
  if [[ -z $_r ]]; then
    ui_shorten _t "$_t" $(( UI_W - 3 ))
    printf '%s%s %s\n' "$G_TL" "$G_H" "$_t"
    return 0
  fi
  _room=$(( UI_W - 8 ))                       # "┌─ " + " " + 3 fill + " "
  if (( ${#_t} + ${#_r} > _room )); then
    if (( _room - ${#_t} >= 12 )); then
      ui_shorten _r "$_r" $(( _room - ${#_t} ))
    else
      ui_shorten _t "$_t" 28
      ui_shorten _r "$_r" $(( _room - ${#_t} ))
    fi
  fi
  printf -v _fill '%*s' $(( _room - ${#_t} - ${#_r} + 3 )) ''
  _fill=${_fill// /$G_H}
  printf '%s%s %s %s %s\n' "$G_TL" "$G_H" "$_t" "$_fill" "$_r"
}

# A blank frame line.
ui_blank() { printf '%s\n' "$G_V"; }

# ui_section <name>: a blank frame line, then `├─ name`.
ui_section() {
  local _n
  ui_map _n "$1"; ui_sanitize _n "$_n"
  ui_shorten _n "$_n" $(( UI_W - 3 ))
  printf '%s\n%s%s %s\n' "$G_V" "$G_TJ" "$G_H" "$_n"
}

# ui_close [kind [text]]: `└─` or `└─ text`; kind ok|warn|fail puts a coloured status glyph in front
# of the text. Then prints what ui_after collected. Does nothing when no frame is open.
ui_close() {
  local _k=${1:-} _t=${2:-} _g='' _c='' _s _i
  local _p1="$G_BL$G_H " _pn='   '
  if (( ! UI_FRAME )); then return 0; fi
  ui_unstep
  UI_FRAME=0
  UI_LEAD=''
  UI_FAILT=''
  case $_k in
    ok)   _g=$G_OK;   _c=$C_GREEN ;;
    warn) _g=$G_WARN; _c=$C_YELLOW ;;
    fail) _g=$G_ERR;  _c=$C_RED ;;
  esac
  if [[ -z $_t ]]; then
    printf '%s%s\n' "$G_BL" "$G_H"
  else
    ui_map _t "$_t"
    if [[ -n $_g ]]; then _t="$_g $_t"; ui_wrap _s "$_t" 2 "$_p1" "$_pn"; else ui_wrap _s "$_t" 0 "$_p1" "$_pn"; fi
    if [[ -n $_g && -n $_c ]]; then _s=${_s/"$_p1$_g"/"$_p1$_c$_g$C_OFF"}; fi
    printf '%s\n' "$_s"
  fi
  for (( _i = 0; _i < ${#UI_AFTER[@]}; _i++ )); do printf '%s\n' "${UI_AFTER[_i]}"; done
  UI_AFTER=()
  return 0
}

# ui_after <line>: printed right after the frame closes (`netbird status -d` is shown there, never
# logged). Printed at once when no frame is open.
ui_after() {
  local _al
  ui_clean _al "$1"
  if (( UI_FRAME )); then UI_AFTER+=("$_al"); else printf '%s\n' "$_al"; fi
}

# Step buffering hook (the step code sets UI_STEP=1 while a step is open): the messages are kept
# and ui_unstep prints them in order. die / on_err / die_session call it before they print.
ui_unstep() {
  if (( UI_STEP )); then ui_step_end fail ''; fi
  ui_spin_stop
  return 0
}

# Closes the open step and frame on the way out (die, on_err, die_session, cleanup).
ui_abort() {
  ui_unstep
  if (( UI_FRAME )); then
    if [[ -n $UI_FAILT ]]; then ui_close fail "$UI_FAILT"; else ui_close; fi
  fi
  return 0
}

# ui_begin <title>: the frame of an action. Opens one; inside an already open frame (the auto-update
# menu) it only starts a new section.
ui_begin() {
  if (( UI_FRAME )); then ui_section "$1"; else ui_open "$1"; ui_blank; fi
  return 0
}

# ui_plan [title]: the `├─ Plan (nothing is changed)` section of a dry run. Opens a frame with
# <title> when none is open (the menu dry runs).
ui_plan() {
  if (( ! UI_FRAME )); then ui_open "${1:-Dry run}"; fi
  ui_section 'Plan (nothing is changed)'
}

# ui_stage <text>: what to say in the red closing line if the action dies from here on.
ui_stage() { UI_FAILT=$1; }

# --- Steps ---------------------------------------------------------------------------------
# `│  ✓ Name        detail                                            12s`
# ui_step_begin <name> [running detail] opens a step: while it is open info / ok / warn / fail print
# nothing (the log is written as always) and, on a terminal, a spinner ticker shows the elapsed
# seconds on the same line. ui_step_end <ok|warn|fail> <detail> [seconds] prints the one final line;
# a buffered warn / fail turns the glyph into ▲ / ✗ and its text is printed under the line.
# Never open a step around a prompt (read), and end it before ui_close.
ui_step_begin() {
  ui_spin_stop
  UI_STEP=1; UI_SN=$1; UI_SD=${2:-}; UI_ST0=$SECONDS
  UI_NOTE_K=(); UI_NOTE_T=()
  if (( UI_TTY && UI_FRAME )); then ui_spin_start; fi
  return 0
}

ui_step_end() {
  local _k=$1 _d=${2:-} _s _i _n=${#UI_NOTE_K[@]} _w=$1
  if (( ! UI_STEP )); then return 0; fi
  ui_spin_stop
  _s=${3:-$(( SECONDS - UI_ST0 ))}
  UI_STEP=0
  UI_TOTAL=$(( UI_TOTAL + _s ))
  for (( _i = 0; _i < _n; _i++ )); do
    case ${UI_NOTE_K[_i]} in
      fail) _w=fail ;;
      warn) if [[ $_w == ok ]]; then _w=warn; fi ;;
    esac
  done
  ui_step_line "$_w" "$UI_SN" "$_d" "$_s"
  for (( _i = 0; _i < _n; _i++ )); do ui_step_note "${UI_NOTE_T[_i]}"; done
  UI_NOTE_K=(); UI_NOTE_T=()
  return 0
}

# ui_step_line <ok|warn|fail> <name> <detail> <seconds>: the finished step line (no state change).
# The name column is 12 wide, the time sits right-aligned at column 78, a long detail wraps under
# the detail column.
ui_step_line() {
  local _k=$1 _n=$2 _d=$3 _s=$4 _g _gm _nm _t='' _tl=0 _av _sp _r _l _x _hang _ln _i
  case $_k in
    ok|warn|fail) case $_k in ok) _g=$G_OK ;; warn) _g=$G_WARN ;; *) _g=$G_ERR ;; esac; ui_c _gm "$_k" "$_g" ;;
    *) _gm=' ' ;;
  esac
  ui_map _n "$_n"; ui_sanitize _n "$_n"
  ui_map _d "$_d"; ui_sanitize _d "$_d"
  if (( _s > 0 )); then _t="${_s}s"; _tl=$(( ${#_t} + 1 )); fi
  ui_pad _nm "$_n" 12
  if (( ${#_n} >= 12 )); then _nm+=' '; fi
  _hang=$(( 2 + ${#_nm} ))
  _av=$(( UI_W - ${#UI_PFX} - _hang - _tl ))
  printf -v _sp '%*s' $(( UI_W - _av )) ''
  ui_wrap _r "$_d" 0 "$_sp" "$_sp"
  printf -v _x '%*s' "$_hang" ''
  local -a _ls=()
  while IFS= read -r _l; do _ls+=("${_l:${#_sp}}"); done <<<"$_r"
  for (( _i = 0; _i < ${#_ls[@]}; _i++ )); do
    if (( _i == 0 )); then _ln=$UI_PFX$_gm' '$_nm${_ls[_i]}; else _ln=$UI_PFX$_x${_ls[_i]}; fi
    if (( _i == ${#_ls[@]} - 1 )) && [[ -n $_t ]]; then
      ui_pad _ln "$_ln" $(( UI_W - ${#_t} )); _ln+=$_t     # the time sits on the last line
    else
      _ln=${_ln%"${_ln##*[! ]}"}                           # no trailing spaces
    fi
    ui_paint _ln "$_ln"
    printf '%s\n' "$_ln"
  done
}

# The text of a buffered message, printed under its step line (wrapped, no glyph).
ui_step_note() {
  local _t _pf _s
  if [[ -z $1 ]]; then return 0; fi
  ui_map _t "$1"
  printf -v _pf '%s%*s' "$UI_PFX" 14 ''
  ui_wrap _s "$_t" auto "$_pf" "$_pf"
  printf '%s\n' "$_s"
}

# The spinner: a background ticker that redraws one line with \r every 0.2 s. It is owned by the
# shell that started it (the pid is taken BEFORE the &), closes its copies of the ssh descriptors,
# runs without ERR/EXIT traps and ends by itself when the owner is gone (Ctrl-C, die).
ui_spin_loop() {
  local owner=$1 t0=$2 post=$3 i=0 n=${#UI_SPIN[@]} el t pad
  trap - ERR EXIT
  set +e
  if [[ -n $SSH_W ]]; then exec {SSH_W}>&-; fi
  if [[ -n $SSH_R ]]; then exec {SSH_R}<&-; fi
  exec </dev/null
  while kill -0 "$owner" 2>/dev/null; do
    el=$(( SECONDS - t0 ))
    t="${el}s"
    pad=$(( UI_W - ${#UI_PFX} - 2 - ${#post} - ${#t} ))
    if (( pad < 1 )); then pad=1; fi
    printf '\r%s%s %s%*s%s\033[K' "$UI_PFX" "${UI_SPIN[i]}" "$post" "$pad" '' "$t"
    i=$(( (i + 1) % n ))
    sleep 0.2
  done
  exit 0
}

ui_spin_start() {
  local owner=$BASHPID post nm d
  ui_map nm "$UI_SN"; ui_sanitize nm "$nm"
  ui_pad nm "$nm" 12
  if (( ${#UI_SN} >= 12 )); then nm+=' '; fi
  ui_map d "$UI_SD"; ui_sanitize d "$d"
  ui_shorten d "$d" $(( UI_W - ${#UI_PFX} - 2 - ${#nm} - 7 ))
  post=$nm$d
  ui_spin_loop "$owner" "$SECONDS" "$post" &
  UI_SPID=$!
  return 0
}

# Stops the ticker and wipes its line. Safe to call at any time, from any path.
ui_spin_stop() {
  if [[ -n $UI_SPID ]]; then
    kill "$UI_SPID" 2>/dev/null || true
    wait "$UI_SPID" 2>/dev/null || true
    UI_SPID=''
    printf '\r\033[K'
  fi
  return 0
}

# ui_kv <label> <value> [path]: `│  Label        value`. The value may hold ui_c colour markers. A value
# wider than UI_W - 3 - UI_KVW (62) wraps by words under the value column and keeps its colour;
# with `path` (a path or URL) it is middle-shortened instead. Callers shorten long plain parts
# BEFORE colouring. A label of 13 or more columns still gets one separator space.
ui_kv() {
  local _kl _kv _kn _kw _ka _kp=${3:-} _kx _kw1 _kcur _kcl _kopen _kc _ki _kj _kline _kfirst=1
  local -a _kwords=() _klines=()
  ui_map _kl "$1"; ui_map _kv "$2"
  ui_len _kn "$_kl"
  _kw=$UI_KVW
  if (( _kn >= _kw )); then _kw=$(( _kn + 1 )); fi     # always a separator space
  ui_pad _kl "$_kl" "$_kw"
  _ka=$(( UI_W - ${#UI_PFX} - _kw ))
  ui_len _kn "$_kv"
  _klines=("$_kv")
  if (( _kn > _ka )); then
    _kx=${_kv//[$UI_MK]/}
    read -r -a _kwords <<<"$_kv"
    _kw1=0
    for _kc in ${_kwords[@]+"${_kwords[@]}"}; do
      ui_len _ki "$_kc"
      if (( _ki > _kw1 )); then _kw1=$_ki; fi
    done
    if [[ $_kp == path ]] || (( _kw1 > _ka )); then
      # A path or URL (or an unbreakable word): middle-shorten, plain.
      ui_shorten _kv "$_kx" "$_ka"
      _klines=("$_kv")
    else
      # Words wrap under the value column; a colour that spans a line break is closed and reopened.
      _klines=(); _kcur=''; _kcl=0; _kopen=''
      for _kc in "${_kwords[@]}"; do
        ui_len _ki "$_kc"
        if (( _kcl > 0 && _kcl + 1 + _ki > _ka )); then
          if [[ -n $_kopen ]]; then _kcur+=$UI_ME; fi
          _klines+=("$_kcur")
          _kcur=$_kopen$_kc
          _kcl=$_ki
        elif (( _kcl > 0 )); then
          _kcur+=" $_kc"
          _kcl=$(( _kcl + 1 + _ki ))
        else
          _kcur=$_kc
          _kcl=$_ki
        fi
        for (( _kj = 0; _kj < ${#_kc}; _kj++ )); do
          case ${_kc:_kj:1} in
            "$UI_MG"|"$UI_MY"|"$UI_MR") _kopen=${_kc:_kj:1} ;;
            "$UI_ME") _kopen='' ;;
          esac
        done
      done
      _klines+=("$_kcur")
    fi
  fi
  for _kv in "${_klines[@]}"; do
    if (( _kfirst )); then
      _kline=$UI_PFX$_kl$_kv
      _kfirst=0
    else
      printf -v _kline '%s%*s%s' "$UI_PFX" "$_kw" '' "$_kv"
    fi
    ui_paint _kline "$_kline"
    printf '%s\n' "$_kline"
  done
}

# ui_menu1 <item>...: one-column menu, one item per line in the frame (the connected screen; same
# look as the submenus). An item longer than the frame is shortened.
ui_menu1() {
  local _a
  for _a in "$@"; do
    ui_map _a "$_a"; ui_sanitize _a "$_a"
    ui_shorten _a "$_a" $(( UI_W - ${#UI_PFX} ))
    printf '%s%s\n' "$UI_PFX" "$_a"
  done
}

# ui_menu2 <item>... <zero-item>: two-column menu. Items 1-3 on the left, 4 and up on the right,
# the LAST argument (the 0 item) on its own row below. The left column is at least 30 wide.
ui_menu2() {
  local -a _L=() _R=()
  local _n=$# _i=0 _a _lw=30 _rw _rows _x _l _r _z=''
  for _a in "$@"; do
    _i=$(( _i + 1 ))
    ui_map _a "$_a"; ui_sanitize _a "$_a"
    if (( _i == _n )); then
      _z=$_a
    elif (( _i <= 3 )); then
      _L+=("$_a")
      if (( ${#_a} + 2 > _lw )); then _lw=$(( ${#_a} + 2 )); fi
    else
      _R+=("$_a")
    fi
  done
  if (( _lw > 40 )); then
    _lw=40
    for (( _x = 0; _x < ${#_L[@]}; _x++ )); do ui_shorten "_L[$_x]" "${_L[_x]}" $(( _lw - 2 )); done
  fi
  _rw=$(( UI_W - ${#UI_PFX} - _lw ))
  for (( _x = 0; _x < ${#_R[@]}; _x++ )); do ui_shorten "_R[$_x]" "${_R[_x]}" "$_rw"; done
  _rows=${#_L[@]}
  if (( ${#_R[@]} > _rows )); then _rows=${#_R[@]}; fi
  for (( _x = 0; _x < _rows; _x++ )); do
    _l=${_L[_x]:-}
    _r=${_R[_x]:-}
    if [[ -n $_r ]]; then
      ui_pad _l "$_l" "$_lw"
      printf '%s%s%s\n' "$UI_PFX" "$_l" "$_r"
    else
      printf '%s%s\n' "$UI_PFX" "$_l"
    fi
  done
  if [[ -n $_z ]]; then printf '%s%s\n' "$UI_PFX" "$_z"; fi
  return 0
}

# ui_prompt <var> <text>: reads one line into <var> after printing <text> (with the frame prefix
# when a frame is open). Returns 1 on end of input (var empty); callers guard it with ||.
ui_prompt() {
  local _pv=$1 _pq _pa='' _prc=0
  ui_map _pq "$2"
  if (( UI_FRAME )); then _pq=$UI_PFX$_pq; fi
  read -r -p "$_pq " _pa || _prc=1
  printf -v "$_pv" '%s' "$_pa"
  return "$_prc"
}

# ui_say <kind> <text>: the body of info/ok/warn/fail. kind: info | ok | warn | fail. Inside a frame
# the text is wrapped with the `│  ` prefix and ok/warn/fail get a coloured ✓ ▲ ✗ in front (instead
# of the old WARNING: / ERROR: words); outside a frame it is one line as before, with the glyph.
# While a step is open (UI_STEP) the text is buffered for the step code. Screen only: the log is
# written by the callers.
ui_say() {
  local _k=$1 _t=$2 _g='' _c='' _s
  case $_k in
    ok)   _g=$G_OK;   _c=$C_GREEN ;;
    warn) _g=$G_WARN; _c=$C_YELLOW ;;
    fail) _g=$G_ERR;  _c=$C_RED ;;
  esac
  if (( UI_STEP )); then
    UI_NOTE_K+=("$_k"); UI_NOTE_T+=("$_t")
    return 0
  fi
  ui_map _t "$_t"
  if (( ! UI_FRAME )); then
    ui_clean _t "$_t"
    if [[ -n $_g ]]; then
      printf '%s%s%s %s\n' "$_c" "$_g" "$C_OFF" "$_t"
    else
      printf '%s\n' "$_t"
    fi
    return 0
  fi
  if [[ -z $_t && -z $_g ]]; then printf '%s\n' "$G_V"; return 0; fi    # info '' = blank frame line
  if [[ -n $_g ]]; then
    _t=${_t//$'\n'/$'\n  '}        # explicit newlines hang under the text
    if [[ -n $_t ]]; then ui_wrap _s "$_g $_t" 2; else ui_wrap _s "$_g" 0; fi
  else
    ui_wrap _s "$_t" auto
  fi
  if [[ -n $_g && -n $_c ]]; then _s=${_s/"$UI_PFX$_g"/"$UI_PFX$_c$_g$C_OFF"}; fi
  printf '%s\n' "$_s"
}

# ui_para <kind> <text>: like ui_say but for a long paragraph OUTSIDE a frame: wrapped to UI_W
# columns (a glyph message hangs under its text). Inside a frame it is ui_say.
ui_para() {
  local _k=$1 _t=$2 _g='' _c='' _s
  case $_k in
    ok)   _g=$G_OK;   _c=$C_GREEN ;;
    warn) _g=$G_WARN; _c=$C_YELLOW ;;
    fail) _g=$G_ERR;  _c=$C_RED ;;
  esac
  if (( UI_FRAME || UI_STEP )); then ui_say "$_k" "$_t"; return 0; fi
  ui_map _t "$_t"
  if [[ -n $_g ]]; then ui_wrap _s "$_g $_t" 2 '' ''; else ui_wrap _s "$_t" 0 '' ''; fi
  if [[ -n $_g && -n $_c ]]; then _s=${_s/"$_g"/"$_c$_g$C_OFF"}; fi
  printf '%s\n' "$_s"
}

info() { ui_say info "$1"; log_line "$1"; }
ok()   { ui_say ok "$1"; log_line "OK: $1"; }
warn() { ui_say warn "$1"; log_line "WARNING: $1"; }
fail() { ui_say fail "$1"; log_line "ERROR: $1"; }
# Long paragraphs (wrapped on screen, the log gets the text as one piece, as before).
info_w() { ui_para info "$1"; log_line "$1"; }
warn_w() { ui_para warn "$1"; log_line "WARNING: $1"; }
fail_w() { ui_para fail "$1"; log_line "ERROR: $1"; }

# Appends text to the session log, one timestamped line per text line, ANSI colours
# stripped and the UI glyphs mapped to ASCII (LC_ALL=C sed, byte-exact). No frame chrome, no
# step or spinner lines: the log gets the plain message. Does nothing when logging is off or no
# log exists. Never fails the script.
log_line() {
  local ts text
  if (( LOG_ON )) && (( ! LOG_MUTE )) && [[ -n $LOG_FILE ]]; then
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    text=$(printf '%s\n' "$1" | LC_ALL=C sed -e $'s/\033\\[[0-9;]*m//g' "${LOG_SED[@]}" -e "s/^/$ts /")
    { printf '%s\n' "$text" >>"$LOG_FILE"; } 2>/dev/null || true
  fi
  return 0
}

# Reason for a failed mkdir -p of the log folder ($1), decided here because the mkdir text differs by flavour
# (GNU: "File exists", uutils: "Already exists"): the folder exists but is not a directory -> "File exists";
# no write access to the nearest existing parent -> "Permission denied" (the PowerShell twin says the same);
# anything else keeps the mkdir text ($2).
log_dir_reason() {
  local d=$1
  if [[ -e $d || -L $d ]]; then
    if [[ ! -d $d ]]; then printf 'File exists'; return 0; fi
  else
    while [[ $d == */* && ! -e $d && ! -L $d ]]; do d=${d%/*}; d=${d:-/}; done
    if [[ -d $d && ! -w $d ]]; then printf 'Permission denied'; return 0; fi
  fi
  printf '%s' "${2##*: }"
}

# A failed log_open: remembers the reason in LOG_WHY and, unless LOG_QUIET, prints the warning.
log_open_fail() {
  LOG_WHY=$1
  if (( ! LOG_QUIET )); then warn "cannot create the session log ($1); continuing without it"; fi
}

# Opens this connection's log next to the backups: one file per firewall per day, appended to when
# it exists (one blank line, then the header). The day is the one fixed at login (LOG_DAY). Mode 0600
# only on a file this run created. Called right after the login.
log_open() {
  local host=$1 dir safe path created=0 appending=0 err
  if (( ! LOG_ON )); then return 0; fi
  LOG_WHY=''; LOG_QUIET=0
  if [[ ${2:-} == retry ]]; then LOG_QUIET=1; fi
  downloads_dir
  dir=$DL_DIR
  if ! err=$(mkdir -p "$dir" 2>&1); then log_open_fail "$(log_dir_reason "$dir" "$err")"; return 0; fi
  safe=${host//[^A-Za-z0-9._-]/_}
  if [[ -z $LOG_DAY ]]; then LOG_DAY=$(date +%Y%m%d); fi
  path="$dir/pfnetbird-$safe-$LOG_DAY.log"
  # Only a path that does not exist is created (noclobber: never truncates). An existing path is never opened
  # for writing before the regular-file check below (opening a FIFO for writing would block).
  if [[ ! -e $path && ! -L $path ]]; then
    if err=$( ( set -C; umask 077; : >"$path" ) 2>&1 ); then
      created=1
    elif [[ ! -e $path && ! -L $path ]]; then
      log_open_fail "${err##*: }"
      return 0
    fi   # else: made by another session a moment ago, append
  fi
  if (( created )); then
    chmod 600 "$path" 2>/dev/null || true
  else
    # Exists already: must be a regular file and writable, else no log. Nothing is written here.
    if [[ ! -f $path ]]; then
      log_open_fail "$path is not a file"
      return 0
    fi
    if [[ -s $path ]]; then appending=1; fi
    if ! err=$( ( : >>"$path" ) 2>&1 ); then
      log_open_fail "${err##*: }"
      return 0
    fi
  fi
  LOG_FILE=$path
  if (( appending )); then { printf '\n' >>"$path"; } 2>/dev/null || true; fi
  log_line "pfnetbird $SCRIPT_VERSION session log started"
}

# Closes the log and prints its path once.
log_close() {
  if [[ -n $LOG_FILE ]]; then
    printf 'Log saved: %s\n' "$LOG_FILE"
    LOG_FILE=''
  fi
  return 0
}

# Menu screens only: clear the terminal before a redraw (plain ANSI, no clear/tput). Not logged.
# Does nothing when stdout is not a terminal or TERM is dumb (UI_TTY; twin: Clear-UiScreen).
clear_screen() {
  if (( UI_TTY )); then printf '\033[H\033[2J'; fi
}

# Wait for Enter so action output can be read before the next redraw clears it. End of input
# counts as Enter. Not logged.
pause_menu() {
  local _k=''
  read -r -p 'Press Enter to return to the menu ' _k || printf '\n'
}

trim() {
  local v=$1
  v=${v#"${v%%[![:space:]]*}"}
  v=${v%"${v##*[![:space:]]}"}
  printf '%s' "$v"
}

print_context() {
  if [[ -n $CTX_BACKUP ]]; then info "Config backup (local): $CTX_BACKUP"; fi
  if [[ -n $CTX_IDENTITY ]]; then info "Identity snapshot (on the firewall): $CTX_IDENTITY"; fi
}

# Print the error and the paths worth knowing, then exit 2. The EXIT trap cleans up.
# An open step and frame are closed first (ui_abort), so the screen ends with a `└─` line.
die() {
  ui_unstep
  fail "$1"
  print_context
  ui_abort
  exit 2
}

on_err() {
  local line=$1 rc=$2
  trap - ERR
  set +e
  ui_unstep
  fail "internal error at line $line (exit status $rc)"
  print_context
  ui_abort
  exit 2
}

read_yes_no() {
  local ans='' q s
  ui_map q "$1: "
  if (( UI_FRAME )); then
    # Framed: earlier wrapped lines are printed, the last one becomes the read prompt.
    ui_wrap s "$q"
    if [[ $s == *$'\n'* ]]; then printf '%s\n' "${s%$'\n'*}"; fi
    q=${s##*$'\n'}
    if [[ $q != *' ' ]]; then q+=' '; fi
  else
    ui_clean q "$q"
  fi
  read -r -p "$q" ans || ans=''
  ans=$(trim "$ans")
  ans=${ans,,}
  log_line "prompt: $1 -> answer: ${ans:-(empty)}"
  [[ $ans == y || $ans == yes ]]
}

usage() {
  cat <<EOF
pfnetbird $SCRIPT_VERSION - maintain NetBird on pfSense, the community way

Usage: pfnetbird.sh [--host [user@]host] [--ascii] [--no-log] [--key <path>]

With no options, a start screen opens: 1) Connect to firewall, 2) Logging
(toggle), 0) Exit. Connect asks for the firewall as [user@]host (prompt
"Firewall (user@host):", checked like --host; a wrong entry is reported and
asked again) and for the user only when "user@" is missing. After Disconnect
the start screen comes back. Everything else (check, backup, install, update,
uninstall, auto-update) is done in the connected menu.
Install/update/reinstall and Uninstall each open a submenu: 1) Run, 2) Dry run
(plan only: prints what would be done and changes nothing), Back. Install/
update also has an Older release item: it lists the 5 stable releases before
the latest (newest first, 0 = Back), then offers Run / Dry run / Back for the
one you pick. A downgrade is allowed (pkg add -f); an older pick than the
installed version asks "Downgrade NetBird from X to Y?" instead (y goes on).
The frame is then titled "Downgrade NetBird" and ends "Downgraded to Y".

Install, Update and Uninstall ask for a y/N confirmation before anything
changes. Before every change you choose the backup: 1) local export like
Diagnostics > Backup & Restore (optionally encrypted, saved and verified in
the Downloads folder), 2) an AutoConfigBackup (ACB) cloud backup confirmed at
Netgate, 3) both, 4) skip (no backup; Install, Update, Uninstall and
Auto-update Enable, Change schedule and Disable only) or 5) back. The
change runs only if every chosen part succeeded; Back cancels it without
changes. Backup only (menu item 2) takes the same backup without changing
anything. Downloaded packages are verified against the SHA-256 digest
published by GitHub. Update keeps the NetBird identity and package settings.
Uninstall is blocked while wt0 is assigned as a pfSense interface.

Auto-update (menu item "Auto-update: <schedule>", also the Auto-update row of
the connected screen) puts a small PHP runner in /root/pfnetbird on the
firewall and one job in pfSense's own cron config. Off: Enable (Run / Dry run
/ Back), then Daily, Weekly or Monthly and HH:MM (firewall time, default
03:30). On: Status, Change schedule, Disable, Back. At each scheduled run the
firewall looks up the latest stable release; if it is newer it takes an ACB
backup and updates only after Netgate has confirmed that backup, keeps the
NetBird identity and settings, restarts NetBird and waits for "Management:
Connected". Results go to the pfSense notices and /root/pfnetbird/auto.log.
Enable, Change schedule and Disable ask for the backup choice first (all
three can skip it). Update and Uninstall stop while a scheduled run is
in progress; Uninstall removes the job and the runner too. Needs the new ACB
with an encryption password (Services > AutoConfigBackup).

Exit code 0 = normal end, 2 = error (also an unknown option and a failed login
with --host).

Options:
  --host [user@]host  Skip the start screen, connect straight away and open
                      the connected menu; after Disconnect the script ends.
                      The host is checked before the login (invalid: error,
                      exit 2). The user is asked only when "user@" is missing;
                      an invalid or empty entry there is reported and asked
                      again.
  --ascii             Draw with plain ASCII instead of Unicode glyphs. Same as
                      PFNETBIRD_ASCII=1.
  --no-log            Do not write a session log (default: on, next to the
                      backups). One file per firewall per day (appended to),
                      pfnetbird-<host>-<yyyyMMdd>.log. In the menu, the log
                      can also be toggled.
  --key <path>        Optional: pin one key (a private key file, or its .pub
                      file to pick one SSH agent key). Nothing is installed or
                      changed on pfSense. A rejected key fails at once, there
                      is no password fallback.
  --version           Print the version and exit.
  --help              Show this help.

Login is a plain ssh: a key from your SSH agent (e.g. 1Password) or ~/.ssh is
used if the firewall accepts it, otherwise ssh asks for the password once.
The script never sees either. An agent that offers many keys can trip
sshguard; pin one key with --key.

Environment:
  GITHUB_TOKEN     Optional. Sent as a Bearer token (never shown, logged or
                   on a command line) to raise the GitHub API rate limit.
                   GitHub answers are cached in memory for 10 minutes; on a
                   rate limit the screen shows Latest unknown and Check
                   retries.
  PFNETBIRD_ASCII  Set to 1 for ASCII drawing (same as --ascii). Without it
                   the script picks Unicode only on a UTF-8 terminal.
                   TERM=dumb and TERM=linux get ASCII.
  NO_COLOR         Turns colour off. The status glyphs stay.

The screens need 78 columns. On a narrower window, widen it or use --ascii.
EOF
}

need_arg() {
  # need_arg <option> <number of remaining args including the option>
  if (( $2 < 2 )); then
    printf 'ERROR: option %s needs a value\n' "$1" >&2
    exit 2
  fi
}

parse_args() {
  while (( $# )); do
    case $1 in
      --no-log)     LOG_ON=0 ;;
      --ascii)      ASCII_FLAG=1 ;;
      --version)    printf 'pfnetbird %s\n' "$SCRIPT_VERSION"; exit 0 ;;
      --host)       need_arg "$1" "$#"; (( HOST_GIVEN )) && HOST_TWICE=1; HOST_GIVEN=1; HOST_ARG=$2; shift ;;
      --host=*)     (( HOST_GIVEN )) && HOST_TWICE=1; HOST_GIVEN=1; HOST_ARG=${1#*=} ;;
      --key)        need_arg "$1" "$#"; KEY_GIVEN=1; KEY_FILE=$2; shift ;;
      --key=*)      KEY_GIVEN=1; KEY_FILE=${1#*=} ;;
      -h|--help)    usage; exit 0 ;;
      *)
        printf 'ERROR: unknown option: %s\n\n' "$1" >&2
        usage >&2
        exit 2
        ;;
    esac
    shift
  done
}

# --key: the key file must exist and be readable on the client. Only the name is ever shown.
check_key_file() {
  if [[ $KEY_FILE == '~/'* ]]; then KEY_FILE=$HOME/${KEY_FILE#'~/'}; fi
  if [[ -z $KEY_FILE ]]; then die '--key needs the path of a private key file'; fi
  ui_sanitize KEY_NAME "${KEY_FILE##*/}"
  if [[ ! -f $KEY_FILE ]]; then die "key file '$KEY_NAME' does not exist or is not a file"; fi
  if [[ ! -r $KEY_FILE ]]; then die "key file '$KEY_NAME' is not readable"; fi
}

check_deps() {
  local -a missing=()
  local c
  for c in ssh curl sha256sum base64 mktemp mv grep sed awk tail date rm mkdir sleep od tr wc tee; do
    command -v "$c" >/dev/null 2>&1 || missing+=("$c")
  done
  if (( ${#missing[@]} )); then
    fail 'missing required commands:'
    for c in "${missing[@]}"; do printf '  - %s\n' "$c"; done
    exit 2
  fi
}

assert_interactive() {
  if [[ ! -t 0 ]] || ! { : </dev/tty; } 2>/dev/null; then
    die 'run pfnetbird from an interactive terminal'
  fi
}

# ---------------------------------------------------------------------------
# Transport: ALL contact with the box lives in send_line, read_remote,
# connect_remote, remote and disconnect_remote. The session is the coproc SSH;
# SSH_W / SSH_R are copies of its fds so ( ) subshells (menu actions) can use it.
# ---------------------------------------------------------------------------
send_line() {
  local fd=$SSH_W
  if [[ -z $fd ]]; then return 1; fi
  { printf '%s\n' "$1" >&"$fd"; } 2>/dev/null
}

# The session is lost or timed out. Menu action subshell: exit 3 (the parent tears the session
# down). Menu handshake (SOFT_FAIL): print and return.
die_session() {
  ui_unstep
  fail "$1"
  print_context
  ui_abort
  if (( IN_ACTION )); then exit 3; fi
  if (( SOFT_FAIL )); then return 0; fi
  exit 2
}

# Reads stdout lines until this command's marker. Whole-command deadline.
# Sets R_OUT (lines, trailing empty lines removed) and R_CODE.
# Returns 0 on success, 2 if the ssh session ended, 3 on timeout during a menu handshake.
read_remote() {
  local marker=$1 timeout=$2
  local line code remaining rc fd n start=$SECONDS
  R_OUT=()
  R_CODE=0
  while :; do
    remaining=$(( timeout - (SECONDS - start) ))
    if (( remaining <= 0 )); then
      die_session "timed out after ${timeout} s waiting for the firewall"
      return 3
    fi
    fd=$SSH_R
    if [[ -z $fd ]]; then return 2; fi
    rc=0
    IFS= read -r -t "$remaining" line <&"$fd" || rc=$?
    if (( rc != 0 )); then
      if (( rc > 128 )); then
        # Timed out (or interrupted). Only an ssh process that is gone ends the session.
        if ! kill -0 "$SESSION_PID" 2>/dev/null; then return 2; fi
        continue
      fi
      return 2   # EOF
    fi
    line=${line%$'\r'}
    if [[ $line == "${marker}_"* ]]; then
      code=${line#"${marker}_"}
      if [[ $code =~ ^[0-9]+$ ]]; then
        n=${#R_OUT[@]}
        while (( n > 0 )) && [[ -z ${R_OUT[n-1]} ]]; do
          n=$(( n - 1 ))
          unset "R_OUT[$n]"
        done
        R_CODE=$(( 10#$code ))
        return 0
      fi
    fi
    R_OUT+=("$line")
  done
}

# A login problem: print the error, tear the session down and return, so the caller can go back
# to the start screen.
login_error() {
  fail_w "$1"
  disconnect_remote
  return 0
}

login_failed() {
  local host=${1:-} code='unknown' i rc=0 err='' eline
  for i in {1..25}; do
    kill -0 "$SESSION_PID" 2>/dev/null || break
    sleep 0.2
  done
  if ! kill -0 "$SESSION_PID" 2>/dev/null; then
    wait "$SESSION_PID" 2>/dev/null || rc=$?
    if (( rc != 127 )); then code=$rc; fi
  fi
  # ssh's own error text (copied to the terminal by connect_remote). The copy (tee) may lag a
  # moment behind ssh's exit, so wait briefly for it.
  if [[ -n $SSH_ERR_FILE ]]; then
    for i in {1..10}; do
      [[ -s $SSH_ERR_FILE ]] && break
      sleep 0.1
    done
    err=$(LC_ALL=C tr -cd '\11\12\40-\176' <"$SSH_ERR_FILE" 2>/dev/null) || err=''
  fi
  if [[ $err =~ (Connection\ timed\ out|Connection\ refused|No\ route\ to\ host|Could\ not\ resolve\ hostname) ]]; then
    # No answer at all: nothing was tried, so this is not a login failure and the key hint is wrong.
    while IFS= read -r eline; do
      if [[ $eline == *"${BASH_REMATCH[1]}"* ]]; then log_line "ssh: $eline"; break; fi
    done <<<"$err"
    local nport=22
    if [[ $host =~ ^\[[^]]+\]:([0-9]+)$ ]]; then nport=$((10#${BASH_REMATCH[1]})); fi
    login_error "No answer from ${host:-the firewall} on port $nport. Check host and network. If you just had failed logins, pfSense (sshguard) may have blocked your IP; wait a few minutes."
    return 0
  fi
  if (( KEY_GIVEN )); then
    warn_w 'pfSense sshguard blocks your IP after a few failed logins. Not retrying.'
    login_error "login failed (ssh exit code $code)"
    return 0
  fi
  if [[ $err == *'Too many authentication failures'* ]]; then
    warn_w 'ssh tries your SSH keys first, then the password. If ssh said "Too many authentication failures", your agent offers too many keys. Pin one for this host (IdentityFile <key>.pub + IdentitiesOnly yes in ~/.ssh/config, see 1Password'"'"'s SSH docs) or run with --key <key>.pub.'
  fi
  login_error "Login failed (ssh exit code $code). Not retrying: pfSense login protection (sshguard) blocks your IP after about 3 failed attempts (default block 120 s, longer on repeats)."
}

# Starts the ssh session in THIS shell (the coproc must belong to the parent). Sets
# LOGIN_OK=1 on success. A failure returns with LOGIN_OK=0.
connect_remote() {
  local host=$1 user=$2 marker rc=0 w r
  local -a auth_opts=() port_opts=()
  local ssh_host=$host
  LOGIN_OK=0

  # [addr] and [addr]:port: ssh keeps brackets in a host name, so pass the bare address and the port as
  # -p. The screen and the log keep what was typed.
  if [[ $host =~ ^\[([^]]+)\](:([0-9]+))?$ ]]; then
    ssh_host=${BASH_REMATCH[1]}
    if [[ -n ${BASH_REMATCH[3]} ]]; then port_opts=(-p "$((10#${BASH_REMATCH[3]}))"); fi
  fi

  # Default: no key options, so this is a plain ssh (~/.ssh/config, SSH_AUTH_SOCK and IdentityAgent
  # apply; ssh prompts for the password if no key works). One thing is fixed: the method order is
  # publickey, then password, and nothing else. NumberOfPasswordPrompts counts PER method (OpenSSH
  # keeps a separate counter for keyboard-interactive and for password), so with the default order
  # (publickey, keyboard-interactive, password) a wrong password gave the PAM prompt "(user@host)
  # Password for ...:" and then, after the server's failure, a second "user@host's password:". That
  # is two failed logins for sshguard and two prompts for one login. pfSense's sshd
  # (src/etc/sshd) has three modes: "Key or Password" (PasswordAuthentication yes + challenge
  # response), "Require both" (AuthenticationMethods publickey,password) and "Key only" (no
  # password at all). The password method is offered in both modes that take a password, so
  # publickey,password gives one prompt in each; keyboard-interactive would fail without a prompt in
  # the "Require both" mode. PreferredAuthentications is used because KbdInteractiveAuthentication
  # aborts OpenSSH older than 8.7. With --key: that key only, and no password fallback, so a
  # rejected key is one failed attempt (sshguard).
  if (( KEY_GIVEN )); then
    auth_opts=(-i "$KEY_FILE"
      -o IdentitiesOnly=yes
      -o PubkeyAuthentication=yes
      -o PasswordAuthentication=no
      -o PreferredAuthentications=publickey)
  else
    auth_opts=(-o 'PreferredAuthentications=publickey,password')
  fi

  # ssh's errors still reach the terminal, and a copy goes to a private temp file (mode 600, removed
  # by disconnect_remote) so login_failed can tell a wrong password from "no answer" and show the
  # key hint only for "Too many authentication failures". Only ssh's stderr is copied: the password
  # (or key passphrase) prompt and what is typed use /dev/tty, never stderr. If mktemp fails ssh
  # runs with stderr untouched, as before.
  SSH_ERR_FILE=$(mktemp "${TMPDIR:-/tmp}/pfnetbird-ssh-XXXXXX" 2>/dev/null) || SSH_ERR_FILE=''
  coproc SSH {
    trap - ERR EXIT
    if [[ -n $SSH_ERR_FILE ]]; then exec 2> >(tee -a "$SSH_ERR_FILE" >&2); fi
    exec ssh -T \
      ${auth_opts[@]+"${auth_opts[@]}"} \
      ${port_opts[@]+"${port_opts[@]}"} \
      -o NumberOfPasswordPrompts=1 \
      -o ConnectTimeout=15 \
      -o ServerAliveInterval=30 \
      "$user@$ssh_host" sh
  }
  SESSION_PID=${SSH_PID:-}
  # Take the fd numbers at once: an ssh that dies instantly gets reaped and SSH is unset.
  w=${SSH[1]:-}
  r=${SSH[0]:-}
  if [[ -z $w || -z $r ]]; then login_failed "$host"; return 0; fi
  # Copy the coproc fds once; subshells do not inherit the coproc's own fds.
  exec {SSH_W}>&"$w" {SSH_R}<&"$r" || { login_failed "$host"; return 0; }

  if [[ -r /proc/sys/kernel/random/uuid ]]; then
    read -r TOK </proc/sys/kernel/random/uuid
    TOK=${TOK//-/}
  else
    TOK=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
  fi
  if [[ ! $TOK =~ ^[0-9a-f]{16,}$ ]]; then login_error 'cannot create a session token'; return 0; fi

  # Queued in the pipe until ssh has logged in. PATH first, then merge stderr into
  # stdout, then the handshake: echo + marker.
  send_line 'export PATH="$PATH:/usr/local/bin:/usr/local/sbin"' || { login_failed "$host"; return 0; }
  send_line 'exec 2>&1' || { login_failed "$host"; return 0; }
  SEQ=$(( SEQ + 1 ))
  marker="__PFNB_${TOK}_${ACT}_${SEQ}"
  send_line "echo handshake; printf '\\n${marker}_%d\\n' \"\$?\"" || { login_failed "$host"; return 0; }
  # Generous deadline: a human types the password in this window.
  SOFT_FAIL=1
  read_remote "$marker" 180 || rc=$?
  SOFT_FAIL=0
  if (( rc == 3 )); then disconnect_remote; return 0; fi
  if (( rc != 0 )); then login_failed "$host"; return 0; fi
  LOGIN_OK=1
  ok 'Login OK'
}

# remote <command> [timeout-seconds]  ->  R_OUT, R_CODE
# Never retries. Ends the action/script if the session is gone or the deadline passes.
remote() {
  local cmd=$1 timeout=${2:-60} marker rc=0 t0 l
  if [[ -z $SESSION_PID ]]; then die 'not connected'; fi
  if [[ $cmd == *$'\n'* || $cmd == *$'\r'* ]]; then die 'internal error: multi-line remote command'; fi
  SEQ=$(( SEQ + 1 ))
  marker="__PFNB_${TOK}_${ACT}_${SEQ}"
  t0=$SECONDS
  log_line "remote> $cmd"
  # Brace group so </dev/null covers the whole command; $? is read right after it.
  send_line "{ ${cmd}; } </dev/null; printf '\\n${marker}_%d\\n' \"\$?\"" \
    || die_session 'the ssh session ended unexpectedly'
  read_remote "$marker" "$timeout" || rc=$?
  if (( rc != 0 )); then die_session 'the ssh session ended unexpectedly'; fi
  log_line "remote< exit=$R_CODE duration=$(( SECONDS - t0 ))s lines=${#R_OUT[@]}"
  # Output is logged only for a failing command, and never while REMOTE_QUIET is set (ACB and
  # config export commands: the output may carry the config backup or ACB data).
  if (( R_CODE != 0 && ! REMOTE_QUIET )); then
    for l in "${R_OUT[@]+"${R_OUT[@]}"}"; do log_line "remote output: $l"; done
  fi
}

# remote_secret <command> <secret> [timeout-seconds] [log-note]  ->  R_OUT, R_CODE
# Like remote, but <command> reads one line from stdin: the secret is sent as a here-doc body
# (line 2) followed by the terminator (line 3). Only line 1 is logged; the secret never is.
remote_secret() {
  local cmd=$1 secret=$2 timeout=${3:-60} note=${4:-secret on stdin, not logged} marker term rc=0 t0 l
  if [[ -z $SESSION_PID ]]; then die 'not connected'; fi
  if [[ $cmd == *$'\n'* || $cmd == *$'\r'* || $secret == *$'\n'* || $secret == *$'\r'* ]]; then die 'internal error: multi-line remote command'; fi
  SEQ=$(( SEQ + 1 ))
  marker="__PFNB_${TOK}_${ACT}_${SEQ}"
  term="__PFNB_S_${TOK}_${SEQ}__"
  t0=$SECONDS
  log_line "remote> $cmd <<'$term' ($note)"
  send_line "${cmd} <<'${term}'; printf '\\n${marker}_%d\\n' \"\$?\"" \
    && send_line "$secret" \
    && send_line "$term" \
    || die_session 'the ssh session ended unexpectedly'
  read_remote "$marker" "$timeout" || rc=$?
  if (( rc != 0 )); then die_session 'the ssh session ended unexpectedly'; fi
  log_line "remote< exit=$R_CODE duration=$(( SECONDS - t0 ))s lines=${#R_OUT[@]}"
  if (( R_CODE != 0 && ! REMOTE_QUIET )); then
    for l in "${R_OUT[@]+"${R_OUT[@]}"}"; do log_line "remote output: $l"; done
  fi
}

# remote_payload <command> <one-line payload> [timeout-seconds]: remote_secret for a non-secret
# payload (the auto-update runner, base64). Logged as the command plus the payload size only.
remote_payload() {
  remote_secret "$1" "$2" "${3:-60}" "payload on stdin, ${#2} bytes, not logged"
}

# A change step: a non-zero exit code stops the script (or the menu action).
remote_step() {
  local name=$1 cmd=$2 timeout=${3:-60} out='' l
  log_line "step: $name"
  remote "$cmd" "$timeout"
  if (( R_CODE != 0 )); then
    for l in "${R_OUT[@]+"${R_OUT[@]}"}"; do out+=$'\n'"$l"; done
    die "step '$name' failed (exit code $R_CODE):$out"
  fi
}

r_first() { if (( ${#R_OUT[@]} )); then trim "${R_OUT[0]}"; fi; }
r_last()  { local n=${#R_OUT[@]}; if (( n )); then trim "${R_OUT[n-1]}"; fi; }

# Closes the session: remove the remote download directory (only if something was
# downloaded), send exit, wait briefly, kill if needed, reap the process, close the fd
# copies and reset the per-session state. Safe to call when there is no session. It does
# not touch shell options, so the EXIT trap can use it.
disconnect_remote() {
  local i
  if [[ -n $SESSION_PID ]]; then
    if kill -0 "$SESSION_PID" 2>/dev/null; then
      if (( DOWNLOADED )); then send_line "rm -rf $REMOTE_DIR" || true; fi
      send_line "rm -f $AUTO_BUSY" || true   # the "client change in progress" marker for the auto-update runner
      send_line 'exit' || true
      for i in {1..25}; do
        kill -0 "$SESSION_PID" 2>/dev/null || break
        sleep 0.2
      done
      if kill -0 "$SESSION_PID" 2>/dev/null; then kill "$SESSION_PID" 2>/dev/null || true; fi
    fi
    wait "$SESSION_PID" 2>/dev/null || true
  fi
  if [[ -n $SSH_ERR_FILE ]]; then rm -f "$SSH_ERR_FILE"; SSH_ERR_FILE=''; fi
  if [[ -n $SSH_W ]]; then exec {SSH_W}>&- || true; fi
  if [[ -n $SSH_R ]]; then exec {SSH_R}<&- || true; fi
  SSH_W=''; SSH_R=''
  if [[ -n ${1:-} ]]; then info "$1"; fi
  log_close
  SESSION_PID=''; TOK=''; ACT=0; SEQ=0; DOWNLOADED=0
  CTX_BACKUP=''; CTX_IDENTITY=''
  reset_state
}

# EXIT trap (never runs inside menu action subshells).
cleanup() {
  set +e
  trap - ERR
  ui_abort
  disconnect_remote
  if [[ -n $TMP_FILE && -e $TMP_FILE ]]; then rm -f "$TMP_FILE"; fi
  if [[ -n $STATE_FILE && -e $STATE_FILE ]]; then rm -f "$STATE_FILE"; fi
}

# ---------------------------------------------------------------------------
# Input checks
# ---------------------------------------------------------------------------
# A host that is only digits and dots must be a valid IPv4 address (four numbers 0-255, no leading
# zero except a single 0, because ssh reads 010 as octal): a bare "2", "192.0.2" or "192.168.010.1" is
# rejected instead of being passed to ssh. Names and IPv6 are unchanged. A bracketed form is [addr] or
# [addr]:port (port 1-65535); connect_remote strips the brackets before ssh sees the address. A port is
# only taken in that bracketed form: an unbracketed host with exactly one ':' (host:port, 1.2.3.4:port) is
# rejected, an IPv6 literal has at least two.
test_hostname() {
  local o
  [[ $1 =~ $RE_HOST ]] || return 1
  if [[ $1 != \[* && $1 == *:* && $1 != *:*:* ]]; then return 1; fi
  if [[ $1 =~ \]:([0-9]+)$ ]]; then
    (( 10#${BASH_REMATCH[1]} >= 1 && 10#${BASH_REMATCH[1]} <= 65535 )) || return 1
  fi
  if [[ $1 =~ ^[0-9.]+$ ]]; then
    [[ $1 =~ ^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$ ]] || return 1
    for o in "${BASH_REMATCH[@]:1}"; do
      if (( 10#$o > 255 )); then return 1; fi
    done
  fi
  return 0
}
test_username() { [[ $1 =~ $RE_USER ]]; }

# 100.64.0.0/10
is_netbird_range() {
  local re='^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$'
  local o1 o2 o3 o4
  [[ $1 =~ $re ]] || return 1
  o1=${BASH_REMATCH[1]}; o2=${BASH_REMATCH[2]}; o3=${BASH_REMATCH[3]}; o4=${BASH_REMATCH[4]}
  if (( 10#$o1 > 255 || 10#$o2 > 255 || 10#$o3 > 255 || 10#$o4 > 255 )); then return 1; fi
  (( 10#$o1 == 100 && (10#$o2 & 192) == 64 ))
}

# ---------------------------------------------------------------------------
# Versions
# ---------------------------------------------------------------------------
# Strip a pkg revision (_N) or epoch (,N) suffix and validate. Result in PV.
parse_pkg_version() {
  try_pkg_version "$1" || die "$RESOLVE_ERR"
}

# The same without dying: returns 1 with RESOLVE_ERR set.
try_pkg_version() {
  local clean
  clean=$(trim "$1")
  clean=${clean%%[_,]*}
  if [[ ! $clean =~ ^[0-9]+(\.[0-9]+){1,3}$ ]]; then RESOLVE_ERR="cannot parse version '$1'"; return 1; fi
  PV=$clean
}

# version_cmp A B: sets VCMP to -1, 0 or 1 (A older than, equal to, newer than B). The one version compare
# for every caller (up-to-date check, downgrade check). Arguments are version strings as pkg and the release
# assets print them: N.N[.N[.N]] with an optional revision _N and an optional epoch ,N. Numeric, part by part
# (0.9.0 < 0.10.0); a missing part counts as 0, so 0.80 equals 0.80.0; the revision is compared last and a
# missing revision counts as 0 (0.80.0 < 0.80.0_1 < 0.80.0_2). The epoch (,N) is ignored. Pure bash
# arithmetic, no sort -V (not on every macOS/BSD). The ps1 twin is Compare-PkgVersion.
version_cmp() {
  local -a pa pb
  local i n x y a=$1 b=$2 ra=0 rb=0
  a=${a//[[:space:]]/}; b=${b//[[:space:]]/}
  a=${a%%,*}; b=${b%%,*}
  if [[ $a == *_* ]]; then ra=${a#*_}; a=${a%%_*}; fi
  if [[ $b == *_* ]]; then rb=${b#*_}; b=${b%%_*}; fi
  IFS=. read -r -a pa <<<"$a"
  IFS=. read -r -a pb <<<"$b"
  n=${#pa[@]}
  if (( ${#pb[@]} > n )); then n=${#pb[@]}; fi
  VCMP=0
  for (( i = 0; i < n; i++ )); do
    x=0; y=0
    if [[ ${pa[i]-} =~ ^[0-9]+$ ]]; then x=$(( 10#${pa[i]} )); fi
    if [[ ${pb[i]-} =~ ^[0-9]+$ ]]; then y=$(( 10#${pb[i]} )); fi
    if (( x < y )); then VCMP=-1; return 0; fi
    if (( x > y )); then VCMP=1; return 0; fi
  done
  x=0; y=0
  if [[ $ra =~ ^[0-9]+$ ]]; then x=$(( 10#$ra )); fi
  if [[ $rb =~ ^[0-9]+$ ]]; then y=$(( 10#$rb )); fi
  if (( x < y )); then VCMP=-1; elif (( x > y )); then VCMP=1; fi
  return 0
}

# version_ge A B: true if A is equal to or newer than B.
version_ge() {
  version_cmp "$1" "$2"
  (( VCMP >= 0 ))
}

# ---------------------------------------------------------------------------
# Box inspection
# ---------------------------------------------------------------------------
get_box_info() {
  local uname_p

  remote 'id -u'
  if (( R_CODE != 0 )) || [[ $(r_last) != 0 ]]; then
    die 'needs admin or root (this login is not uid 0)'
  fi

  remote 'cat /etc/version'
  if (( R_CODE != 0 || ${#R_OUT[@]} == 0 )); then die 'cannot read /etc/version - is this a pfSense box?'; fi
  BOX_VERSION=$(r_first)
  if [[ $BOX_VERSION =~ ^2\. ]]; then
    BOX_EDITION='CE'
  elif [[ $BOX_VERSION =~ ^[0-9]{2}\.[0-9]{2} ]]; then
    BOX_EDITION='Plus'
  else
    BOX_EDITION='unknown'
  fi

  remote 'uname -p'
  if (( R_CODE != 0 || ${#R_OUT[@]} == 0 )); then die 'cannot read the CPU architecture (uname -p)'; fi
  uname_p=$(r_first)
  case $uname_p in
    amd64)           BOX_ARCH='x86_64' ;;
    arm64|aarch64)   BOX_ARCH='aarch64' ;;
    *)               die "unsupported architecture '$uname_p'" ;;
  esac

  BOX_HOST=''; BOX_FQDN=''
  remote 'hostname'
  if (( R_CODE == 0 && ${#R_OUT[@]} > 0 )); then
    BOX_HOST=$(r_first)
    ui_sanitize BOX_FQDN "$BOX_HOST"      # the full name, for the title line (display only)
    BOX_HOST=${BOX_HOST%%.*}
  fi

  remote 'pkg config ABI'
  if (( R_CODE != 0 || ${#R_OUT[@]} == 0 )); then die 'cannot read the package ABI (pkg config ABI)'; fi
  BOX_ABI=$(r_first)
  if [[ ! $BOX_ABI =~ ^[Ff]ree[Bb][Ss][Dd]:([0-9]+):(.+)$ ]]; then die "unexpected package ABI '$BOX_ABI'"; fi
  BOX_MAJOR=$(( 10#${BASH_REMATCH[1]} ))
  if (( BOX_MAJOR < MIN_FREEBSD )); then
    die "FreeBSD $BOX_MAJOR is too old (ABI $BOX_ABI); minimum is FreeBSD $MIN_FREEBSD"
  fi
}

get_netbird_state() {
  NB_INSTALLED=0; NB_CLIENT=''; NB_PKG=''; NB_CLIENT_VER=''
  remote 'pkg info -e netbird'
  if (( R_CODE != 0 )); then return 0; fi
  remote "pkg query '%v' netbird"
  NB_CLIENT=$(r_first)
  remote "pkg query '%v' pfSense-pkg-NetBird"
  NB_PKG=$(r_first)
  if [[ -z $NB_CLIENT ]]; then die 'netbird is installed but its version could not be read'; fi
  NB_INSTALLED=1
  parse_pkg_version "$NB_CLIENT"
  NB_CLIENT_VER=$PV
}

# ---------------------------------------------------------------------------
# GitHub release lookup (runs on the client)
# ---------------------------------------------------------------------------
# One GitHub API reply per URL, kept in memory for 10 minutes (parent shell globals, never on disk).
# Failures are never cached. So the cache survives, lookups run in the parent shell, not in a menu
# action subshell. Sets RELEASE_JSON (body) and HTTP_CODE. Returns 0 on a 2xx reply, 1 on any other
# failure (GH_ERR holds the text), 2 on a rate limit (HTTP 429, or HTTP 403 with
# X-RateLimit-Remaining: 0 or "rate limit" in the message).
declare -A GH_C_BODY=() GH_C_CODE=() GH_C_AT=()
gh_lookup() {
  local uri=$1 now age out='' hdr='' remain='' msg='' sv_tag sv_assets tok
  GH_ERR=''
  now=$(date +%s)
  if [[ -n ${GH_C_AT[$uri]:-} ]]; then
    age=$(( now - GH_C_AT[$uri] ))
    if (( age >= 0 && age < 600 )); then
      RELEASE_JSON=${GH_C_BODY[$uri]}; HTTP_CODE=${GH_C_CODE[$uri]}
      return 0
    fi
  fi
  log_line "GitHub lookup: $uri"
  local -a args=(-sS --max-time 30 -D - -w '\n%{http_code}'
    -H 'Accept: application/vnd.github+json'
    -H "User-Agent: pfnetbird/$SCRIPT_VERSION")
  if [[ -n ${GITHUB_TOKEN:-} ]]; then
    # The token goes to curl on stdin (-K -), never on the command line (ps would show it).
    tok=${GITHUB_TOKEN//\\/\\\\}; tok=${tok//\"/\\\"}
    if [[ $GITHUB_TOKEN == *[[:cntrl:]]* ]]; then
      # A control character (newline, ...) cannot be a header value, and must not reach the curl config.
      log_line 'GitHub HTTP status: none'
      GH_ERR="GitHub release lookup failed ($uri): GITHUB_TOKEN contains a control character and cannot be sent"
      return 1
    fi
    if [[ $GITHUB_TOKEN == *'"'* ]]; then
      # A double quote is refused as well, so both scripts behave the same (.NET rejects it in a header).
      log_line 'GitHub HTTP status: none'
      GH_ERR="GitHub release lookup failed ($uri): GITHUB_TOKEN contains a double quote and cannot be sent"
      return 1
    fi
    if ! out=$(printf 'header = "Authorization: Bearer %s"\n' "$tok" \
               | curl "${args[@]}" -K - "$uri" 2>&1); then
      log_line 'GitHub HTTP status: none'
      GH_ERR="GitHub release lookup failed ($uri): $out"
      return 1
    fi
  else
    if ! out=$(curl "${args[@]}" "$uri" 2>&1); then
      log_line 'GitHub HTTP status: none'
      GH_ERR="GitHub release lookup failed ($uri): $out"
      return 1
    fi
  fi
  HTTP_CODE=${out##*$'\n'}
  out=${out%$'\n'*}
  # Header blocks: more than one with 100 Continue or a proxy CONNECT reply; the last one is the real one.
  while [[ $out == HTTP/* && $out == *$'\r\n\r\n'* ]]; do
    hdr=${out%%$'\r\n\r\n'*}
    out=${out#*$'\r\n\r\n'}
  done
  RELEASE_JSON=$out
  log_line "GitHub HTTP status: $HTTP_CODE"
  if [[ $HTTP_CODE =~ ^2[0-9][0-9]$ ]]; then
    GH_C_BODY[$uri]=$RELEASE_JSON; GH_C_CODE[$uri]=$HTTP_CODE; GH_C_AT[$uri]=$now
    return 0
  fi
  sv_tag=${REL_TAG:-}; sv_assets=${ASSETS:-}
  parse_release_json
  msg=$REL_MSG
  REL_TAG=$sv_tag; ASSETS=$sv_assets
  if [[ ${hdr,,} =~ x-ratelimit-remaining:[[:space:]]*([0-9]+) ]]; then remain=${BASH_REMATCH[1]}; fi
  if [[ $HTTP_CODE == 429 ]] || [[ $HTTP_CODE == 403 && ( $remain == 0 || ${msg,,} == *'rate limit'* ) ]]; then
    return 2
  fi
  if [[ -n $msg ]]; then GH_ERR="GitHub API returned HTTP $HTTP_CODE for $uri: $msg"; else GH_ERR="GitHub API returned HTTP $HTTP_CODE for $uri"; fi
  return 1
}

rate_limit_fail() {
  fail_w 'GitHub rate limit reached for your IP (60 requests per hour). Wait up to an hour, or set GITHUB_TOKEN.'
}

# Formatting-independent JSON reader (no jq): a small string-aware scanner in awk.
# Output lines: "T <tag_name>", "M <message>" (both top-level only) and
# "A <name>|<digest>|<browser_download_url>" for each object directly inside "assets".
# Nested objects (uploader) are skipped by depth, braces inside strings are ignored.
parse_release_json() {
  PARSED=$(printf '%s\n' "$RELEASE_JSON" | LC_ALL=C awk '
    { buf = buf $0 "\n" }
    END {
      n = length(buf); i = 1; depth = 0; A = -1; lastkey = ""
      while (i <= n) {
        c = substr(buf, i, 1)
        if (c == "\"") {
          j = i + 1; str = ""
          while (j <= n) {
            d = substr(buf, j, 1)
            if (d == "\\") { str = str substr(buf, j + 1, 1); j += 2; continue }
            if (d == "\"") break
            str = str d; j++
          }
          i = j + 1
          k = i
          while (k <= n && substr(buf, k, 1) ~ /[ \t\r\n]/) k++
          if (substr(buf, k, 1) == ":") { lastkey = str; i = k + 1 }
          else if (depth == 1 && lastkey == "tag_name") print "T " str
          else if (depth == 1 && lastkey == "message") print "M " str
          else if (A >= 0 && depth == A + 1) {
            if (lastkey == "name") nm = str
            else if (lastkey == "digest") dg = str
            else if (lastkey == "browser_download_url") ur = str
          }
          continue
        }
        if (c == "{") {
          depth++
          if (A >= 0 && depth == A + 1) { nm = ""; dg = ""; ur = "" }
          lastkey = ""
        } else if (c == "[") {
          depth++
          if (depth == 2 && lastkey == "assets") A = 2
          lastkey = ""
        } else if (c == "}") {
          if (A >= 0 && depth == A + 1) print "A " nm "|" dg "|" ur
          depth--; lastkey = ""
        } else if (c == "]") {
          if (depth == A) A = -1
          depth--; lastkey = ""
        } else if (c == ",") {
          lastkey = ""
        }
        i++
      }
    }
  ')
  REL_TAG=$(printf '%s\n' "$PARSED" | sed -n 's/^T //p' | awk 'NR == 1')
  REL_MSG=$(printf '%s\n' "$PARSED" | sed -n 's/^M //p' | awk 'NR == 1')
  ASSETS=$(printf '%s\n' "$PARSED" | sed -n 's/^A //p')
}

# The same scanner for the releases LIST (a JSON array). Output, per release: first one
# "A <name>|<digest>|<browser_download_url>" line for each of its assets, then
# "R <tag>|<draft 0/1>|<prerelease 0/1>|<name of the netbird-<ver>-<arch>.pkg asset or empty>".
# Release objects sit at depth 2, their assets at depth 4; nested objects are skipped by depth.
parse_release_list() {
  PARSED=$(printf '%s\n' "$RELEASE_JSON" | LC_ALL=C awk -v arch="$1" '
    function asset(nm) { if (nm ~ ("^netbird-.+-" arch "\\.pkg$")) cl = nm }
    { buf = buf $0 "\n" }
    END {
      n = length(buf); i = 1; depth = 0; inA = 0; lastkey = ""
      while (i <= n) {
        c = substr(buf, i, 1)
        if (c == "\"") {
          j = i + 1; str = ""
          while (j <= n) {
            d = substr(buf, j, 1)
            if (d == "\\") { str = str substr(buf, j + 1, 1); j += 2; continue }
            if (d == "\"") break
            str = str d; j++
          }
          i = j + 1
          k = i
          while (k <= n && substr(buf, k, 1) ~ /[ \t\r\n]/) k++
          if (substr(buf, k, 1) == ":") { lastkey = str; i = k + 1 }
          else if (depth == 2 && lastkey == "tag_name") tag = str
          else if (inA && depth == 4) {
            if (lastkey == "name") { asset(str); nm = str }
            else if (lastkey == "digest") dg = str
            else if (lastkey == "browser_download_url") ur = str
          }
          continue
        }
        if (c == "{") {
          depth++
          if (depth == 2) { tag = ""; dr = 0; pre = 0; cl = ""; al = "" }
          if (inA && depth == 4) { nm = ""; dg = ""; ur = "" }
          lastkey = ""
        } else if (c == "[") {
          depth++
          if (depth == 3 && lastkey == "assets") inA = 1
          lastkey = ""
        } else if (c == "}") {
          if (inA && depth == 4) al = al "A " nm "|" dg "|" ur "\n"
          if (depth == 2) { if (tag != "") { printf "%s", al; print "R " tag "|" dr "|" pre "|" cl }; al = "" }
          depth--; lastkey = ""
        } else if (c == "]") {
          if (inA && depth == 3) inA = 0
          depth--; lastkey = ""
        } else if (c == ",") {
          lastkey = ""
        } else if (depth == 2 && (lastkey == "draft" || lastkey == "prerelease") && (c == "t" || c == "f")) {
          if (lastkey == "draft") dr = (c == "t") ? 1 : 0; else pre = (c == "t") ? 1 : 0
          lastkey = ""
        }
        i++
      }
    }
  ')
}

# resolve_asset <var-prefix> <ERE pattern> : picks the first asset whose name matches.
# Sets <prefix>_NAME, _URL, _DIGEST, _VER (as published) and _VERCLEAN (revision stripped).
resolve_asset() {
  local prefix=$1 pattern=$2
  local n d u ver name='' url='' digest='' found=0
  while IFS='|' read -r n d u; do
    if [[ $n =~ $pattern ]]; then
      ver=${BASH_REMATCH[1]}
      name=$n; digest=$d; url=$u
      found=1
      break
    fi
  done <<<"$ASSETS"
  if (( ! found )); then RESOLVE_ERR="no release asset matches $pattern"; return 1; fi

  if [[ ! $name =~ ^[A-Za-z0-9._+-]+$ ]]; then RESOLVE_ERR="unexpected asset file name '$name'"; return 1; fi
  if [[ $url != "$URL_PREFIX"* ]]; then RESOLVE_ERR="unexpected download URL for '$name'"; return 1; fi
  if [[ $url == *"'"* ]]; then RESOLVE_ERR="unexpected download URL for '$name'"; return 1; fi
  if [[ ! $digest =~ ^sha256:([0-9a-fA-F]{64})$ ]]; then
    RESOLVE_ERR="release asset '$name' has no usable sha256 digest; there is no fallback checksum source in v0.1"
    return 1
  fi
  digest=${BASH_REMATCH[1]}
  digest=${digest,,}

  try_pkg_version "$ver" || return 1
  printf -v "${prefix}_NAME" '%s' "$name"
  printf -v "${prefix}_URL" '%s' "$url"
  printf -v "${prefix}_DIGEST" '%s' "$digest"
  printf -v "${prefix}_VER" '%s' "$ver"
  printf -v "${prefix}_VERCLEAN" '%s' "$PV"
}

# The latest release (from the cache or GitHub), for this architecture. Returns 0, 1 (GH_ERR) or 2 (rate limit).
get_latest_release() {
  local arch=$1 uri="$REPO_API/releases/latest" rc=0 snippet
  gh_lookup "$uri" || rc=$?
  if (( rc != 0 )); then return "$rc"; fi
  parse_release_json
  if [[ -z $REL_TAG ]]; then
    if [[ -n $REL_MSG ]]; then GH_ERR="GitHub API message for $uri: $REL_MSG"; return 1; fi
    snippet=$(printf '%s' "$RELEASE_JSON" | tr -s '[:space:]' ' ')
    GH_ERR="GitHub response for $uri has no tag_name (HTTP $HTTP_CODE; response starts: ${snippet:0:200})"
    return 1
  fi
  if ! { resolve_asset REL_CL '^netbird-(.+)-'"$arch"'\.pkg$' && resolve_asset REL_UI '^pfSense-pkg-NetBird-(.+)-'"$arch"'\.pkg$'; }; then
    GH_ERR=$RESOLVE_ERR
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# Backup (client side)
# ---------------------------------------------------------------------------
downloads_dir() {
  DL_DIR=''
  if command -v xdg-user-dir >/dev/null 2>&1; then
    DL_DIR=$(xdg-user-dir DOWNLOAD 2>/dev/null || true)
    DL_DIR=${DL_DIR%%$'\n'*}
    DL_DIR=$(trim "$DL_DIR")
  fi
  if [[ -z $DL_DIR ]]; then DL_DIR="$HOME/Downloads"; fi
}

# --- ACB (AutoConfigBackup) -------------------------------------------------
# PHP run on the box. No single quotes inside: each is wrapped in php -r '...'.
# Booleans only: the device key, the ACB password and config content are never printed.
ACB_PRE_PHP='require_once("config.inc"); require_once("acb.inc"); echo "ACB_CODE=".(function_exists("acb_backup_stage_upload")?"new":"legacy")."\n"; echo "ENABLED=".(config_get_path("system/acb/enable")=="yes"?1:0)."\n"; echo "PASSWORD_SET=".(strlen((string)config_get_path("system/acb/encryption_password"))>0?1:0)."\n"; echo "PENDING=".count((array)glob("/cf/conf/acb/*.form"))."\n";'
# Same as the GUI Backup Now: a full write_config (not write_config_only) with /tmp/forceacb set.
ACB_WRITE_PHP='require_once("config.inc"); $w=write_config("pfnetbird: before @WHAT@-MaNuAlBaCkUp"); echo "WRITE=".(is_array($w)?1:0)."\n"; echo "REV=".config_get_path("revision/time")."\n";'
# Lists the backups at Netgate, picks the newest "pfnetbird" entry and compares its sha256.
ACB_CONFIRM_PHP='require_once("config.inc"); require_once("acb.inc"); $k=get_acb_device_key(); $l=(array)acb_backup_list($k); echo "LISTED=".count($l)."\n"; $b=null; foreach($l as $e){ if(stripos((string)$e["reason"],"pfnetbird")===false){continue;} if($b===null||strtotime($e["time"])>=strtotime($b["time"])){$b=$e;} } if($b===null){echo "REMOTE_MATCH=0\n"; exit(0);} $q=acb_backup_get($k,$b["time"]); $p=explode("++++",(string)$q[0],2); echo "REMOTE_MATCH=".(strtolower(trim($p[0]))=="@SHA@"?1:0)."\n"; echo "TIME=".(trim((string)$b["localtime"])!==""?$b["localtime"]:$b["time"])."\n";'
# Same as the GUI Download button (Diagnostics > Backup & Restore) with the GUI defaults.
EXPORT_PHP='require_once("config.inc"); require_once("/usr/local/pfSense/include/www/backup.inc"); $p=["download"=>"Download","backuparea"=>"","donotbackuprrd"=>"yes","backupssh"=>"yes"]; if($e){$w=base64_decode(trim(stream_get_contents(STDIN))); $p["encrypt"]="yes"; $p["encrypt_password"]=$w; $p["encrypt_password_confirm"]=$w;} $r=execPost($p,[],false); if(!is_string($r)){ foreach((array)$r["input_errors"] as $m){echo "ERROR=".$m."\n";} exit(1);} $j=json_decode($r,true); $d=base64_decode($j["contents"]); echo "NAME=".$j["name"]."\n"."SIZE=".strlen($d)."\n"."SHA256=".hash("sha256",$d)."\n"."ENCRYPTED=".($e?1:0)."\n".chunk_split($j["contents"],76,"\n");'

# Reads the ACB state of the box (read-only). Sets ACB_CODE, ACB_OK, ACB_TXT.
acb_preflight() {
  local l en='' pw='' pend=''
  ACB_CODE=''; ACB_OK=0; ACB_TXT=''; ACB_PENDING=0
  REMOTE_QUIET=1
  remote "php -r '$ACB_PRE_PHP'" 60
  REMOTE_QUIET=0
  for l in "${R_OUT[@]+"${R_OUT[@]}"}"; do
    case $l in
      ACB_CODE=*)     ACB_CODE=${l#ACB_CODE=} ;;
      ENABLED=*)      en=${l#ENABLED=} ;;
      PASSWORD_SET=*) pw=${l#PASSWORD_SET=} ;;
      PENDING=*)      pend=${l#PENDING=} ;;
    esac
  done
  if (( R_CODE != 0 )) || [[ ! $ACB_CODE =~ ^(new|legacy)$ || ! $en =~ ^[01]$ || ! $pw =~ ^[01]$ ]]; then
    ACB_CODE=''
    ACB_TXT='ACB not available: state could not be read'
    log_line 'ACB preflight: state could not be read'
    return 0
  fi
  if [[ $pend =~ ^[0-9]+$ ]]; then ACB_PENDING=$pend; fi
  log_line "ACB preflight: code=$ACB_CODE enabled=$en password_set=$pw pending=${pend:-?}"
  if [[ $en != 1 ]]; then
    ACB_TXT='ACB not available: disabled'
  elif [[ $pw != 1 ]]; then
    ACB_TXT='ACB not available: no encryption password'
  else
    ACB_OK=1
    ACB_TXT='ACB: enabled, encryption password set'
  fi
}

# Triggers an ACB backup like the GUI "Backup Now" and confirms it. $1 = install|update|downgrade|uninstall|manual backup.
# Sets ACB_DONE=1 when confirmed. On failure prints the reason, leaves ACB_DONE=0, returns 0.
acb_backup() {
  BK_KIND=ok; BK_DETAIL=''
  ui_step_begin Backup 'ACB cloud backup'
  acb_backup_run "$1"
  if (( ACB_DONE )); then ui_step_end "$BK_KIND" "$BK_DETAIL"; else ui_step_end fail ''; fi
  return 0
}

acb_backup_run() {
  local what=$1 marker form code l rev='' sha='' wr='' match='' rtime='' listed='' mark i hhmm
  ACB_DONE=0
  if [[ $ACB_CODE == new ]]; then marker=/cf/conf/lastACBentry.txt; else marker=/cf/conf/lastpfSbackup.txt; fi

  REMOTE_QUIET=1
  code=${ACB_WRITE_PHP//@WHAT@/$what}
  remote "rm -f $marker; touch /tmp/forceacb; php -r '$code'" 120
  REMOTE_QUIET=0
  for l in "${R_OUT[@]+"${R_OUT[@]}"}"; do
    case $l in
      WRITE=*) wr=${l#WRITE=} ;;
      REV=*)   rev=${l#REV=} ;;
    esac
  done
  if (( R_CODE != 0 )) || [[ $wr != 1 ]]; then
    remote 'rm -f /tmp/forceacb'
    fail 'ACB backup: write_config on the firewall failed'
    return 0
  fi

  remote "sha256 -q $CONFIG_XML"
  sha=$(r_first)
  sha=${sha,,}
  if (( R_CODE != 0 )) || [[ ! $sha =~ ^[0-9a-f]{64}$ ]]; then
    fail 'ACB backup: cannot hash config.xml on the firewall'
    return 0
  fi

  form=/cf/conf/acb/$sha.form
  if [[ $ACB_CODE == new ]]; then
    remote "test -e $form"
    if (( R_CODE != 0 )); then fail 'ACB did not stage the backup'; return 0; fi
  fi

  log_line 'ACB: uploading the backup to Netgate...'
  REMOTE_QUIET=1
  # Each pending form can take up to about 85 s, so the limit scales with the preflight count.
  remote '/usr/bin/nice -n20 /usr/local/bin/php /usr/local/sbin/acbupload.php' $(( 150 + 90 * ACB_PENDING ))
  # The upload may be locked by cron (/tmp/acb.lock): wait up to about 90 s for it to finish.
  if [[ $ACB_CODE == new ]]; then
    remote "i=0; while [ -e $form ] && [ \$i -lt 30 ]; do sleep 3; i=\$((i+1)); done; [ ! -e $form ]" 120
  else
    remote "i=0; while [ ! -e $marker ] && [ \$i -lt 30 ]; do sleep 3; i=\$((i+1)); done; [ -e $marker ]" 120
  fi
  REMOTE_QUIET=0
  if (( R_CODE != 0 )); then
    if [[ $ACB_CODE == new ]]; then
      fail 'ACB upload did not finish within 90 s - see Status > System Logs > System'
    else
      fail 'ACB upload FAILED - see Status > System Logs > System (Unable to resolve / An error occurred...)'
    fi
    return 0
  fi

  remote "test -e $marker"
  if (( R_CODE != 0 )); then
    fail 'ACB upload FAILED - see Status > System Logs > System (Unable to resolve / An error occurred...)'
    return 0
  fi

  if [[ $ACB_CODE == legacy ]]; then
    log_line "OK: ACB upload reported success (legacy, not verified remotely), sha256 $sha"
    BK_KIND=warn; BK_DETAIL="ACB upload reported success $U_MID not verified remotely (legacy)"
    ACB_DONE=1
    return 0
  fi

  code=${ACB_CONFIRM_PHP//@SHA@/$sha}
  REMOTE_QUIET=1
  remote "php -r '$code'" 120
  REMOTE_QUIET=0
  for l in "${R_OUT[@]+"${R_OUT[@]}"}"; do
    case $l in
      LISTED=*)       listed=${l#LISTED=} ;;
      REMOTE_MATCH=*) match=${l#REMOTE_MATCH=} ;;
      TIME=*)         rtime=${l#TIME=} ;;
    esac
  done
  if (( R_CODE == 0 )) && [[ $match == 1 && -n $rtime ]]; then
    log_line "OK: ACB backup confirmed at Netgate: $rtime, sha256 $sha"
    # On screen only the time of day; the full timestamp and the sha256 are in the log.
    hhmm=$rtime
    if [[ $rtime =~ (^|[^0-9])([01]?[0-9]|2[0-3]):([0-5][0-9]) ]]; then
      printf -v hhmm '%02d:%s' "$(( 10#${BASH_REMATCH[2]} ))" "${BASH_REMATCH[3]}"
    fi
    BK_KIND=ok; BK_DETAIL="ACB confirmed at Netgate $hhmm"
    ACB_DONE=1
    return 0
  fi
  # The remote list failed or did not show this backup: fall back to the upload marker.
  log_line "ACB confirm: listed=${listed:-?} remote_match=${match:-?}"
  remote "cat $marker"
  mark=$(r_first)
  if (( R_CODE == 0 )) && [[ -n $rev && $mark == "$rev" ]]; then
    log_line "OK: ACB upload reported success (not verified remotely), sha256 $sha"
    BK_KIND=warn; BK_DETAIL="ACB upload reported success $U_MID not verified remotely"
    ACB_DONE=1
    return 0
  fi
  fail 'ACB upload FAILED - see Status > System Logs > System (Unable to resolve / An error occurred...)'
  return 0
}

# A failed local export: show the error, drop the temp file, and let the caller return 1
# (the backup choice then offers another option).
export_fail() {
  fail "$1"
  if [[ -n $TMP_FILE ]]; then rm -f "$TMP_FILE"; TMP_FILE=''; fi
  ui_step_end fail ''     # the failed attempt stays visible as an ✗ Backup line (no-op before the step)
}

# Native export, identical to the GUI Download button (Diagnostics > Backup & Restore) with the
# GUI defaults. The only question is whether to encrypt. Saves to Downloads under the GUI file name.
# Returns 0 when the file is saved and verified, 1 on any failure (error already shown).
export_backup() {
  local enc=0 pw1='' pw2='' b64='' e=0 code l i first name size rsha renc actual dir path root
  local -a data=()

  if read_yes_no 'Encrypt this configuration file? [y/N]'; then
    enc=1; e=1
    read -rs -p "${UI_LEAD}Password: " pw1 || pw1=''
    printf '\n'
    if (( UI_FRAME )); then ui_blank; fi
    read -rs -p "${UI_LEAD}Confirm password: " pw2 || pw2=''
    printf '\n'
    if (( UI_FRAME )); then ui_blank; fi
    if [[ -z $pw1 || $pw1 != "$pw2" ]]; then
      pw1=''; pw2=''
      { export_fail 'Supplied password and confirmation do not match.'; return 1; }
    fi
    b64=$(printf '%s' "$pw1" | base64 | tr -d '\n')
    pw1=''; pw2=''
  fi

  code="\$e=$e; $EXPORT_PHP"
  ui_step_begin Backup 'exporting the configuration'
  REMOTE_QUIET=1
  if (( enc )); then
    remote_secret "php -r '$code'" "$b64" 120
  else
    remote "php -r '$code'" 120
  fi
  REMOTE_QUIET=0
  b64=''
  if (( R_CODE != 0 )); then
    log_line "export: failed on the firewall (exit $R_CODE); output not logged"
    for l in "${R_OUT[@]+"${R_OUT[@]}"}"; do
      if [[ $l == ERROR=* ]]; then ui_say fail "${l#ERROR=}"; fi   # screen only, never logged
    done
    { export_fail 'backup: the export on the firewall failed'; return 1; }
  fi

  name=''; size=''; rsha=''; renc=''; first=-1
  for i in "${!R_OUT[@]}"; do
    l=${R_OUT[i]}
    case $l in
      NAME=*)      name=${l#NAME=} ;;
      SIZE=*)      size=${l#SIZE=} ;;
      SHA256=*)    rsha=${l#SHA256=} ;;
      ENCRYPTED=*) renc=${l#ENCRYPTED=}; first=$(( i + 1 )); break ;;
    esac
  done
  rsha=${rsha,,}
  if (( first < 0 )) || [[ ! $name =~ ^[A-Za-z0-9._-]+$ || ! $size =~ ^[0-9]+$ || ! $rsha =~ ^[0-9a-f]{64}$ || ! $renc =~ ^[01]$ ]]; then
    { export_fail 'backup: unexpected export output from the firewall'; return 1; }
  fi
  if [[ $renc != "$e" ]]; then { export_fail 'backup: the encryption setting of the export does not match'; return 1; }; fi
  data=("${R_OUT[@]:first}")
  if (( ${#data[@]} == 0 )); then { export_fail 'backup: the export from the firewall is empty'; return 1; }; fi

  downloads_dir
  dir=$DL_DIR
  mkdir -p "$dir" || { export_fail "backup: cannot create $dir"; return 1; }
  # The temp file lives in the target folder so the final mv is an atomic rename.
  TMP_FILE=$(mktemp "$dir/.pfnetbird-backup-XXXXXX") || { export_fail "backup: cannot create a temp file in $dir"; return 1; }

  if ! printf '%s\n' "${data[@]}" | base64 -d >"$TMP_FILE" 2>/dev/null; then
    { export_fail 'backup: the data received from the firewall is not valid base64'; return 1; }
  fi

  actual=$(sha256sum "$TMP_FILE")
  actual=${actual%% *}
  actual=${actual,,}
  if [[ $actual != "$rsha" ]]; then { export_fail 'backup: SHA-256 of the received export does not match the firewall'; return 1; }; fi

  if (( enc )); then
    if ! grep -aq -e '---- BEGIN config.xml ----' "$TMP_FILE" || ! grep -aq -e '---- END config.xml ----' "$TMP_FILE"; then
      { export_fail 'backup: the export is not a valid encrypted config.xml'; return 1; }
    fi
  else
    # Root element check: DTDs refused, first element must be <pfsense>, and it must be closed.
    if grep -aqi '<!DOCTYPE' "$TMP_FILE"; then { export_fail 'backup: config.xml is not a valid <pfsense> document'; return 1; }; fi
    root=$(grep -a -o -m1 '<[A-Za-z_][^[:space:]>/]*' "$TMP_FILE" || true)
    root=${root%%$'\n'*}
    if [[ $root != '<pfsense' ]] || ! grep -aq '</pfsense>' "$TMP_FILE"; then
      { export_fail 'backup: config.xml is not a valid <pfsense> document'; return 1; }
    fi
  fi

  path="$dir/$name"
  mv -f "$TMP_FILE" "$path" || { export_fail "backup: cannot write $path"; return 1; }
  TMP_FILE=''
  CTX_BACKUP=$path
  BACKUP_SHA=$actual
  BACKUP_SIZE=$(trim "$(wc -c <"$path")")
  if (( enc )); then BACKUP_ENC=yes; else BACKUP_ENC=no; fi
  backup_summary
  ui_step_end ok "$BK_DETAIL"
  return 0
}

# The end of the ui_stage texts that name the backup: after Skip no backup exists, so none is claimed.
bk_taken() { if (( BACKUP_SKIPPED )); then printf 'No backup was taken.'; else printf 'A backup was taken first.'; fi; }
bk_restore() { if (( BACKUP_SKIPPED )); then printf 'No backup was taken.'; else printf 'Restore from the backup taken above.'; fi; }

# Backup choice, used for "Backup only" and before install, update, uninstall and auto-update Enable/Change schedule/Disable.
# $1 = install|update|downgrade|uninstall|manual backup (the ACB reason). Sets BACKUP_DONE=1 when every chosen
# part succeeded, 0 when the user chose Back (the caller then cancels). A failed part, or ACB not
# available, shows the choice again. End of input counts as Back. With $2 = skip (before install,
# update, reinstall, uninstall and auto-update Enable, Change schedule and Disable) the list has 4) Skip (no backup), which sets BACKUP_DONE=1 without a backup.
take_backup() {
  local what=$1 allow_skip=${2:-} back=4 opt acb_ok loc_ok
  if [[ $allow_skip == skip ]]; then back=5; fi
  BACKUP_DONE=0
  BACKUP_SKIPPED=0
  while :; do
    # Same list in and out of a frame, like the other submenus (one line per item).
    info ''
    info 'Backup'
    info ' 1) Local only (Downloads)'
    info ' 2) ACB cloud only'
    info ' 3) Both'
    if [[ $allow_skip == skip ]]; then info ' 4) Skip (no backup)'; fi
    info " $back) Back"
    read -r -p "${UI_LEAD}Enter an option: " opt || { opt=$back; info ''; }
    opt=$(trim "$opt")
    if [[ -n $opt ]]; then log_line "menu: backup option $opt selected"; fi
    if [[ $opt == "$back" ]]; then return 0; fi
    if [[ $allow_skip == skip && $opt == 4 ]]; then
      log_line 'WARNING: Backup skipped: no backup was taken'
      ui_step_line warn Backup skipped 0
      BACKUP_DONE=1
      BACKUP_SKIPPED=1
      return 0
    fi
    case $opt in
      '') continue ;;
      1|2|3) ;;
      *) info 'Invalid option.'; continue ;;
    esac

    acb_ok=1; loc_ok=1
    # Both: local first (read-only on the box), then ACB (it does write_config).
    if [[ $opt == 1 || $opt == 3 ]]; then
      if ! export_backup; then loc_ok=0; fi
    fi
    if [[ $opt == 2 || $opt == 3 ]]; then
      if (( ! loc_ok )); then
        info 'ACB backup skipped: the local part failed.'
      else
        acb_preflight
        if (( ACB_OK )); then log_line "$ACB_TXT"; else info "$ACB_TXT"; fi   # an ok state is the Backup step
        if (( ! ACB_OK )); then
          if [[ $opt == 2 ]]; then continue; fi
          acb_ok=0
        else
          acb_backup "$what"
          if (( ! ACB_DONE )); then acb_ok=0; fi
        fi
      fi
      if [[ $opt == 3 ]] && (( loc_ok && ! acb_ok )); then
        info "The local backup is saved: $CTX_BACKUP"
        info 'Choose 2) ACB cloud only to retry the ACB part.'
      fi
    fi

    if (( acb_ok && loc_ok )); then BACKUP_DONE=1; return 0; fi
    if (( ! loc_ok )); then warn 'Backup failed: local export'; fi
    if (( ! acb_ok )); then warn 'Backup failed: ACB cloud backup'; fi
    info 'Choose another option, or Back to cancel.'
  done
}

# ---------------------------------------------------------------------------
# Packages on the box
# ---------------------------------------------------------------------------
# get_remote_package <var-prefix>: download, verify SHA-256, check ABI.
# Sets PKG_PATH. The package ABI values go to the log.
get_remote_package() {
  local prefix=$1 v name url digest remote_path got pkg_abi pkg_major pkg_arch box_arch _a _b t0
  v="${prefix}_NAME"; name=${!v}
  v="${prefix}_URL";  url=${!v}
  v="${prefix}_DIGEST"; digest=${!v}
  remote_path="$REMOTE_DIR/$name"

  DOWNLOADED=1
  UI_SN=Download; t0=$SECONDS
  remote_step "download $name" "mkdir -p $REMOTE_DIR && fetch -q -o $remote_path '$url'" 300
  DL_T=$(( DL_T + SECONDS - t0 ))

  UI_SN=Verify; t0=$SECONDS
  remote_step "checksum $name" "sha256 -q $remote_path"
  got=$(r_first)
  got=${got,,}
  if [[ $got != "${digest,,}" ]]; then
    remote "rm -f $remote_path"
    die "SHA-256 mismatch for $name: expected $digest, got $got. File deleted."
  fi

  remote_step "read package ABI $name" "pkg query -F $remote_path '%q'"
  pkg_abi=$(r_first)
  if [[ ! $pkg_abi =~ ^[Ff]ree[Bb][Ss][Dd]:([0-9]+|\*):(.+)$ ]]; then
    die "unexpected package ABI '$pkg_abi' in $name"
  fi
  pkg_major=${BASH_REMATCH[1]}
  pkg_arch=${BASH_REMATCH[2]}
  IFS=: read -r _a _b box_arch <<<"$BOX_ABI"
  if [[ $pkg_arch != '*' && $pkg_arch != "$box_arch" ]]; then
    die "package $name is for $pkg_abi but the box is $BOX_ABI (architecture mismatch)"
  fi
  log_line "package ABI: $name is $pkg_abi, the box is $BOX_ABI"
  if [[ $pkg_major != '*' ]] && (( 10#$pkg_major > BOX_MAJOR )); then
    die "package $name is for $pkg_abi, newer than the box ($BOX_ABI)"
  fi
  VF_T=$(( VF_T + SECONDS - t0 ))
  PKG_PATH=$remote_path
}

install_packages() {
  remote_step 'install netbird' "pkg add -f $1" 300
  remote_step 'install pfSense-pkg-NetBird' "pkg add -f $2" 300
}

# Verifies the packages and the binary. Result in INSTALLED_VER.
assert_installed() {
  remote_step 'verify netbird package' 'pkg info -e netbird'
  remote_step 'verify pfSense-pkg-NetBird package' 'pkg info -e pfSense-pkg-NetBird'
  remote_step 'verify netbird version' 'netbird version'
  INSTALLED_VER=$(r_last)
}

# Result in IDENT_SNAP (empty if there was nothing to snapshot).
save_identity() {
  local stamp=$1 snap="/root/pfnetbird-identity-$1.json"
  IDENT_SNAP=''; IDENT_DETAIL='snapshot saved on the firewall'
  remote_step 'snapshot NetBird identity' \
    "if [ -f $IDENTITY_FILE ]; then cp -p $IDENTITY_FILE $snap && echo copied; else echo none; fi"
  if [[ $(r_last) == copied ]]; then
    CTX_IDENTITY=$snap
    IDENT_SNAP=$snap
    log_line "OK: Identity snapshot: $snap (on the firewall)"
    return 0
  fi
  IDENT_DETAIL='no identity file to snapshot'
  log_line 'No NetBird identity file to snapshot.'
}

# pkg add of pfSense-pkg-NetBird runs the OLD package's deinstall (deletes config.json), and the new
# package's post-install starts NetBird with a NEW identity. So: stop NetBird, compare the private key
# of the snapshot with the current file (never printed) and restore it if it is missing or different.
# The caller restarts NetBird afterwards.
restore_identity_if_missing() {
  local snap=$1 pat='"PrivateKey": *"[^"]*"' r
  log_line 'step: stop NetBird before the identity check'
  REMOTE_QUIET=1
  remote 'timeout 60 netbird service stop </dev/null >/dev/null 2>&1' 90
  REMOTE_QUIET=0
  if [[ -z $snap ]]; then return 0; fi
  REMOTE_QUIET=1
  remote "if [ ! -f $IDENTITY_FILE ] || { [ -n \"\$(grep -o '$pat' $snap)\" ] && [ \"\$(grep -o '$pat' $snap)\" != \"\$(grep -o '$pat' $IDENTITY_FILE)\" ]; }; then mkdir -p /var/db/netbird && cp -p $snap $IDENTITY_FILE && chmod 600 $IDENTITY_FILE && echo restored; else echo unchanged; fi"
  REMOTE_QUIET=0
  r=$(r_last)
  if (( R_CODE != 0 )); then
    warn "NetBird identity could not be restored — snapshot kept at $snap (on the firewall)"
  elif [[ $r == restored ]]; then
    warn 'The package install had replaced the NetBird identity; restored it from the snapshot.'
  else
    log_line 'identity unchanged'
  fi
}

# NetBird package settings (installedpackages/netbird) are unset by the old package's deinstall.
# Saved to a root-only file before pkg add, restored after (default), then deleted.
PKGCFG_SAVE_PHP='require_once("config.inc"); $c=config_get_path("installedpackages/netbird"); if (is_array($c) && !empty($c)) { $f="@FILE@"; file_put_contents($f, serialize($c)); chmod($f, 0600); echo "SAVED=1\n"; } else { echo "SAVED=0\n"; }'
PKGCFG_RESTORE_PHP='require_once("config.inc"); $s=@unserialize((string)@file_get_contents("@FILE@"), ["allowed_classes"=>false]); if (!is_array($s) || empty($s)) { echo "RESTORE=none\n"; exit(0); } if (!config_read_file(true, false)) { echo "RESTORE=reread-failed\n"; exit(1); } $cur=config_get_path("installedpackages/netbird"); if (!is_array($cur) || empty($cur) || $cur != $s) { config_set_path("installedpackages/netbird", $s); $w=write_config("pfnetbird: restore NetBird package settings-NoReMoTeBaCkUp"); echo "RESTORE=".(is_array($w)?"restored":"failed")."\n"; } else { echo "RESTORE=unchanged\n"; }'

# Result in PKGCFG_FILE (empty if there were no settings).
save_pkgcfg() {
  local code l saved=''
  PKGCFG_FILE=''
  code=${PKGCFG_SAVE_PHP//@FILE@//root/pfnetbird-pkgcfg-$1.ser}
  REMOTE_QUIET=1
  remote "php -r '$code'" 60
  REMOTE_QUIET=0
  for l in "${R_OUT[@]+"${R_OUT[@]}"}"; do
    case $l in SAVED=*) saved=${l#SAVED=} ;; esac
  done
  if (( R_CODE != 0 )) || [[ ! $saved =~ ^[01]$ ]]; then die 'cannot save the NetBird package settings before the update'; fi
  if [[ $saved == 1 ]]; then PKGCFG_FILE=/root/pfnetbird-pkgcfg-$1.ser; log_line 'NetBird package settings saved'; fi
}

restore_pkgcfg() {
  local code l res=''
  if [[ -z ${PKGCFG_FILE:-} ]]; then return 0; fi
  code=${PKGCFG_RESTORE_PHP//@FILE@/$PKGCFG_FILE}
  REMOTE_QUIET=1
  remote "php -r '$code'" 60
  REMOTE_QUIET=0
  for l in "${R_OUT[@]+"${R_OUT[@]}"}"; do
    case $l in RESTORE=*) res=${l#RESTORE=} ;; esac
  done
  log_line "NetBird package settings: ${res:-?}"
  case $res in
    restored)  warn 'The package install had removed the NetBird package settings; restored them.'; remote "rm -f $PKGCFG_FILE" ;;
    unchanged|none) remote "rm -f $PKGCFG_FILE" ;;
    *) warn "The NetBird package settings could not be restored; they are saved in $PKGCFG_FILE (on the firewall). Check VPN > NetBird." ;;
  esac
}

# Returns 0 if "Management: Connected" is seen within the timeout, 1 otherwise.
wait_netbird_connected() {
  local timeout=${1:-30} start=$SECONDS out l
  while (( SECONDS - start < timeout )); do
    REMOTE_QUIET=1
    remote 'netbird status'
    REMOTE_QUIET=0
    out=''
    for l in "${R_OUT[@]+"${R_OUT[@]}"}"; do out+="$l"$'\n'; done
    if [[ $out =~ [Mm]anagement:[[:space:]]*[Cc]onnected ]]; then return 0; fi
    sleep 3
  done
  return 1
}

# ---------------------------------------------------------------------------
# Branches (these end the script with exit)
# ---------------------------------------------------------------------------
# One guide line printed after the frame has closed (logged as is, wrapped on screen, hanging under the
# list marker). Used by show_post_install_steps through print_netbird_steps pns_after.
pns_after() {
  local w l
  log_line "$1"
  ui_map w "$1"
  ui_wrap w "$w" auto '' ''
  while IFS= read -r l; do ui_after "$l"; done <<<"$w"
}

# The configuration steps after an install, following NetBird's pfSense guide.
print_netbird_steps() {
  local say=${1:-info}   # info (inside the frame) or pns_after (after the frame closes)
  $say '  1. VPN > NetBird: enter the Management URL and the setup key, then Save.'
  $say '       Management URL: https://app.netbird.io:443 (default) or your self-hosted server.'
  $say '  2. Status > NetBird: verify the connection status (peers and control services).'
  $say '  3. Interfaces > Assignments (wt0 appears after step 1): under "Available network ports" select wt0, then Add.'
  $say '  4. Interfaces > OPT<n> (the new interface): check Enable Interface, set Description to NetBird, then Save and Apply Changes.'
  $say '  5. Firewall > Rules > NetBird tab: Add a rule, Action Pass, Interface NetBird, Protocol Any, Source Any, Destination Any, Description "Allow all on NetBird (managed by NetBird)". Save and Apply Changes.'
  $say '       NetBird access policies (ACLs) then control what traffic is allowed.'
  $say '  6. Static port for direct (non-relayed) connections. The guide lists this under "Config for Troubleshooting Relayed Connections"; do it if peers connect through a relay:'
  $say '       a. Firewall > NAT > Outbound: choose Hybrid Outbound NAT rule generation, then Save.'
  $say '       b. Add a rule at the top: Interface WAN, Address Family IPv4, Protocol UDP, Source Network = this firewall'"'"'s NetBird IP, Destination Any, check Static Port, Description "NetBird Static Port". Save and Apply Changes.'
  $say '       c. Diagnostics > States: filter by the NetBird IP, then click Kill.'
  $say '       d. Run `netbird service restart`, then `netbird status -d`.'
  $say '          Already done by this script after the install; repeat after configuring.'
  $say 'Guide: https://docs.netbird.io/get-started/install/pfsense'
}

# Last thing an install prints: after the frame has closed and after `netbird status -d`, just before
# "Press Enter" (twin: Show-PostInstallSteps).
show_post_install_steps() {
  log_line ''
  log_line 'NetBird is installed. Remaining steps in the pfSense web UI:'
  ui_after ''
  ui_after 'Next in the pfSense web UI:'
  print_netbird_steps pns_after
}

# Downloads both packages, asks, and sets CPATH/UPATH. Question text in QUESTION.
prepare_packages() {
  local intro=$1 cpath upath dl
  DL_T=0; VF_T=0
  dl="netbird $REL_CL_VER + pfSense-pkg-NetBird $REL_UI_VER"
  ui_step_begin Download "$dl"
  get_remote_package REL_CL; cpath=$PKG_PATH
  get_remote_package REL_UI; upath=$PKG_PATH
  CPATH=$cpath; UPATH=$upath
  QUESTION=$intro
  UI_SN=Download
  ui_step_end ok "$dl" "$DL_T"
  ui_step_line ok Verify 'SHA-256 match' "$VF_T"
  UI_TOTAL=$(( UI_TOTAL + VF_T ))
}

# Path, size, encryption and sha256 of the local export just taken (end of export_backup).
backup_summary() {
  log_line "OK: Backup saved:  $CTX_BACKUP"
  log_line "Backup size:   $BACKUP_SIZE bytes"
  log_line "Encrypted:     $BACKUP_ENC"
  log_line "Backup sha256: $BACKUP_SHA"
  # On screen one short step line; the path, size and sha256 are in the log only.
  local _bh
  fmt_home _bh "$DL_DIR"
  ui_sanitize _bh "$_bh"
  BK_DETAIL="Local saved to $_bh, encrypted $BACKUP_ENC"
}

# Dry runs (menu): the read-only ACB preflight and the plan of what a Run would do; nothing is
# written on the firewall.
dry_pkg() {
  # dry_pkg <var-prefix> <label>
  local p=$1 v name url digest
  v="${p}_NAME"; name=${!v}
  v="${p}_URL"; url=${!v}
  v="${p}_DIGEST"; digest=${!v}
  info "     $2"
  info "       asset:        $name"
  info '       download URL:'
  info "         $url"
  info '       sha256:'
  info "         $digest"
  info "       target path:  $REMOTE_DIR/$name"
}

# Read-only ACB preflight line plus the backup line of every plan.
dry_backup_line() {
  acb_preflight
  info "$ACB_TXT"
  info 'DRY RUN — backup: would ask for backup: Local / ACB / Both / Skip / Back'
  info ''
}

# Plan for install or update (no uninstall section), nothing is written. When NetBird is already up
# to date the plan is the reinstall (what the menu Run does).
dry_install_plan() {
  local n=0 stamp

  stamp='<yyyyMMdd-HHmmss>'
  info 'DRY RUN — would do:'
  n=$(( n + 1 ))
  info "  $n. Create $REMOTE_DIR on the firewall and download both packages with fetch:"
  dry_pkg REL_CL 'netbird client'
  dry_pkg REL_UI 'pfSense-pkg-NetBird'
  n=$(( n + 1 ))
  info "  $n. Verify each downloaded file against the sha256 above; delete it and stop on a mismatch."
  n=$(( n + 1 ))
  if is_downgrade; then
    info "  $n. Downgrade from $NB_CLIENT to $REL_CL_VER: ask for confirmation (y/N), then would ask for backup: Local / ACB / Both / Skip / Back."
  else
    info "  $n. Ask for confirmation (y/N), then would ask for backup: Local / ACB / Both / Skip / Back."
  fi
  if (( NB_INSTALLED )); then
    n=$(( n + 1 ))
    info "  $n. Snapshot the NetBird identity if present: cp -p $IDENTITY_FILE /root/pfnetbird-identity-$stamp.json"
  fi
  n=$(( n + 1 ))
  info "  $n. pkg add -f $REMOTE_DIR/$REL_CL_NAME"
  n=$(( n + 1 ))
  info "  $n. pkg add -f $REMOTE_DIR/$REL_UI_NAME"
  if (( NB_INSTALLED )); then
    n=$(( n + 1 ))
    info "  $n. Restore $IDENTITY_FILE from the snapshot if it is missing after the update."
    n=$(( n + 1 ))
    info "  $n. netbird service restart"
  fi
  n=$(( n + 1 ))
  info "  $n. Verify: pkg info -e netbird, pkg info -e pfSense-pkg-NetBird, netbird version."
  if (( ! NB_INSTALLED )); then
    n=$(( n + 1 ))
    info "  $n. netbird service restart (a failed restart is only a warning)."
  fi
  if (( NB_INSTALLED )); then
    REMOTE_QUIET=1
    remote 'netbird status'
    REMOTE_QUIET=0
    n=$(( n + 1 ))
    if [[ "${R_OUT[*]+"${R_OUT[*]}"}" == *NeedsLogin* ]]; then
      info "  $n. NetBird is not logged in yet (no setup key): no wait for \"Management: Connected\"."
    else
      info "  $n. Wait up to 30 s for \"Management: Connected\" in netbird status."
    fi
  fi
  n=$(( n + 1 ))
  info "  $n. Show netbird status -d on screen only (not logged; a non-zero exit is shown, not treated as failure)."
  n=$(( n + 1 ))
  info "  $n. Remove $REMOTE_DIR from the firewall and close the session."
  if (( ! NB_INSTALLED )); then
    info ''
    info 'After a real install, the remaining steps in the pfSense web UI would be:'
    print_netbird_steps
  fi
}

# Uninstall prerequisite check, read-only. Is wt0 assigned as a pfSense interface, and do rules
# reference that interface? Sets UN_ASSIGNED, UN_IF, UN_DESC, UN_FW, UN_NAT, UN_ONAT. The detail
# (interface name, description) goes to the screen only; the log gets booleans.
UN_CHECK_PHP='require_once("config.inc"); $a=0; $n0=""; $d0=""; foreach (config_get_path("interfaces", array()) as $n=>$i) { if (isset($i["if"]) && $i["if"]==="wt0") { $a=1; $n0=$n; $d0=isset($i["descr"])?$i["descr"]:""; break; } } echo "ASSIGNED=".$a.PHP_EOL; if ($a) { echo "IFNAME=".$n0.PHP_EOL; echo "DESCR=".$d0.PHP_EOL; $c=array("FW"=>"filter/rule","NAT"=>"nat/rule","ONAT"=>"nat/outbound/rule"); foreach ($c as $k=>$p) { $m=0; foreach (config_get_path($p, array()) as $r) { if (isset($r["interface"]) && in_array($n0, explode(",", $r["interface"]))) { $m++; } } echo $k."=".$m.PHP_EOL; } }'

uninstall_check() {
  local l k v
  UN_ASSIGNED=0; UN_IF=''; UN_DESC=''; UN_FW=0; UN_NAT=0; UN_ONAT=0
  REMOTE_QUIET=1
  remote "php -r '$UN_CHECK_PHP'" 60
  REMOTE_QUIET=0
  if (( R_CODE != 0 )); then die 'cannot check whether wt0 is assigned as a pfSense interface (php check failed)'; fi
  local seen=0
  for l in "${R_OUT[@]+"${R_OUT[@]}"}"; do
    l=${l%$'\r'}
    k=${l%%=*}; v=${l#*=}
    case $k in
      ASSIGNED) if [[ $v == 0 || $v == 1 ]]; then UN_ASSIGNED=$v; seen=1; fi ;;
      IFNAME)   UN_IF=$v ;;
      DESCR)    UN_DESC=$v ;;
      FW)       if [[ $v =~ ^[0-9]+$ ]]; then UN_FW=$v; fi ;;
      NAT)      if [[ $v =~ ^[0-9]+$ ]]; then UN_NAT=$v; fi ;;
      ONAT)     if [[ $v =~ ^[0-9]+$ ]]; then UN_ONAT=$v; fi ;;
    esac
  done
  if (( ! seen )); then die 'cannot check whether wt0 is assigned as a pfSense interface (no ASSIGNED line)'; fi
  ui_sanitize UN_IF "$UN_IF"; ui_sanitize UN_DESC "$UN_DESC"   # remote strings, display only
  log_line "uninstall check: wt0 assigned=$UN_ASSIGNED; firewall rules=$(( UN_FW > 0 )); nat rules=$(( UN_NAT > 0 )); outbound nat=$(( UN_ONAT > 0 ))"
}

dry_uninstall() {
  info ''
  info 'DRY RUN — uninstall plan (NetBird is installed):'
  info '  1. Check whether wt0 is assigned as a pfSense interface (read-only, result below).'
  uninstall_check
  LOG_MUTE=1
  if (( UN_ASSIGNED )); then
    info "  wt0 is assigned as pfSense interface '$UN_IF' (description: ${UN_DESC:-none})"
    info "  firewall rules on it: $UN_FW, NAT rules: $UN_NAT, outbound NAT rules: $UN_ONAT"
  else
    info '  wt0 is not assigned as a pfSense interface.'
  fi
  LOG_MUTE=0
  if (( UN_ASSIGNED )); then
    info '  The uninstall would STOP here: remove the rules and the wt0 assignment in the pfSense UI first.'
    return 0
  fi
  info '  2. Ask for confirmation (y/N).'
  info '  3. would ask for backup: Local / ACB / Both / Skip / Back'
  auto_read
  if [[ $AU_READ != 1 ]]; then
    info '  3a. auto-update state unreadable (cannot tell whether it is on)'
  elif auto_present; then
    info "  3a. would remove auto-update: the cron job (Removed cron job for $AUTO_CMD) and $AUTO_DIR"
  fi
  info '  4. would stop: netbird service stop (a non-zero exit is only a warning)'
  info '  5. would pkg delete: pkg delete -y pfSense-pkg-NetBird netbird'
  info '  6. would verify: pkg info -e netbird and pkg info -e pfSense-pkg-NetBird must both report not installed'
}

do_uninstall() {
  local left='' ver=$NB_CLIENT auto_on=0 extra='' ifn='' tab=''
  ui_begin "Uninstall NetBird $ver"
  ui_stage 'NetBird was not changed.'
  ui_step_begin Check 'wt0 interface assignment'
  uninstall_check
  if (( UN_ASSIGNED )); then
    if [[ -n $UN_IF ]]; then ifn=" (${UN_IF^^})"; fi
    tab=${UN_DESC:-${UN_IF^^}}
    ui_step_end fail "wt0 is assigned as a pfSense interface$ifn"
    LOG_MUTE=1
    ui_blank
    info 'Removing the package now would leave a missing interface, and pfSense can stop at boot with an interface mismatch.'
    info 'Remove these in the pfSense web UI first, then try again:'
    if [[ -n $tab ]]; then
      info "  1. Firewall $U_GT Rules $U_GT $tab: the rules on the NetBird interface"
    else
      info "  1. Firewall $U_GT Rules: the rules on the NetBird interface"
    fi
    info "  2. Interfaces $U_GT Assignments: the wt0 assignment"
    if (( UN_NAT > 0 )); then info "  (also found: $UN_NAT NAT rule(s) on that interface, Firewall $U_GT NAT)"; fi
    if (( UN_ONAT > 0 )); then info "  (also found: $UN_ONAT outbound NAT rule(s) on that interface, Firewall $U_GT NAT $U_GT Outbound)"; fi
    ui_blank
    LOG_MUTE=0
    log_line 'uninstall stopped: wt0 assigned'
    ui_close '' 'NetBird was not changed.'
    exit 2
  fi
  ui_step_end ok 'wt0 is not assigned as a pfSense interface'

  # Auto-update is removed together with NetBird (one confirmation, one backup).
  auto_read
  if [[ $AU_READ != 1 ]]; then
    warn 'cannot read the auto-update state, so it is not known whether auto-update is on.'
    if ! read_yes_no 'Continue the uninstall anyway? A left-over auto-update would only report "NetBird is not installed". [y/N]'; then
      info 'Cancelled. Nothing was changed.'
      UI_FAILT=''
      exit 0
    fi
  elif auto_present; then
    auto_on=1
    info "Auto-update is on ($(auto_word)); it is removed too."
    extra=" The auto-update cron job and $AUTO_DIR are removed too."
  fi

  info 'The NetBird identity on this box is removed; a reinstall needs a new setup key.'
  if ! read_yes_no "Uninstall NetBird $ver?$extra [y/N]"; then info 'Cancelled. Nothing was changed.'; UI_FAILT=''; exit 0; fi

  auto_guard
  take_backup uninstall skip
  if (( ! BACKUP_DONE )); then info 'Cancelled — NetBird was not changed'; UI_FAILT=''; exit 0; fi
  ui_blank

  if (( auto_on )); then
    ui_step_begin Auto-update 'removing the cron job and the runner'
    auto_remove_all
    log_line 'OK: Auto-update removed (cron job and runner directory).'
    ui_step_end ok 'cron job and runner directory removed'
    ui_stage 'Auto-update was removed; NetBird is still installed.'
  fi

  ui_stage "NetBird may be stopped or partly removed. $(bk_taken)"
  ui_step_begin Stop 'netbird service stop'
  log_line 'step: stop NetBird'
  remote 'netbird service stop >/dev/null 2>&1' 120
  if (( R_CODE != 0 )); then
    warn "netbird service stop exited with code $R_CODE; continuing (the service may already be stopped)."
  fi
  ui_step_end ok 'netbird service stop'

  # One call with both names, as NetBird's guide says. pfSense-pkg-NetBird depends on netbird, so pkg
  # removes the GUI package first; its pre-deinstall hook runs while the client still exists.
  ui_stage "NetBird may be stopped or partly removed. $(bk_taken)"
  ui_step_begin Remove 'pkg delete'
  log_line 'step: pkg delete'
  remote 'pkg delete -y pfSense-pkg-NetBird netbird' 300
  if (( R_CODE != 0 )); then
    warn "pkg delete exited with code $R_CODE; checking what is left."
  fi
  ui_step_end ok 'pkg delete pfSense-pkg-NetBird netbird'

  ui_step_begin Verify 'pkg info'
  remote 'pkg info -e netbird'
  if (( R_CODE == 0 )); then left+=' netbird'; fi
  remote 'pkg info -e pfSense-pkg-NetBird'
  if (( R_CODE == 0 )); then left+=' pfSense-pkg-NetBird'; fi
  if [[ -n $left ]]; then
    fail "Uninstall failed. Still installed:$left"
    ui_step_end fail ''
    ui_stage 'Uninstall failed; NetBird is still partly installed.'
    exit 2
  fi
  ui_step_end ok 'both packages are gone'
  log_line 'OK: NetBird uninstalled'
  info 'The package removes its own pfSense settings (installedpackages/netbird), /var/db/netbird/config.json and its interface-mismatch patch.'
  info 'You can check in the pfSense UI that no NetBird config is left. This script deletes no config.'
  info 'The peer is still listed in the NetBird dashboard; remove it there if you want.'
  ui_close ok "NetBird uninstalled in ${UI_TOTAL}s."
  exit 0
}

# Shows `netbird status -d` on screen only. The output (peer names, IPs, public keys) is never
# logged: REMOTE_QUIET keeps it out of the log, which gets the command and exit code only.
# A non-zero exit (for example not logged in yet) is information, never a failure.
show_netbird_status_detail() {
  local l
  log_line ''
  log_line 'netbird status -d:'
  ui_after ''
  ui_after 'netbird status -d:'
  REMOTE_QUIET=1
  remote 'netbird status -d' 60
  REMOTE_QUIET=0
  for l in "${R_OUT[@]+"${R_OUT[@]}"}"; do ui_after "$l"; done   # after the frame closes, never logged
  if (( R_CODE != 0 )); then
    log_line "netbird status -d exited with code $R_CODE (for example: not logged in yet). Not an error."
    ui_after "netbird status -d exited with code $R_CODE (for example: not logged in yet). Not an error."
  fi
}

do_install() {
  ui_begin "Install NetBird $REL_CL_VER"
  ui_stage 'NetBird was not changed.'
  prepare_packages "Install NetBird $REL_CL_VER?"
  ui_blank
  if ! read_yes_no "$QUESTION [y/N]"; then info 'Cancelled. Nothing was changed.'; UI_FAILT=''; exit 0; fi

  take_backup install skip
  if (( ! BACKUP_DONE )); then info 'Cancelled — NetBird was not changed'; UI_FAILT=''; exit 0; fi
  ui_blank
  ui_stage "NetBird may be partly installed. $(bk_taken)"
  ui_step_begin Install 'pkg add'
  install_packages "$CPATH" "$UPATH"
  assert_installed
  log_line "OK: Installed: $INSTALLED_VER"
  ui_step_end ok "pkg add $U_MID netbird $INSTALLED_VER"
  ui_stage 'NetBird is installed, but the restart step failed. Check the firewall.'
  ui_step_begin Restart 'netbird service restart'
  log_line 'step: restart NetBird'
  remote 'netbird service restart >/dev/null 2>&1' 120
  if (( R_CODE != 0 )); then
    warn "netbird service restart exited with code $R_CODE; continuing (not configured yet?)."
  fi
  ui_step_end ok 'netbird service restart'
  show_netbird_status_detail
  show_post_install_steps
  ui_close ok "Installed NetBird $REL_CL_VER in ${UI_TOTAL}s."
  exit 0
}

# Header of an install-over-installed job: "Reinstall NetBird X" when the installed client already is
# that version, "Downgrade NetBird" when the picked release is older, else "Update NetBird X → Y".
update_title() {
  if is_downgrade; then
    printf 'Downgrade NetBird'
  elif is_same_version; then
    printf 'Reinstall NetBird %s' "$REL_CL_VER"
  else
    printf 'Update NetBird %s %s %s' "$NB_CLIENT" "$U_ARR" "$REL_CL_VER"
  fi
}

# is_same_version: true if the picked release (REL_CL_VER) equals the installed client (version_cmp, so 0.80 is 0.80.0).
is_same_version() {
  version_cmp "$NB_CLIENT" "$REL_CL_VER"
  (( VCMP == 0 ))
}

# is_downgrade: true if the picked release (REL_CL_VER) is numerically older than the installed client.
is_downgrade() {
  if (( ! NB_INSTALLED )); then return 1; fi
  version_cmp "$NB_CLIENT" "$REL_CL_VER"
  (( VCMP > 0 ))
}

do_update() {
  local snap up=0 stamp same=0 needs_login=0 word verb=Updated
  if is_downgrade; then verb=Downgraded; fi
  ui_begin "$(update_title)"
  ui_stage 'NetBird was not changed.'
  prepare_packages "Update from $NB_CLIENT to $REL_CL_VER?"
  same=0
  if is_same_version; then same=1; QUESTION="Reinstall NetBird $REL_CL_VER?"; fi
  # An older release than the installed one: the one confirm question warns about the downgrade.
  if is_downgrade; then QUESTION="Downgrade NetBird from $NB_CLIENT to $REL_CL_VER?"; fi
  ui_blank
  if ! read_yes_no "$QUESTION [y/N]"; then info 'Cancelled. Nothing was changed.'; UI_FAILT=''; exit 0; fi

  auto_guard
  # The ACB reason names a downgrade too ("pfnetbird: before downgrade"), by the same compare as the title.
  if is_downgrade; then take_backup downgrade skip; else take_backup update skip; fi
  if (( ! BACKUP_DONE )); then info 'Cancelled — NetBird was not changed'; UI_FAILT=''; exit 0; fi
  # Read-only, before anything changes: NeedsLogin means there is no setup key yet, so there is nothing to wait for.
  REMOTE_QUIET=1
  remote 'netbird status'
  REMOTE_QUIET=0
  if [[ "${R_OUT[*]+"${R_OUT[*]}"}" == *NeedsLogin* ]]; then needs_login=1; fi
  ui_blank
  stamp=$(date +%Y%m%d-%H%M%S)
  ui_step_begin Identity 'snapshot of the NetBird identity and settings'
  save_identity "$stamp"
  snap=$IDENT_SNAP
  save_pkgcfg "$stamp"
  ui_step_end ok "$IDENT_DETAIL"
  ui_stage "NetBird may be partly changed. $(bk_restore)"
  ui_step_begin Install 'pkg add'
  install_packages "$CPATH" "$UPATH"
  restore_identity_if_missing "$snap"
  restore_pkgcfg
  ui_step_end ok "pkg add $U_MID identity and settings kept"
  ui_stage "$verb, but the restart step failed. Check NetBird on the firewall."
  ui_step_begin Restart 'netbird service restart'
  remote_step 'restart NetBird' 'netbird service restart >/dev/null 2>&1' 120
  assert_installed
  ui_step_end ok 'netbird service restart'
  if (( needs_login )); then
    show_netbird_status_detail
    if (( same )); then word="Reinstalled NetBird $REL_CL_VER."; else word="$verb to $REL_CL_VER."; fi
    log_line "OK: $word NetBird is not logged in yet (no setup key)."
    if [[ -n $snap ]]; then
      info "$snap (on the firewall) holds the NetBird private identity. Delete it from the firewall once NetBird is verified."
    fi
    ui_close ok "$word NetBird is not logged in yet (no setup key)."
    exit 0
  fi
  log_line "Installed: $INSTALLED_VER. Waiting up to 30 s for the management connection..."
  ui_stage "$verb, but the connection check did not finish."
  ui_step_begin Connect 'waiting for Management: Connected'
  if wait_netbird_connected 30; then up=1; fi
  if (( up )); then
    ui_step_end ok 'Management: Connected'
  else
    ui_step_end warn 'Management: Connected was not seen within 30 s'
  fi
  show_netbird_status_detail
  if (( up )); then
    if (( same )); then log_line "OK: Reinstalled NetBird $REL_CL_VER."; else log_line "OK: $verb to $REL_CL_VER. Management: Connected."; fi
    # A successful manual update clears a failed auto-update attempt (it would otherwise block the runner).
    remote "rm -f $AUTO_DIR/last-result $AUTO_DIR/paused-* $AUTO_DIR/identity-*.json"
    if [[ -n $snap ]]; then
      info "$snap (on the firewall) holds the NetBird private identity. Delete it from the firewall once NetBird is verified."
    fi
    if (( same )); then ui_close ok "Reinstalled NetBird $REL_CL_VER in ${UI_TOTAL}s."
    else ui_close ok "$verb to $REL_CL_VER in ${UI_TOTAL}s. Management: Connected."; fi
    exit 0
  fi
  log_line "WARNING: $verb, but \"Management: Connected\" was not seen within 30 s. Check \`netbird status\` on the firewall."
  ui_close fail "$verb to $REL_CL_VER, but not connected."
  exit 2
}

# ---------------------------------------------------------------------------
# Auto-update (cron on the firewall)
# ---------------------------------------------------------------------------
# pfnetbird deploys a small PHP runner to /root/pfnetbird and adds ONE job to pfSense's own cron
# config (install_cron_job). Settings live inside the runner file, never in the cron command, so
# the command never changes and install_cron_job always updates instead of duplicating.
# PHP run on the box. No single quotes inside: each is wrapped in php -r '...'. Nothing secret.
# Read: our cron job(s), runner sha256 (with the version string of the define() line replaced by @VERSION@, so a
# version bump alone does not change it), time zone, identity snapshots, last-result file.
AUTO_READ_PHP='require_once("config.inc"); $r="/root/pfnetbird/pfnetbird-auto.php"; $n=0; foreach ((array)config_get_path("cron/item", []) as $i) { if (strpos((string)$i["command"], $r) === false) { continue; } $n++; if ($n == 1) { foreach (["minute"=>"MIN","hour"=>"HOUR","mday"=>"MDAY","month"=>"MONTH","wday"=>"WDAY"] as $k=>$v) { echo $v."=".$i[$k]."\n"; } echo "EXACT=".(((string)$i["command"] === "/usr/bin/nice -n20 /usr/local/bin/php -f ".$r)?1:0)."\n"; } } echo "JOBS=".$n."\n"; echo "DIR=".(is_dir("/root/pfnetbird")?1:0)."\n"; echo "RUNNER_SHA=".(is_file($r)?hash("sha256",preg_replace("/^define\\(\\x27PFNB_RUNNER_VERSION\\x27, \\x27[^\\x27]*\\x27\\);$/m","define(\x27PFNB_RUNNER_VERSION\x27, \x27@VERSION@\x27);",file_get_contents($r))):"")."\n"; echo "TZ=".date("T")."\n"; $g=glob("/root/pfnetbird/identity-*.json"); echo "SNAPS=".(is_array($g)?count($g):0)."\n"; $f=@file("/root/pfnetbird/last-result", FILE_IGNORE_NEW_LINES); if (is_array($f)) { foreach ($f as $l) { echo "LAST_".$l."\n"; } } echo "READ=1\n";'
# Runner upload: base64 on stdin (remote_payload), written to a .tmp file first.
AUTO_WRITE_PHP='$d=base64_decode(trim(file_get_contents("php://stdin")), true); $t="/root/pfnetbird/pfnetbird-auto.php.tmp"; if (!is_string($d) || $d === "" || @file_put_contents($t, $d) !== strlen($d)) { echo "WRITE=0\n"; exit(1); } chmod($t, 0600); echo "WRITE=1\n";'
# Apply: prefixed with $m, $h, $d, $w. install_cron_job adds the job or updates it in place (no write when unchanged).
AUTO_APPLY_PHP='require_once("config.inc"); require_once("services.inc"); $c="/usr/bin/nice -n20 /usr/local/bin/php -f /root/pfnetbird/pfnetbird-auto.php"; install_cron_job($c, true, $m, $h, $d, "*", $w, "root"); $n=0; foreach ((array)config_get_path("cron/item", []) as $i) { if ((string)$i["command"] === $c && (string)$i["minute"] === $m && (string)$i["hour"] === $h && (string)$i["mday"] === $d && (string)$i["month"] === "*" && (string)$i["wday"] === $w) { $n++; } } echo "APPLIED=".$n."\n"; $t=@file_get_contents("/etc/crontab"); echo "CRONTAB=".((is_string($t) && strpos($t, "/root/pfnetbird/pfnetbird-auto.php") !== false)?1:0)."\n";'
# Remove every job with the exact command (at most 10 loops), then count what still mentions the runner.
AUTO_REMOVE_PHP='require_once("config.inc"); require_once("services.inc"); $r="/root/pfnetbird/pfnetbird-auto.php"; $c="/usr/bin/nice -n20 /usr/local/bin/php -f ".$r; $x=0; for ($k=0; $k<10; $k++) { $f=0; foreach ((array)config_get_path("cron/item", []) as $i) { if (strpos((string)$i["command"], $c) !== false) { $f=1; break; } } if (!$f) { break; } install_cron_job($c, false); $x++; } $n=0; foreach ((array)config_get_path("cron/item", []) as $i) { if (strpos((string)$i["command"], $r) !== false) { $n++; } } echo "REMOVED=".$x."\n"; echo "LEFT=".$n."\n";'

# The runner. The placeholder @VERSION@ is substituted by auto_runner_build.
# Quoted here-doc: nothing in it is expanded. Do not use any other @...@ token inside.
IFS= read -r -d '' RUNNER_PHP <<'PFNB_RUNNER' || true
<?php
/*
 * pfnetbird-auto.php - unattended NetBird update on pfSense, run by pfSense cron.
 * Deployed and maintained by pfnetbird (menu: Auto-update). Do not edit: pfnetbird checks its sha256.
 * Newer stable release -> download + SHA-256 + ABI check -> ACB backup confirmed at Netgate ->
 * pkg add -f (both) -> netbird service restart -> wait for "Management: Connected".
 * Prints nothing. Writes /root/pfnetbird/auto.log and /root/pfnetbird/last-result, reports via the
 * GUI notices. Never logs the ACB device key, the ACB password, config content or netbird status output.
 */
define('PFNB_RUNNER_VERSION', '@VERSION@');
define('PFNB_DIR', '/root/pfnetbird');
define('PFNB_LOG', PFNB_DIR . '/auto.log');
define('PFNB_STATE', PFNB_DIR . '/last-result');
define('PFNB_LOCK', '/tmp/pfnetbird-auto.lock');
define('PFNB_BUSY', '/tmp/pfnetbird-client.busy');
define('PFNB_API', 'https://api.github.com/repos/netbirdio/pfsense-netbird/releases/latest');
define('PFNB_URL_PREFIX', 'https://github.com/netbirdio/pfsense-netbird/releases/download/');
define('PFNB_IDENTITY', '/var/db/netbird/config.json');
define('PFNB_LOG_MAX', 262144);

ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('error_log', PFNB_LOG);
ini_set('zend.exception_ignore_args', '1');
putenv('PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin');
putenv('HTTP_USER_AGENT=pfnetbird-auto/' . PFNB_RUNNER_VERSION);
umask(077);

$RUN = date('Ymd-His');
$TMP = '';
$FROM = '';
$TO = '';
$DONE = false;      /* set by pfnb_finish; a started run that ends without it crashed */
$STARTED = false;
$SNAP = '';         /* identity snapshot of this run while it exists */
$STOPPED = false;   /* NetBird was stopped by this run and not yet restarted */
$OBTAIL = '';       /* the last 4 KB pfSense code printed (pfnb_ob); nothing else of the output is kept */
$OBN = 0;           /* bytes pfSense code printed in all */
$ACB_DBG = file_exists('/tmp/acb_debug.txt');   /* acb.inc may leave this file behind; it is removed at the end, never read */

function pfnb_log($m) {
	@file_put_contents(PFNB_LOG, date('Y-m-d H:i:s') . ' [' . $GLOBALS['RUN'] . '] ' . $m . "\n", FILE_APPEND);
}

/* Runs a stock command. Output stays in memory; only pfnb_tail() ever logs part of it. */
function pfnb_sh($cmd, &$out = null) {
	$out = [];
	$rc = 0;
	exec($cmd . ' 2>&1', $out, $rc);
	return $rc;
}

function pfnb_tail($out, $n) {
	foreach (array_slice((array)$out, -$n) as $l) {
		pfnb_log('  | ' . substr((string)$l, 0, 200));
	}
}

/* Last lines of a command output file (package messages, no secrets). */
function pfnb_tail_file($f, $n) {
	$l = @file($f, FILE_IGNORE_NEW_LINES);
	if (is_array($l)) { pfnb_tail($l, $n); }
}

/* After a restart NetBird must run. "service netbird status" checks the daemon(8) supervisor by its pidfile
 * /var/run/netbird.pid; if it is not running, start it once more. rc.subr and daemon -P refuse a start while
 * the pidfile is held, so this never starts a second daemon. Restart and start run under timeout --foreground:
 * without it FreeBSD timeout(1) is the reaper of all descendants, waits for the new daemon and kills it at expiry. */
function pfnb_ensure_running() {
	if (pfnb_sh('timeout 20 service netbird status </dev/null >/dev/null 2>&1') == 0) { return; }
	pfnb_log('netbird is not running after the restart; starting it once more');
	pfnb_log('netbird service start: exit ' . pfnb_sh('timeout --foreground 120 netbird service start </dev/null >/dev/null 2>&1'));
}

/* The NetBird private key of an identity file, or null. Compared only, never logged. */
function pfnb_pk($f) {
	$j = @json_decode((string)@file_get_contents($f), true);
	return (is_array($j) && isset($j['PrivateKey']) && is_string($j['PrivateKey']) && $j['PrivateKey'] !== '') ? $j['PrivateKey'] : null;
}

/* The values that must never reach the log: the ACB password, the ACB device key (the one in the config and
 * the legacy one derived from the SSH host key; get_acb_device_key() is not called, it can write the config)
 * and the NetBird private key, each also in its white-space-collapsed form (as pfnb_piece collapses the text),
 * values under 4 bytes left out, longest first (so a shorter one inside a longer one cannot break its mask).
 * null when they cannot be read. */
function pfnb_secrets() {
	$x = [];
	try {
		if (function_exists('config_get_path')) {
			foreach (['system/acb/encryption_password', 'system/acb/device_key'] as $k) { $x[] = config_get_path($k); }
		}
		if (function_exists('get_acb_legacy_device_key')) { $x[] = get_acb_legacy_device_key(); }
		$x[] = pfnb_pk(PFNB_IDENTITY);
		if ($GLOBALS['SNAP'] !== '') { $x[] = pfnb_pk($GLOBALS['SNAP']); }
	} catch (Throwable $e) {
		return null;
	}
	$r = [];
	foreach ($x as $v) {
		if (!is_string($v)) { continue; }
		foreach ([$v, trim(preg_replace('/[\x00-\x20\x7f]+/', ' ', $v))] as $w) {
			if (strlen($w) >= 4 && !in_array($w, $r, true)) { $r[] = $w; }
		}
	}
	usort($r, function ($a, $b) { return strlen($b) - strlen($a); });
	return $r;
}

/* One piece of an error text for the log. The secrets are masked FIRST, then the piece is cut, so a cut never
 * splits a secret. The raw text is masked, control characters and runs of white space become one space, and it
 * is masked again (the collapse can rebuild a secret that holds white space printed differently). $open names
 * the edge where $s itself was cut from a longer text ('head': $s is the start of it, so its end is open; 'tail':
 * its start is open; '': $s is whole). A secret can straddle that edge, so then that edge of the collapsed text
 * is dropped by the length of the longest secret. Last the piece is cut to $len bytes, keeping the side $keep
 * ('head' or 'tail'). */
function pfnb_piece($s, $open, $keep, $len) {
	$x = pfnb_secrets();
	if ($x === null) { return 'the error text was not logged (it could not be checked for secrets)'; }
	$s = (string)$s;
	$m = 0;
	foreach ($x as $v) { $s = str_replace($v, '***', $s); $m = max($m, strlen($v)); }
	$s = trim(preg_replace('/[\x00-\x20\x7f]+/', ' ', $s));
	foreach ($x as $v) { $s = str_replace($v, '***', $s); }
	if ($m > 0 && $open === 'head') { $s = rtrim((string)substr($s, 0, max(0, strlen($s) - $m))); }
	if ($m > 0 && $open === 'tail') { $s = ltrim((string)substr($s, $m)); }
	if (strlen($s) > $len) { $s = $keep === 'tail' ? '...' . substr($s, -$len) : substr($s, 0, $len) . '...'; }
	return $s;
}

/* One log line from a whole error text: masked, one line, capped at $max bytes. */
function pfnb_clean($s, $max = 400) {
	return pfnb_piece($s, '', 'head', $max);
}

/* Output handler of ob_start(): keeps only the last 4 KB of what pfSense code prints (raw: pfnb_why masks it
 * before it cuts it), counts the bytes, prints nothing. With a chunk size the buffer is handed over every
 * 4 KB, so the output never piles up in memory. */
function pfnb_ob($buf, $phase) {
	$GLOBALS['OBN'] += strlen($buf);
	$GLOBALS['OBTAIL'] = substr($GLOBALS['OBTAIL'] . substr($buf, -4096), -4096);
	return '';
}

/* Why a started run ended without pfnb_finish: the last fatal PHP error, else the last bytes that pfSense
 * code printed before it called exit or die (pfnb_ob), and the last PHP warning or notice if any. Bounded:
 * each part is taken raw at 4 KB at most, masked, then cut (message 300, file 100, output 300 bytes). */
function pfnb_why() {
	$names = [E_ERROR => 'PHP Fatal error', E_PARSE => 'PHP Parse error', E_CORE_ERROR => 'PHP Core error',
	          E_COMPILE_ERROR => 'PHP Compile error', E_USER_ERROR => 'PHP User error', E_RECOVERABLE_ERROR => 'PHP Recoverable error'];
	$e = error_get_last();
	$last = '';
	if (is_array($e)) {
		$msg = (string)$e['message'];
		$file = (string)$e['file'];
		$last = pfnb_piece(substr($msg, 0, 4096), strlen($msg) > 4096 ? 'head' : '', 'head', 300)
		      . ' in ' . pfnb_piece(substr($file, -1024), strlen($file) > 1024 ? 'tail' : '', 'tail', 100) . ':' . (int)$e['line'];
	}
	if (is_array($e) && isset($names[$e['type']])) { $t = $names[$e['type']] . ': ' . $last; }
	else {
		$cur = ob_get_level() > 0 ? (string)ob_get_contents() : '';
		$n = $GLOBALS['OBN'] + strlen($cur);
		$raw = substr($GLOBALS['OBTAIL'] . substr($cur, -4096), -4096);
		$out = $n > 0 ? pfnb_piece($raw, $n > strlen($raw) ? 'tail' : '', 'tail', 300) : '';
		$t = $out !== '' ? 'exit with output: ' . $out : 'exit without a message';
		if ($last !== '') { $t .= '; last PHP message (type ' . (int)$e['type'] . '): ' . $last; }
	}
	return strlen($t) > 400 ? substr($t, 0, 400) . '...' : $t;   /* every part is masked already */
}

function pfnb_ver($raw) {
	$v = preg_replace('/[_,].*$/', '', trim((string)$raw));
	return preg_match('/^[0-9]+(\.[0-9]+){1,3}$/', $v) ? $v : null;
}

function pfnb_last() {
	$r = ['RESULT' => '', 'TO' => ''];
	$f = @file(PFNB_STATE, FILE_IGNORE_NEW_LINES);
	if (is_array($f)) {
		foreach ($f as $l) {
			$p = explode('=', $l, 2);
			if (count($p) == 2) { $r[$p[0]] = $p[1]; }
		}
	}
	return $r;
}

/* Writes last-result (atomic). */
function pfnb_state($result, $detail) {
	global $FROM, $TO;
	$s = 'TIME=' . date('Y-m-d H:i:s') . "\n" . 'RESULT=' . $result . "\n" . 'DETAIL=' . $detail . "\n"
	   . 'FROM=' . $FROM . "\n" . 'TO=' . $TO . "\n" . 'RUNNER=' . PFNB_RUNNER_VERSION . "\n";
	if (@file_put_contents(PFNB_STATE . '.tmp', $s) !== false) { @rename(PFNB_STATE . '.tmp', PFNB_STATE); }
}

/* Ends the run. $prio: -1 no notice, 0 info, 1 warning, 2 error.
 * $dedup: notice only when RESULT or TO differs from the previous run (conditions that repeat daily).
 * A success notice (prio 0) is local only: no mail / Telegram / Pushover for it. */
function pfnb_finish($result, $detail, $prio, $dedup = false) {
	global $TO, $DONE;
	$DONE = true;
	$detail = str_replace(["\r", "\n"], ' ', $detail);
	$last = pfnb_last();
	pfnb_log('result=' . $result . ' ' . $detail);
	pfnb_state($result, $detail);
	if ($prio >= 0 && !($dedup && $last['RESULT'] === $result && $last['TO'] === $TO)) {
		file_notice('pfnetbird', 'pfnetbird auto-update: ' . $detail, 'pfnetbird', '', $prio, $prio == 0);
	}
	exit(($result === 'updated' || $result === 'uptodate') ? 0 : 1);
}

/* Shutdown: a started run that never reached pfnb_finish crashed or was killed on an error. */
function pfnb_cleanup() {
	global $TMP, $DONE, $STARTED, $SNAP, $ACB_DBG, $STOPPED;
	if ($STARTED && !$DONE) {
		$d = 'the run ended unexpectedly (PHP error); check ' . PFNB_LOG . ($SNAP !== '' && file_exists($SNAP) ? '. Identity snapshot kept: ' . $SNAP : '');
		if ($STOPPED) {   /* do not leave the tunnel down */
			pfnb_log('netbird service restart after the crash: exit ' . pfnb_sh('timeout --foreground 120 netbird service restart </dev/null >/dev/null 2>&1'));
			pfnb_ensure_running();
		}
		pfnb_log('result=failed-crash ' . $d);
		pfnb_state('failed-crash', $d);
		file_notice('pfnetbird', 'pfnetbird auto-update: ' . $d, 'pfnetbird', '', 2);
	}
	if (!$ACB_DBG && file_exists('/tmp/acb_debug.txt')) { @unlink('/tmp/acb_debug.txt'); }
	if ($TMP !== '' && strpos($TMP, '/tmp/pfnetbird-auto.') === 0) {
		pfnb_sh('rm -rf ' . escapeshellarg($TMP));
	}
	/* Last, after the restart, last-result and the notice: finding the cause must not stop those. */
	if ($STARTED && !$DONE) { pfnb_log('crash cause: ' . pfnb_why()); }
	while (ob_get_level() > 0) { ob_end_clean(); }   /* the runner prints nothing itself; a crash text is in the log */
}

function pfnb_asset($j, $re) {
	foreach ((array)($j['assets'] ?? []) as $a) {
		$n = (string)($a['name'] ?? '');
		if (!preg_match($re, $n, $m)) { continue; }
		$u = (string)($a['browser_download_url'] ?? '');
		$d = (string)($a['digest'] ?? '');
		$v = pfnb_ver($m[1]);
		if (!preg_match('/^[A-Za-z0-9._+-]+$/', $n) || strpos($u, PFNB_URL_PREFIX) !== 0 || strpos($u, "'") !== false
		    || !preg_match('/^sha256:([0-9a-fA-F]{64})$/', $d, $dm) || $v === null) {
			return null;
		}
		return ['name' => $n, 'url' => $u, 'sha' => strtolower($dm[1]), 'raw' => $m[1], 'ver' => $v];
	}
	return null;
}

/* ---- 0. Log size, lock, client busy marker, includes, boot, clock ---- */
if (!is_dir(PFNB_DIR)) { exit(1); }
clearstatcache();
if (@filesize(PFNB_LOG) > PFNB_LOG_MAX) { @rename(PFNB_LOG, PFNB_LOG . '.1'); }
$lockfh = @fopen(PFNB_LOCK, 'ce');   /* e: close-on-exec, so children (netbird service) do not inherit the lock */
if ($lockfh === false || !flock($lockfh, LOCK_EX | LOCK_NB)) { pfnb_log('another run holds the lock; exiting'); exit(0); }
register_shutdown_function('pfnb_cleanup');
ob_start('pfnb_ob', 4096);   /* keeps the last bytes pfSense code prints before an exit or die, for the crash log line */
if (file_exists(PFNB_BUSY) && time() - filemtime(PFNB_BUSY) < 3600) { pfnb_log('a pfnetbird change is in progress; exiting'); exit(0); }

require_once('config.inc');
require_once('util.inc');
require_once('notices.inc');
require_once('acb.inc');

if (function_exists('is_platform_booting') && is_platform_booting()) { pfnb_log('system is booting; exiting'); exit(0); }
$STARTED = true;
pfnb_log('start: runner ' . PFNB_RUNNER_VERSION);
pfnb_main();

/* The run is a function, so none of its variables is a PHP global. pfSense code reads globals such as $g
 * (g_get(), lock(), the config paths) and $config. Up to 0.20.1 the run was top-level code and its
 * $g = glob(...) replaced pfSense's $g, so config_read_file() then looked for /config.xml and died. */
function pfnb_main() {
	global $RUN, $TMP, $FROM, $TO, $DONE, $SNAP, $STOPPED;
try {   /* body not re-indented, so the diff to 0.20.1 stays readable */
	if (time() < mktime(0, 0, 0, 1, 1, 2025)) {
		pfnb_finish('failed-clock', 'the system clock is not plausible (' . date('Y-m-d') . '); nothing was changed', 1, true);
	}

	/* ---- 1. NetBird must be installed: auto-update only updates ---- */
	if (pfnb_sh('pkg info -e netbird') != 0) {
		pfnb_finish('skipped-not-installed', 'NetBird is not installed; auto-update only updates. Disable it in pfnetbird (Auto-update > Disable).', 1, true);
	}
	pfnb_sh('pkg query %v netbird', $o);
	$FROM = trim((string)($o[0] ?? ''));
	$inst = pfnb_ver($FROM);
	if ($inst === null) { pfnb_finish('failed-internal', 'cannot read the installed netbird version; nothing was changed', 2, true); }

	/* ---- 2. Box ABI and architecture (as pfnetbird.sh get_box_info) ---- */
	pfnb_sh('pkg config ABI', $o);
	$box_abi = trim((string)($o[0] ?? ''));
	if (!preg_match('/^freebsd:([0-9]+):(.+)$/i', $box_abi, $m)) { pfnb_finish('failed-internal', 'unexpected package ABI of the box; nothing was changed', 2, true); }
	$box_major = (int)$m[1];
	$box_arch = $m[2];
	pfnb_sh('uname -p', $o);
	$u = trim((string)($o[0] ?? ''));
	if ($u === 'amd64') { $arch = 'x86_64'; }
	elseif ($u === 'arm64' || $u === 'aarch64') { $arch = 'aarch64'; }
	else { pfnb_finish('failed-internal', 'unsupported architecture ' . $u . '; nothing was changed', 2, true); }

	/* ---- 3. Latest stable release (fetch, no token) ---- */
	$TMP = '/tmp/pfnetbird-auto.' . $RUN;
	if (!@mkdir($TMP, 0700)) { $TMP = ''; pfnb_finish('failed-internal', 'cannot create the temp directory; nothing was changed', 2, true); }
	$rc = pfnb_sh('fetch -q -T 30 -o ' . escapeshellarg($TMP . '/release.json') . ' ' . escapeshellarg(PFNB_API), $o);
	if ($rc != 0) { pfnb_tail($o, 2); pfnb_finish('failed-lookup', 'the GitHub release lookup failed (fetch exit ' . $rc . '); nothing was changed', 1, true); }
	$j = json_decode((string)@file_get_contents($TMP . '/release.json'), true);
	$tag = is_array($j) ? (string)($j['tag_name'] ?? '') : '';
	if (!preg_match('/^[A-Za-z0-9._-]+$/', $tag) || !empty($j['draft']) || !empty($j['prerelease'])) {
		pfnb_finish('failed-lookup', 'the GitHub response has no usable stable release; nothing was changed', 1, true);
	}
	$cl = pfnb_asset($j, '/^netbird-(.+)-' . $arch . '\.pkg$/');
	$ui = pfnb_asset($j, '/^pfSense-pkg-NetBird-(.+)-' . $arch . '\.pkg$/');
	if ($cl === null || $ui === null) { pfnb_finish('failed-lookup', 'release ' . $tag . ' has no usable package for ' . $arch . '; nothing was changed', 1, true); }
	$TO = $cl['raw'];

	/* ---- 4. Compare: the client version decides, as in pfnetbird.sh ---- */
	if (version_compare($inst, $cl['ver'], '>=')) {
		/* Up to date: a left-over snapshot of an update that did connect is stale. Remove it only when NetBird is connected. */
		$sn = glob(PFNB_DIR . '/identity-*.json');
		if (is_array($sn) && count($sn) > 0) {
			pfnb_sh('timeout 20 netbird status </dev/null', $o);
			if (preg_match('/management:\s*connected/i', implode("\n", (array)$o)) === 1) {
				foreach ($sn as $f) { @unlink($f); }
				pfnb_log('stale identity snapshot removed');
			}
			$o = [];
		}
		foreach ((array)glob(PFNB_DIR . '/paused-*') as $f) { @unlink($f); }
		pfnb_finish('uptodate', 'netbird ' . $FROM . ' is up to date (release ' . $tag . ')', -1);
	}
	pfnb_log('update available: netbird ' . $FROM . ' -> ' . $TO . ' (release ' . $tag . ')');
	/* A failed attempt for this version (or a kept identity snapshot) blocks further runs: no new ACB backup
	 * every night. last-result is left untouched so the block stays; Disable + Enable in pfnetbird clears it. */
	$snaps = glob(PFNB_DIR . '/identity-*.json');
	$lr = pfnb_last();
	if ((is_array($snaps) && count($snaps) > 0)
	    || ($lr['TO'] === $TO && in_array($lr['RESULT'], ['failed-pkg', 'failed-acb', 'failed-snapshot', 'failed-crash', 'failed-internal', 'updated-not-connected'], true))) {
		pfnb_log('skipped: previous failure for ' . $TO . ' (Disable and Enable auto-update in pfnetbird to clear it)');
		$mk = PFNB_DIR . '/paused-' . $TO;   /* one notice per version */
		if (!file_exists($mk)) {
			@touch($mk);
			file_notice('pfnetbird', 'pfnetbird auto-update paused for ' . $TO . ' - run Disable and Enable in pfnetbird to clear', 'pfnetbird', '', 1);
		}
		$DONE = true;
		exit(0);
	}

	/* ---- 5. Download, SHA-256, ABI. Nothing is changed yet ---- */
	$paths = [];
	foreach ([$cl, $ui] as $p) {
		$path = $TMP . '/' . $p['name'];
		$rc = pfnb_sh('fetch -q -T 60 -o ' . escapeshellarg($path) . ' ' . escapeshellarg($p['url']), $o);
		if ($rc != 0) { pfnb_tail($o, 2); pfnb_finish('failed-download', 'download of ' . $p['name'] . ' failed (fetch exit ' . $rc . '); nothing was changed', 2); }
		pfnb_sh('sha256 -q ' . escapeshellarg($path), $o);
		if (strtolower(trim((string)($o[0] ?? ''))) !== $p['sha']) {
			@unlink($path);
			pfnb_finish('failed-checksum', 'SHA-256 mismatch for ' . $p['name'] . '; file deleted; nothing was changed', 2);
		}
		pfnb_sh('pkg query -F ' . escapeshellarg($path) . ' %q', $o);
		$pabi = trim((string)($o[0] ?? ''));
		if (!preg_match('/^freebsd:([0-9]+|\*):(.+)$/i', $pabi, $pm)) { pfnb_finish('failed-download', 'unexpected package ABI in ' . $p['name'] . '; nothing was changed', 2); }
		if ($pm[2] !== '*' && $pm[2] !== $box_arch) {
			pfnb_finish('skipped-abi', $p['name'] . ' is for ' . $pabi . ' but the box is ' . $box_abi . ' (architecture); not updated', 1, true);
		}
		if ($pm[1] !== '*' && (int)$pm[1] > $box_major) {
			pfnb_finish('skipped-abi', $p['name'] . ' is for ' . $pabi . ', newer than the box (' . $box_abi . '); not updated', 1, true);
		}
		pfnb_log('package ABI: ' . $p['name'] . ' is ' . $pabi . ', the box is ' . $box_abi);
		$paths[] = $path;
	}

	/* ---- 6. ACB cloud backup like the GUI "Backup Now", confirmed at Netgate by sha256 ---- */
	if (!function_exists('acb_backup_stage_upload')) {
		pfnb_finish('failed-acb-preflight', 'this pfSense has the legacy ACB, which cannot confirm a backup at Netgate; not updated', 2, true);
	}
	if (config_get_path('system/acb/enable') != 'yes') {
		pfnb_finish('failed-acb-preflight', 'update ' . $FROM . ' -> ' . $TO . ' available, but ACB is disabled; not updated', 2, true);
	}
	if (strlen((string)config_get_path('system/acb/encryption_password')) == 0) {
		pfnb_finish('failed-acb-preflight', 'update ' . $FROM . ' -> ' . $TO . ' available, but ACB has no encryption password; not updated', 2, true);
	}
	$staged = glob(g_get('acbbackuppath') . '*.form');
	$pend = is_array($staged) ? count($staged) : 0;
	unset($staged);
	if (!config_read_file(true, false)) { pfnb_finish('failed-acb', 'cannot re-read config.xml before the ACB backup; not updated', 2); }   /* the in-memory config may be stale */
	touch('/tmp/forceacb');
	$w = write_config('pfnetbird: before auto-update to ' . $TO . ' (run ' . $RUN . ')-MaNuAlBaCkUp');
	if (!is_array($w)) { @unlink('/tmp/forceacb'); pfnb_finish('failed-acb', 'write_config for the ACB backup failed; not updated', 2); }
	unset($w);
	pfnb_sh('sha256 -q /cf/conf/config.xml', $o);
	$sha = strtolower(trim((string)($o[0] ?? '')));
	if (!preg_match('/^[0-9a-f]{64}$/', $sha)) { pfnb_finish('failed-acb', 'cannot hash config.xml; not updated', 2); }
	$form = g_get('acbbackuppath') . $sha . '.form';
	if (!file_exists($form)) { pfnb_finish('failed-acb', 'ACB did not stage the backup; not updated', 2); }
	pfnb_log('ACB: backup staged, uploading');
	pfnb_sh('nice -n20 php /usr/local/sbin/acbupload.php', $o);   /* returns at once if the minute cron holds /tmp/acb.lock */
	for ($i = 0; $i < 30 + 30 * $pend && file_exists($form); $i++) { sleep(3); clearstatcache(); }
	if (file_exists($form)) { pfnb_finish('failed-acb', 'the ACB upload did not finish in time; not updated', 2); }
	$k = get_acb_device_key();
	$rtime = '';
	for ($t = 0; $t < 3 && $rtime === '' && $k !== null; $t++) {
		if ($t > 0) { sleep(10); }
		$b = null;
		foreach ((array)acb_backup_list($k) as $e) {
			if (stripos((string)$e['reason'], '(run ' . $RUN . ')') === false) { continue; }
			if ($b === null || strtotime($e['time']) >= strtotime($b['time'])) { $b = $e; }
		}
		if ($b === null) { continue; }
		$q = acb_backup_get($k, $b['time']);
		$p = explode('++++', (string)$q[0], 2);
		if (strtolower(trim($p[0])) === $sha) {
			$rtime = trim((string)$b['localtime']) !== '' ? (string)$b['localtime'] : (string)$b['time'];
		}
	}
	unset($k, $q, $p, $b);
	if ($rtime === '') { pfnb_finish('failed-acb', 'the ACB backup could not be confirmed at Netgate; not updated', 2); }
	pfnb_log('ACB backup confirmed at Netgate: ' . $rtime . ', sha256 ' . substr($sha, 0, 12));

	/* ---- 7. Snapshot identity and package settings, pkg add, restore, restart, verify.
	 *         pkg add of pfSense-pkg-NetBird runs the OLD package's deinstall (deletes config.json and unsets
	 *         installedpackages/netbird), and the new package's post-install starts NetBird with a NEW identity.
	 *         So: stop, compare the identity by key and restore, restore the settings, then restart. ---- */
	$snap = '';
	if (file_exists(PFNB_IDENTITY)) {
		$snap = PFNB_DIR . '/identity-' . $RUN . '.json';
		if (pfnb_sh('cp -p ' . escapeshellarg(PFNB_IDENTITY) . ' ' . escapeshellarg($snap)) != 0) {
			pfnb_finish('failed-snapshot', 'cannot snapshot the NetBird identity; not updated (ACB backup ' . $rtime . ' was taken)', 2);
		}
		@chmod($snap, 0600);
		$SNAP = $snap;
	}
	$pkgcfg = config_get_path('installedpackages/netbird');
	$step = '';
	if (pfnb_sh('timeout 300 pkg add -f ' . escapeshellarg($paths[0]) . ' </dev/null >' . escapeshellarg($TMP . '/pkg.out') . ' 2>&1') != 0) { $step = 'pkg add netbird'; }
	elseif (pfnb_sh('timeout 300 pkg add -f ' . escapeshellarg($paths[1]) . ' </dev/null >' . escapeshellarg($TMP . '/pkg.out') . ' 2>&1') != 0) { $step = 'pkg add pfSense-pkg-NetBird'; }
	if ($step !== '') { pfnb_tail_file($TMP . '/pkg.out', 5); }
	$STOPPED = true;
	$rrc = pfnb_sh('timeout 60 netbird service stop </dev/null >/dev/null 2>&1');
	pfnb_log('netbird service stop: exit ' . $rrc);
	$extra = '';
	if ($snap !== '') {
		$spk = pfnb_pk($snap);
		if (!file_exists(PFNB_IDENTITY) || ($spk !== null && $spk !== pfnb_pk(PFNB_IDENTITY))) {
			@mkdir('/var/db/netbird', 0700, true);
			if (pfnb_sh('cp -p ' . escapeshellarg($snap) . ' ' . escapeshellarg(PFNB_IDENTITY)) != 0) {
				pfnb_finish('failed-snapshot', 'the NetBird identity could not be restored after the update ' . $FROM . ' -> ' . $TO . '. Identity snapshot kept: ' . $snap . '. ACB backup ' . $rtime . '.', 2);
			}
			@chmod(PFNB_IDENTITY, 0600);
			pfnb_log('identity restored');
			$extra .= ' Identity restored from the snapshot (the package install had replaced it).';
		} else {
			pfnb_log('identity unchanged');
		}
		unset($spk);
	}
	if (is_array($pkgcfg) && !empty($pkgcfg)) {
		$cres = 'unchanged';
		if (config_read_file(true, false)) {
			$cur = config_get_path('installedpackages/netbird');
			if (!is_array($cur) || empty($cur) || $cur != $pkgcfg) {
				config_set_path('installedpackages/netbird', $pkgcfg);
				$w = write_config('pfnetbird: restore NetBird package settings-NoReMoTeBaCkUp');
				$cres = is_array($w) ? 'restored' : 'restore-failed';
				unset($w);
			}
			unset($cur);
		} else {
			$cres = 'reread-failed';
		}
		pfnb_log('package settings ' . $cres);
		if ($cres === 'restored') { $extra .= ' NetBird package settings restored.'; }
		elseif ($cres !== 'unchanged') { $extra .= ' NetBird package settings could NOT be restored (' . $cres . '); check VPN > NetBird.'; }
	}
	unset($pkgcfg);
	/* Restart also after a failed pkg add, so the tunnel comes back with whatever is installed. */
	$rrc = pfnb_sh('timeout --foreground 120 netbird service restart </dev/null >/dev/null 2>&1');
	$STOPPED = false;
	pfnb_log('netbird service restart: exit ' . $rrc);
	pfnb_ensure_running();
	pfnb_sh('pkg query %v netbird', $o);
	$now_cl = trim((string)($o[0] ?? ''));
	if ($now_cl === '') { $now_cl = 'missing'; }
	pfnb_sh('pkg query %v pfSense-pkg-NetBird', $o);
	$now_ui = trim((string)($o[0] ?? ''));
	if ($now_ui === '') { $now_ui = 'missing'; }
	if ($step !== '' || pfnb_sh('pkg info -e netbird') != 0 || pfnb_sh('pkg info -e pfSense-pkg-NetBird') != 0) {
		pfnb_finish('failed-pkg', ($step !== '' ? $step . ' failed' : 'package verification failed') . ' during the update ' . $FROM . ' -> ' . $TO
			. '. Installed now: netbird ' . $now_cl . ', pfSense-pkg-NetBird ' . $now_ui . '. ACB backup ' . $rtime . '.' . $extra
			. ($snap !== '' ? ' Identity snapshot: ' . $snap . '.' : '') . ' Repair with pfnetbird > Install/Update.', 2);
	}
	$up = false;
	for ($i = 0; $i < 20 && !$up; $i++) {
		if ($i > 0) { sleep(3); }
		pfnb_sh('timeout 20 netbird status </dev/null', $o);
		$up = preg_match('/management:\s*connected/i', implode("\n", (array)$o)) === 1;
	}
	$o = [];
	if (!$up) {
		pfnb_finish('updated-not-connected', 'NetBird updated ' . $FROM . ' -> ' . $now_cl . ', but "Management: Connected" was not seen within 60 s; check Status > NetBird.'
			. ($snap !== '' ? ' Identity snapshot kept: ' . $snap . '.' : '') . ' ACB backup ' . $rtime . '.' . $extra, 2);
	}
	if ($snap !== '') { @unlink($snap); $SNAP = ''; }
	pfnb_finish('updated', 'NetBird updated ' . $FROM . ' -> ' . $now_cl . ' (release ' . $tag . '), Management: Connected. ACB backup ' . $rtime . '.' . $extra, 0);
} catch (Throwable $e) {
	pfnb_log('error: ' . pfnb_clean(get_class($e) . ': ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine()));
	pfnb_finish('failed-internal', 'unexpected ' . get_class($e) . '; see ' . PFNB_LOG, 2);
}
}
PFNB_RUNNER

AUTO_WDAYS=(Sunday Monday Tuesday Wednesday Thursday Friday Saturday)

# Builds the runner text. Sets RUNNER_TEXT, RUNNER_SHA, RUNNER_B64, RUNNER_TPL_SHA.
# printf '%s' everywhere: the bytes hashed are exactly the bytes sent. RUNNER_TPL_SHA is the sha256
# of the runner with the placeholder @VERSION@ left in: the box (AUTO_READ_PHP) hashes its runner
# with the version string in the define() line replaced by the same placeholder, so a runner that
# differs only in that string compares equal.
auto_runner_build() {
  RUNNER_TPL_SHA=$(printf '%s' "$RUNNER_PHP" | sha256sum)
  RUNNER_TPL_SHA=${RUNNER_TPL_SHA%% *}
  RUNNER_TEXT=${RUNNER_PHP//@VERSION@/$SCRIPT_VERSION}
  RUNNER_SHA=$(printf '%s' "$RUNNER_TEXT" | sha256sum)
  RUNNER_SHA=${RUNNER_SHA%% *}
  RUNNER_B64=$(printf '%s' "$RUNNER_TEXT" | base64 | tr -d '\n')
}

# Compares the runner on the box (AU_RUNNER_SHA, hashed with its version string normalised) with this
# script's runner template. Sets AU_RSTATE: missing | current | other. The version string is not
# compared (every version bump would otherwise show "runner differs"); any other byte difference, also
# a truncated or edited file, is "other": its cron job keeps running unchanged, and Change schedule
# redeploys the current runner.
auto_runner_state() {
  AU_RSTATE=other
  if [[ -z $AU_RUNNER_SHA ]]; then AU_RSTATE=missing; return 0; fi
  auto_runner_build
  if [[ $AU_RUNNER_SHA == "$RUNNER_TPL_SHA" ]]; then AU_RSTATE=current; fi
  return 0
}

# auto_sched_text <min> <hour> <mday> <month> <wday>: daily / weekly / monthly / custom, as text.
auto_sched_text() {
  local min=$1 hour=$2 mday=$3 month=$4 wday=$5 hhmm
  if [[ $min =~ ^[0-9]+$ && $hour =~ ^[0-9]+$ && $month == '*' ]]; then
    printf -v hhmm '%02d:%02d' "$(( 10#$hour ))" "$(( 10#$min ))"
    if [[ $mday == '*' && $wday == '*' ]]; then printf 'daily %s' "$hhmm"; return 0; fi
    if [[ $mday == '*' && $wday =~ ^[0-9]+$ ]]; then
      printf 'weekly %s %s' "${AUTO_WDAYS[$(( 10#$wday % 7 ))]}" "$hhmm"
      return 0
    fi
    if [[ $wday == '*' && $mday =~ ^[0-9]+$ ]]; then printf 'monthly day %s %s' "$(( 10#$mday ))" "$hhmm"; return 0; fi
  fi
  printf 'custom (%s %s %s %s %s)' "$min" "$hour" "$mday" "$month" "$wday"
}

# True when anything of auto-update is on the firewall: a job, the runner, or the directory.
auto_present() {
  (( ${AU_JOBS:-0} > 0 )) || [[ -n ${AU_RUNNER_SHA:-} ]] || [[ ${AU_HASDIR:-0} == 1 ]]
}

# Short state word for the menu: off | <schedule> | unknown.
auto_word() {
  if [[ ${AU_READ:-0} != 1 ]]; then printf 'unknown'; return 0; fi
  if (( ${AU_JOBS:-0} == 0 )); then printf 'off'; return 0; fi
  auto_sched_text "$AU_MIN" "$AU_HOUR" "$AU_MDAY" "$AU_MONTH" "$AU_WDAY"
}

# Reads the auto-update state of the box (read-only) into AU_*. A failure sets AU_READ=0 and never dies.
auto_read() {
  local l k v got=0
  AU_READ=0; AU_JOBS=0; AU_MIN=''; AU_HOUR=''; AU_MDAY=''; AU_MONTH=''; AU_WDAY=''; AU_EXACT=0
  AU_RUNNER_SHA=''; AU_TZ=''; AU_SNAPS=0; AU_LAST_TIME=''; AU_LAST_RESULT=''; AU_LAST_DETAIL=''; AU_LAST_TO=''; AU_HASDIR=0
  REMOTE_QUIET=1
  remote "php -r '$AUTO_READ_PHP'" 60
  REMOTE_QUIET=0
  for l in "${R_OUT[@]+"${R_OUT[@]}"}"; do
    l=${l%$'\r'}
    k=${l%%=*}; v=${l#*=}
    v=${v//[[:cntrl:]]/}
    case $k in
      MIN)         AU_MIN=$v ;;
      HOUR)        AU_HOUR=$v ;;
      MDAY)        AU_MDAY=$v ;;
      MONTH)       AU_MONTH=$v ;;
      WDAY)        AU_WDAY=$v ;;
      DIR)         if [[ $v == 1 ]]; then AU_HASDIR=1; fi ;;
      EXACT)       if [[ $v == 1 ]]; then AU_EXACT=1; fi ;;
      JOBS)        if [[ $v =~ ^[0-9]+$ ]]; then AU_JOBS=$(( 10#$v )); fi ;;
      RUNNER_SHA)  if [[ $v =~ ^[0-9a-f]{64}$ ]]; then AU_RUNNER_SHA=$v; fi ;;
      TZ)          if [[ $v =~ ^[A-Za-z0-9+-]{1,8}$ ]]; then AU_TZ=$v; fi ;;
      SNAPS)       if [[ $v =~ ^[0-9]+$ ]]; then AU_SNAPS=$(( 10#$v )); fi ;;
      LAST_TIME)   if [[ $v =~ ^[0-9:[:space:]-]+$ ]]; then AU_LAST_TIME=$v; fi ;;
      LAST_RESULT) if [[ $v =~ ^[A-Za-z0-9-]+$ ]]; then AU_LAST_RESULT=$v; fi ;;
      LAST_DETAIL) AU_LAST_DETAIL=$v ;;
      LAST_TO)     if [[ $v =~ ^[A-Za-z0-9._+-]+$ ]]; then AU_LAST_TO=$v; fi ;;
      READ)        if [[ $v == 1 ]]; then got=1; fi ;;
    esac
  done
  [[ $AU_MIN =~ ^[0-9*/,-]*$ ]] || AU_MIN='?'
  [[ $AU_HOUR =~ ^[0-9*/,-]*$ ]] || AU_HOUR='?'
  [[ $AU_MDAY =~ ^[0-9*/,-]*$ ]] || AU_MDAY='?'
  [[ $AU_MONTH =~ ^[0-9*/,-]*$ ]] || AU_MONTH='?'
  [[ $AU_WDAY =~ ^[0-9*/,-]*$ ]] || AU_WDAY='?'
  if (( R_CODE == 0 )) && [[ $got == 1 ]]; then AU_READ=1; fi
  auto_runner_state
  log_line "auto-update read: ok=$AU_READ jobs=$AU_JOBS runner=$AU_RSTATE"
}

# Stops the change when an auto-update run is in progress on the firewall, then marks this client
# busy so the runner skips. The marker is removed by remote_cleanup_job and by disconnect_remote.
auto_guard() {
  # Marker first, then the lock check: a run that starts in between sees the marker and skips.
  remote_step 'mark pfnetbird busy' "touch $AUTO_BUSY"
  remote "lockf -k -s -t 0 $AUTO_LOCK /usr/bin/true" 30
  if (( R_CODE != 0 )); then
    remote "rm -f $AUTO_BUSY"
    die 'an auto-update run is in progress on the firewall; try again in a few minutes. Nothing was changed.'
  fi
}

# Schedule input (default). Sets AS_MIN AS_HOUR AS_MDAY AS_WDAY AS_TEXT.
# Returns 1 on Back or end of input.
auto_ask_schedule() {
  local opt ans kind first=0
  if [[ ${1:-} == enable ]]; then first=1; fi
  AS_MIN=''; AS_HOUR=''; AS_MDAY='*'; AS_WDAY='*'; AS_TEXT=''
  while :; do
    if (( first )); then first=0; else info ''; fi   # Enable: the frame already opened with a blank line
    info "Schedule (firewall time, ${AU_TZ:-?})"
    info ' 1) Daily'
    info ' 2) Weekly'
    info ' 3) Monthly'
    info ' 4) Back'
    read -r -p "${UI_LEAD}Enter an option: " opt || { opt=4; info ''; }
    opt=$(trim "$opt")
    if [[ -n $opt ]]; then log_line "menu: schedule option $opt selected"; fi
    case $opt in
      '') ;;
      1) kind=daily; break ;;
      2) kind=weekly; break ;;
      3) kind=monthly; break ;;
      4) return 1 ;;
      *) info 'Invalid option.' ;;
    esac
  done
  if [[ $kind == weekly ]]; then
    while :; do
      info 'Weekday: 1) Mon 2) Tue 3) Wed 4) Thu 5) Fri 6) Sat 7) Sun'
      read -r -p "${UI_LEAD}Enter a weekday [1-7]: " ans || { info ''; return 1; }
      ans=$(trim "$ans")
      log_line "prompt: weekday -> answer: ${ans:-(empty)}"
      if [[ $ans =~ ^[1-7]$ ]]; then AS_WDAY=$(( ans % 7 )); break; fi
      info 'Invalid weekday.'
    done
  elif [[ $kind == monthly ]]; then
    while :; do
      read -r -p "${UI_LEAD}Day of the month [1-28]: " ans || { info ''; return 1; }
      ans=$(trim "$ans")
      log_line "prompt: day of month -> answer: ${ans:-(empty)}"
      if [[ $ans =~ ^([1-9]|1[0-9]|2[0-8])$ ]]; then AS_MDAY=$ans; break; fi
      info 'Invalid day (1-28, so that every month has it).'
    done
  fi
  while :; do
    read -r -p "${UI_LEAD}Time HH:MM, 24 h, firewall time [$AUTO_DEFAULT_TIME]: " ans || { info ''; return 1; }
    ans=$(trim "$ans")
    log_line "prompt: time -> answer: ${ans:-(empty)}"
    if [[ -z $ans ]]; then ans=$AUTO_DEFAULT_TIME; fi
    if [[ $ans =~ ^([01]?[0-9]|2[0-3]):([0-5][0-9])$ ]]; then
      AS_HOUR=$(( 10#${BASH_REMATCH[1]} ))
      AS_MIN=$(( 10#${BASH_REMATCH[2]} ))
      break
    fi
    info 'Invalid time. Use HH:MM, for example 03:30.'
  done
  AS_TEXT=$(auto_sched_text "$AS_MIN" "$AS_HOUR" "$AS_MDAY" '*' "$AS_WDAY")
  return 0
}

# Writes the runner to the firewall (checked by sha256 and php -l before it is used).
auto_deploy_runner() {
  local got l w=''
  auto_runner_build
  remote_step 'create /root/pfnetbird' "mkdir -p $AUTO_DIR && chmod 700 $AUTO_DIR"
  REMOTE_QUIET=1
  remote_payload "php -r '$AUTO_WRITE_PHP'" "$RUNNER_B64" 60
  REMOTE_QUIET=0
  for l in "${R_OUT[@]+"${R_OUT[@]}"}"; do
    case $l in WRITE=*) w=${l#WRITE=} ;; esac
  done
  if (( R_CODE != 0 )) || [[ $w != 1 ]]; then die 'auto-update: writing the runner on the firewall failed'; fi
  remote "sha256 -q $AUTO_RUNNER.tmp"
  got=$(r_first)
  got=${got,,}
  if (( R_CODE != 0 )) || [[ $got != "$RUNNER_SHA" ]]; then
    remote "rm -f $AUTO_RUNNER.tmp"
    die 'auto-update: the runner on the firewall does not match (sha256); removed'
  fi
  remote_step 'syntax check runner' "php -l $AUTO_RUNNER.tmp >/dev/null"
  remote_step 'install runner' "mv -f $AUTO_RUNNER.tmp $AUTO_RUNNER"
  log_line "OK: Runner written: $AUTO_RUNNER (sha256 ${RUNNER_SHA:0:12})"
}

# Removes every pfnetbird cron job. Dies when a job that only mentions the runner path is left.
auto_remove_cron() {
  local l left=''
  REMOTE_QUIET=1
  remote "php -r '$AUTO_REMOVE_PHP'" 60
  REMOTE_QUIET=0
  for l in "${R_OUT[@]+"${R_OUT[@]}"}"; do
    case $l in LEFT=*) left=${l#LEFT=} ;; esac
  done
  if (( R_CODE != 0 )) || [[ ! $left =~ ^[0-9]+$ ]]; then die 'auto-update: removing the cron job failed'; fi
  if (( left > 0 )); then
    die "a cron job referencing $AUTO_RUNNER was not created by pfnetbird; remove it by hand (Cron package or config)"
  fi
}

# Adds or updates the cron job from AS_*. Removes duplicates or a differing command first.
auto_apply_cron() {
  local l applied='' crontab='' code
  if (( ${AU_JOBS:-0} > 1 )) || { (( ${AU_JOBS:-0} > 0 )) && [[ $AU_EXACT != 1 ]]; }; then
    auto_remove_cron
  fi
  code="\$m=\"$AS_MIN\"; \$h=\"$AS_HOUR\"; \$d=\"$AS_MDAY\"; \$w=\"$AS_WDAY\"; $AUTO_APPLY_PHP"
  REMOTE_QUIET=1
  remote "php -r '$code'" 60
  REMOTE_QUIET=0
  for l in "${R_OUT[@]+"${R_OUT[@]}"}"; do
    case $l in
      APPLIED=*) applied=${l#APPLIED=} ;;
      CRONTAB=*) crontab=${l#CRONTAB=} ;;
    esac
  done
  if (( R_CODE != 0 )) || [[ $applied != 1 || $crontab != 1 ]]; then
    die 'auto-update: the cron job could not be set (not found in the pfSense config or /etc/crontab afterwards)'
  fi
}

# Removes the cron job and /root/pfnetbird, then checks both are gone.
auto_remove_all() {
  auto_remove_cron
  remote_step 'delete /root/pfnetbird' "rm -rf $AUTO_DIR"
  auto_read
  if [[ $AU_READ != 1 ]] || auto_present; then
    die 'auto-update: the cron job or /root/pfnetbird is still there after the removal'
  fi
}

# Enable (first time) or change the schedule. $1 = enable | change. Ends the action with exit.
auto_enable_run() {
  local mode=$1 same=0 verb q
  if [[ $mode == change ]]; then ui_begin 'Change auto-update schedule'; else ui_begin 'Enable auto-update'; fi
  auto_read
  if [[ $AU_READ != 1 ]]; then die 'auto-update: cannot read the auto-update state on the firewall'; fi
  if (( ! NB_INSTALLED )); then
    die 'Auto-update only updates an installed NetBird. Install it first.'
  fi
  acb_preflight
  if (( ! ACB_OK )); then
    die "$ACB_TXT. Auto-update needs ACB enabled with an encryption password (Services > AutoConfigBackup)."
  fi
  if [[ $ACB_CODE != new ]]; then
    die 'This pfSense has the legacy ACB, which cannot confirm a backup at Netgate; auto-update is not available.'
  fi

  if ! auto_ask_schedule "$mode"; then exit "$RC_NAV"; fi
  if [[ $mode == change ]]; then verb='Change auto-update to'; else verb='Enable auto-update:'; fi
  q="$verb $AS_TEXT (firewall time, ${AU_TZ:-?}). [y/N]"
  if ! read_yes_no "$q"; then
    info 'Cancelled. Nothing was changed.'
    exit 0
  fi
  if (( AU_JOBS == 1 )) && [[ $AU_EXACT == 1 && $AU_MIN == "$AS_MIN" && $AU_HOUR == "$AS_HOUR" && $AU_MDAY == "$AS_MDAY" \
        && $AU_MONTH == '*' && $AU_WDAY == "$AS_WDAY" ]]; then
    same=1
  fi

  auto_guard
  take_backup "auto-update $mode" skip
  if (( ! BACKUP_DONE )); then exit "$RC_NAV"; fi

  ui_blank
  ui_stage 'Auto-update may be partly set up. Check it with Status.'
  ui_step_begin Runner 'deploying the runner'
  auto_deploy_runner
  remote_step 'clear last result' "rm -f $AUTO_DIR/last-result $AUTO_DIR/paused-*"   # a previous failure no longer blocks the runner
  ui_step_end ok "written, sha256 ${RUNNER_SHA:0:8}"
  ui_step_begin 'Cron job' 'setting the schedule'
  auto_read
  auto_apply_cron
  auto_read
  if [[ $AU_READ != 1 ]] || (( AU_JOBS != 1 )) || [[ $AU_EXACT != 1 || $AU_MIN != "$AS_MIN" || $AU_HOUR != "$AS_HOUR" \
        || $AU_MDAY != "$AS_MDAY" || $AU_MONTH != '*' || $AU_WDAY != "$AS_WDAY" || $AU_RSTATE != current ]]; then
    die 'auto-update: the cron job or the runner read back from the firewall does not match what was set'
  fi
  ui_step_end ok "$AS_TEXT (firewall time, ${AU_TZ:-?})"
  if [[ $mode == change ]]; then
    log_line "OK: Auto-update schedule changed: $AS_TEXT (firewall time, ${AU_TZ:-?})."
    if (( same )); then info 'The schedule was already set; the runner is current.'; fi
  else
    log_line "OK: Auto-update enabled: $AS_TEXT (firewall time, ${AU_TZ:-?})."
  fi
  info 'The firewall checks for a new NetBird release then. Results: the notices bell, and /root/pfnetbird/auto.log on the firewall.'
  info 'Auto-update always follows the latest stable release.'
  if [[ $mode == change ]]; then
    ui_close ok "Auto-update schedule changed in ${UI_TOTAL}s."
  else
    ui_close ok "Auto-update enabled in ${UI_TOTAL}s."
  fi
  exit 0
}

auto_enable_dry() {
  local bk='Local / ACB / Both / Skip / Back'
  if [[ ${1:-enable} == change ]]; then ui_plan 'Dry run: change auto-update schedule'; else ui_plan 'Dry run: enable auto-update'; fi
  auto_read
  acb_preflight
  info 'DRY RUN — would do:'
  info "  1. Check: NetBird installed ($( (( NB_INSTALLED )) && printf yes || printf no )), $ACB_TXT."
  info '     Run is refused when NetBird is not installed, or ACB is disabled, has no encryption password, or is the legacy ACB.'
  info "  2. Ask the schedule: 1) Daily 2) Weekly (weekday) 3) Monthly (day 1-28), then HH:MM (firewall time, ${AU_TZ:-?})."
  info '  3. Ask for confirmation (y/N).'
  info "  4. Check that no auto-update run is in progress (lockf on $AUTO_LOCK) and mark this client busy."
  info "  5. Ask for backup: $bk."
  info "  6. Write $AUTO_RUNNER (mode 0600; sha256 and php -l checked before it is used) and clear last-result."
  info "  7. Add or update the pfSense cron job (install_cron_job): $AUTO_CMD"
  info '     pfSense writes the config as "Installed cron job for ..." or "Updated cron job for ...".'
  info '  8. Read the cron job back and check /etc/crontab.'
  info '  At each scheduled run the firewall would: look up the latest stable release on GitHub; stop if netbird is up to date; skip if an earlier attempt for the same release failed; download both packages, check SHA-256; take an ACB backup and confirm it at Netgate (stop without changes if that fails); snapshot the NetBird identity and package settings; pkg add -f both; stop NetBird, restore the identity and settings if the package install replaced them; netbird service restart; wait 60 s for "Management: Connected"; report in the notices bell and /root/pfnetbird/auto.log.'
  ui_close '' 'Dry run: nothing was changed.'
}

# Read-only. Shows the cron job, the runner, the last result and the tail of the run log.
auto_status_show() {
  local cron runner last l
  ui_begin 'Auto-update status'
  auto_read
  if [[ $AU_READ != 1 ]]; then die 'auto-update: cannot read the auto-update state on the firewall'; fi
  if (( AU_JOBS == 0 )); then
    cron='none'
  elif (( AU_JOBS > 1 )); then
    cron="$AU_JOBS jobs found (Change schedule repairs this)"
  elif [[ $AU_EXACT != 1 ]]; then
    cron="$(auto_word), but the command differs (Change schedule repairs this)"
  else
    cron="$(auto_word) (firewall time, ${AU_TZ:-?})"
  fi
  case $AU_RSTATE in
    missing)  runner='missing (Change schedule redeploys it)' ;;
    current)  runner='current' ;;
    *)        runner='other version (Change schedule redeploys it)' ;;
  esac
  LOG_MUTE=1   # the box output is shown, not logged; one summary line below
  info "  Cron job:     $cron"
  info "  Runner:       $runner"
  info "  Last run:     ${AU_LAST_TIME:-never}"
  if [[ -n $AU_LAST_RESULT ]]; then
    last="$AU_LAST_RESULT"
    if [[ -n $AU_LAST_DETAIL ]]; then last+=" - $AU_LAST_DETAIL"; fi
    info "  Last result:  $last"
  fi
  if (( AU_SNAPS > 0 )); then info "  Identity snapshots on the firewall: $AU_SNAPS"; fi
  if (( AU_SNAPS > 0 )); then
    info '  Next runs:    paused while an identity snapshot exists (cleared by Disable and Enable, a successful manual Update, or a later run that finds NetBird connected and up to date; Change schedule does not remove it)'
  else
    case $AU_LAST_RESULT in
      failed-pkg|failed-acb|failed-snapshot|failed-crash|failed-internal|updated-not-connected)
        info "  Next runs:    paused for release ${AU_LAST_TO:-?} (cleared by Change schedule, Disable and Enable, or a successful manual Update)" ;;
    esac
  fi
  info "  Log on the firewall: $AUTO_DIR/auto.log (last 10 lines):"
  remote "if [ -f $AUTO_DIR/auto.log ]; then tail -n 10 $AUTO_DIR/auto.log; else echo '(no log yet)'; fi" 30
  for l in "${R_OUT[@]+"${R_OUT[@]}"}"; do info "  $l"; done
  LOG_MUTE=0
  log_line "auto-update status shown: jobs=$AU_JOBS runner=$AU_RSTATE last=${AU_LAST_RESULT:-none}"
}

auto_disable_run() {
  local extra=''
  ui_begin 'Disable auto-update'
  auto_read
  if [[ $AU_READ != 1 ]]; then die 'auto-update: cannot read the auto-update state on the firewall'; fi
  if (( AU_SNAPS > 0 )); then extra=", $AU_SNAPS identity snapshot(s)"; fi
  if ! read_yes_no "Disable auto-update? The cron job and $AUTO_DIR (runner, log, last result$extra) are removed. [y/N]"; then
    info 'Cancelled. Nothing was changed.'
    exit 0
  fi
  auto_guard
  take_backup 'auto-update disable' skip
  if (( ! BACKUP_DONE )); then exit "$RC_NAV"; fi
  ui_blank
  ui_stage 'Auto-update may be partly removed. Check it with Status.'
  ui_step_begin Remove 'removing the cron job and the runner'
  auto_remove_all
  log_line "OK: Auto-update disabled. The cron job and $AUTO_DIR are removed."
  ui_step_end ok 'cron job and runner directory removed'
  ui_close ok "Auto-update disabled in ${UI_TOTAL}s."
  exit 0
}

auto_disable_dry() {
  ui_plan 'Dry run: disable auto-update'
  auto_read
  info 'DRY RUN — would do:'
  info '  1. Ask for confirmation (y/N).'
  info "  2. Check that no auto-update run is in progress (lockf on $AUTO_LOCK) and mark this client busy."
  info '  3. Ask for backup: Local / ACB / Both / Skip / Back.'
  info "  4. Remove the pfSense cron job (install_cron_job, inactive): pfSense writes \"Removed cron job for $AUTO_CMD\"."
  info "  5. Delete $AUTO_DIR (runner, auto.log, last-result$( (( ${AU_SNAPS:-0} > 0 )) && printf ', %s identity snapshot(s)' "$AU_SNAPS" || true ))."
  info '  6. Check that no cron job is left and the directory is gone.'
  ui_close '' 'Dry run: nothing was changed.'
}

# Menu entry "Auto-update (cron)". Off: straight to Enable. On (job or runner found): maintenance menu.
auto_job() {
  local opt
  auto_read
  if [[ $AU_READ != 1 ]]; then die 'auto-update: cannot read the auto-update state on the firewall'; fi
  if ! auto_present; then
    change_menu 'Enable auto-update (cron on the firewall)' '' 'Requires ACB (Services > AutoConfigBackup) with an encryption password.'
    case $CHANGE_CHOICE in
      run) auto_enable_run enable ;;
      dry) auto_enable_dry enable ;;
      *) exit "$RC_NAV" ;;
    esac
    return 0
  fi
  ui_open 'Auto-update'
  while :; do
    info ''
    info "Auto-update (cron on the firewall): $(auto_word)"
    info ' 1) Status'
    info ' 2) Change schedule'
    info ' 3) Disable'
    info ' 4) Back'
    read -r -p "${UI_LEAD}Enter an option: " opt || { opt=4; info ''; }
    opt=$(trim "$opt")
    if [[ -n $opt ]]; then log_line "menu: auto-update option $opt selected"; fi
    case $opt in
      '') ;;
      1) auto_status_show; return 0 ;;
      2)
        change_menu "Change auto-update schedule (now: $(auto_word))"
        case $CHANGE_CHOICE in
          run) auto_enable_run change ;;
          dry) auto_enable_dry change ;;
          *) exit "$RC_NAV" ;;
        esac
        return 0
        ;;
      3)
        change_menu 'Disable auto-update'
        case $CHANGE_CHOICE in
          run) auto_disable_run ;;
          dry) auto_disable_dry ;;
          *) exit "$RC_NAV" ;;
        esac
        return 0
        ;;
      4) exit "$RC_NAV" ;;
      *) info 'Invalid option.' ;;
    esac
  done
}

# ---------------------------------------------------------------------------
# Session state shared between the parent shell and the menu action subshells
# ---------------------------------------------------------------------------
reset_state() {
  local v
  for v in "${STATE_VARS[@]}"; do printf -v "$v" '%s' ''; done
  NB_INSTALLED=0
  ACB_OK=0
  STATE_STAGE=0
}

# Writes the state variables and the stage reached to STATE_FILE (called in a subshell).
save_state() {
  local v
  : >"$STATE_FILE"
  for v in "${STATE_VARS[@]}"; do printf '%s=%q\n' "$v" "${!v}" >>"$STATE_FILE"; done
  printf 'STATE_STAGE=%q\n' "$1" >>"$STATE_FILE"
}

# Reads STATE_FILE into the parent shell (plain assignments, so they are global).
load_state() {
  if [[ -s $STATE_FILE ]]; then . "$STATE_FILE"; fi
}

# Reads the box, NetBird and the release. Each stage is saved, so a failure later on
# (for example GitHub being down) still leaves the earlier stages for the screen.
refresh_job() {
  reset_state
  save_state 0
  get_box_info
  save_state 1
  get_netbird_state
  acb_preflight
  auto_read
  save_state 2
}

# The release lookup, after refresh_job, in the parent shell (the cache lives here). Sets STATE_STAGE=3
# on success; a rate limit sets REL_LIMITED and prints one line; any other failure prints the error and
# sets ACT_RC=2 (the caller then waits for Enter).
refresh_release() {
  local rc=0
  REL_LIMITED=0
  get_latest_release "$BOX_ARCH" || rc=$?
  case $rc in
    0) STATE_STAGE=3 ;;
    2) REL_LIMITED=1; rate_limit_fail ;;
    *) fail "$GH_ERR"; print_context; ACT_RC=2 ;;
  esac
}

# ---------------------------------------------------------------------------
# Menu: actions run in a ( ) subshell so die / exit only end that action.
# ---------------------------------------------------------------------------
job_exit() {
  ui_abort
  if [[ -n $TMP_FILE && -e $TMP_FILE ]]; then rm -f "$TMP_FILE"; fi
}

# run_action <function> [args]: sets ACT_RC (0 ok, 2 action error, 3 session lost).
run_action() {
  ACT=$(( ACT + 1 ))
  trap - ERR
  set +e
  (
    set -e
    trap - EXIT
    trap job_exit EXIT
    trap 'on_err $LINENO $?' ERR
    IN_ACTION=1
    # The subshell starts with a clean frame state: the parent's screen frame is already closed.
    UI_FRAME=0; UI_STEP=0; UI_AFTER=(); UI_NOTE_K=(); UI_NOTE_T=(); UI_SPID=''; UI_LEAD=''; UI_FAILT=''; UI_TOTAL=0
    "$@"
  )
  ACT_RC=$?
  set -e
  trap 'on_err $LINENO $?' ERR
  return 0
}

# run_job <function>: run_action, then decide whether the session is still there.
# Sets JOB_LOST=1 (after tearing the session down) if it is gone. The action already
# printed its ERROR and paths.
run_job() {
  JOB_LOST=0
  run_action "$@"
  if (( ACT_RC == 3 )); then
    JOB_LOST=1
  elif ! kill -0 "$SESSION_PID" 2>/dev/null; then
    fail 'the ssh session has ended'
    JOB_LOST=1
  fi
  if (( JOB_LOST )); then
    info 'Connection lost.'
    disconnect_remote
  fi
  return 0
}

backup_job() {
  ui_open 'Backup'
  take_backup 'manual backup'
  if (( ! BACKUP_DONE )); then exit "$RC_NAV"; fi
  ui_close ok "Backup done in ${UI_TOTAL}s."
}
remote_cleanup_job() { remote "rm -rf $REMOTE_DIR; rm -f $AUTO_BUSY"; }

# Submenu for a change. $1 = header. Sets CHANGE_CHOICE to run, dry, older or back (end of input =
# back). With $2 = older the list is 1) Run 2) Dry run (plan only) 3) Older release 4) Back.
# $3 = an optional note line printed right after the header.
change_menu() {
  local opt older=${2:-} note=${3:-} back=3
  if [[ $older == older ]]; then back=4; fi
  CHANGE_CHOICE=back
  while :; do
    info ''
    info "$1"
    if [[ -n $note ]]; then info " $note"; fi
    info ' 1) Run'
    info ' 2) Dry run (plan only)'
    if [[ $older == older ]]; then info ' 3) Older release'; fi
    info " $back) Back"
    read -r -p "${UI_LEAD}Enter an option: " opt || { opt=$back; info ''; }
    opt=$(trim "$opt")
    if [[ -n $opt ]]; then log_line "menu: change option $opt selected"; fi
    case $opt in
      '') ;;
      1) CHANGE_CHOICE=run; return 0 ;;
      2) CHANGE_CHOICE=dry; return 0 ;;
      3) if [[ $older == older ]]; then CHANGE_CHOICE=older; fi; return 0 ;;
      4) if [[ $older == older ]]; then return 0; fi; info 'Invalid option.' ;;
      *) info 'Invalid option.' ;;
    esac
  done
}

dry_install_job() {
  if (( NB_INSTALLED )) && is_downgrade; then ui_plan 'Dry run: downgrade NetBird'; else ui_plan "$JOB_HDR (dry run)"; fi
  dry_backup_line
  dry_install_plan
  ui_close '' 'Dry run: nothing was changed.'
}

dry_uninstall_job() {
  ui_plan "$JOB_HDR (dry run)"
  dry_uninstall
  ui_close '' 'Dry run: nothing was changed.'
}

# Header, Run / Dry run / Back for the release in REL_* (the latest, or an older one). "older" as $1
# adds the Older release item. Sets IR_RESULT to older or back when the user chose those, otherwise done.
install_release() {
  local hdr
  if (( NB_INSTALLED )); then
    hdr=$(update_title)
  else
    hdr="Install NetBird $REL_CL_VER"
  fi
  JOB_HDR=$hdr
  change_menu "$hdr" "${1:-}"
  IR_RESULT=done
  case $CHANGE_CHOICE in
    run) if (( NB_INSTALLED )); then do_update; else do_install; fi ;;
    dry) dry_install_job ;;
    older) IR_RESULT=older ;;
    *) IR_RESULT=back ;;
  esac
  return 0
}

# Menu item 3: header, Run / Dry run / Older release / Back, then the flows.
install_job() {
  install_release older
  if [[ $IR_RESULT == older ]]; then exit "$RC_OLDER"; elif [[ $IR_RESULT == back ]]; then exit "$RC_NAV"; fi
  return 0
}

# Older release, in the parent shell (the cache lives here): reads the release list from GitHub (or the
# cache) and builds the 5 newest stable releases before the latest in OLD_TAGS / OLD_VERS / OLD_BLKS
# (a release whose packages cannot be used is left out and logged). Returns 0, 1 (GH_ERR) or 2 (rate limit).
older_prepare() {
  local _sv _rc=0
  # The candidates are resolved into REL_*: keep the latest release's values for the screen.
  _sv=$(declare -p REL_TAG REL_CL_NAME REL_CL_URL REL_CL_DIGEST REL_CL_VER REL_CL_VERCLEAN \
    REL_UI_NAME REL_UI_URL REL_UI_DIGEST REL_UI_VER REL_UI_VERCLEAN)
  older_prepare_run || _rc=$?
  eval "${_sv//declare -- /declare -g }"
  return "$_rc"
}

older_prepare_run() {
  local line tag dr pre cl blk='' latest=$REL_TAG seen=0 skipped=0 rc=0 a
  local uri="$REPO_API/releases?per_page=50"
  OLD_N=0; OLD_TAGS=(); OLD_VERS=(); OLD_BLKS=()
  gh_lookup "$uri" || rc=$?
  if (( rc != 0 )); then return "$rc"; fi
  parse_release_list "$BOX_ARCH"
  if [[ -n $latest ]] && grep -qF "R $latest|" <<<"$PARSED"; then seen=1; fi
  while IFS= read -r line; do
    if [[ $line == 'A '* ]]; then blk+="${line#A }"$'\n'; continue; fi
    [[ $line == 'R '* ]] || continue
    line=${line#R }
    IFS='|' read -r tag dr pre cl <<<"$line"
    ASSETS=${blk%$'\n'}; blk=''
    cl=''
    while IFS='|' read -r a _; do
      if [[ $a =~ ^netbird-.+-"$BOX_ARCH"\.pkg$ ]]; then cl=$a; break; fi
    done <<<"$ASSETS"
    if [[ $dr != 0 || $pre != 0 || -z $cl ]]; then continue; fi
    if [[ ! $tag =~ ^[A-Za-z0-9._-]+$ ]]; then continue; fi
    # Everything up to and including the latest release is skipped (without a known latest: the first one).
    if (( ! skipped )); then
      if (( seen )); then
        if [[ $tag == "$latest" ]]; then skipped=1; fi
        continue
      fi
      skipped=1
      continue
    fi
    if ! { resolve_asset REL_CL '^netbird-(.+)-'"$BOX_ARCH"'\.pkg$' && resolve_asset REL_UI '^pfSense-pkg-NetBird-(.+)-'"$BOX_ARCH"'\.pkg$'; }; then
      log_line "release $tag skipped: $RESOLVE_ERR"
      continue
    fi
    OLD_TAGS+=("$tag"); OLD_VERS+=("$REL_CL_VER"); OLD_BLKS+=("$ASSETS")
    OLD_N=$(( OLD_N + 1 ))
    if (( OLD_N >= 5 )); then break; fi
  done <<<"$PARSED"
  if (( OLD_N == 0 )); then GH_ERR='no older stable release found on GitHub'; return 1; fi
  return 0
}

# Menu item 3, Older release chosen: the list is read here, then the pick menu runs as an action.
# Sets OLDER_RC (what the caller treats as the action's exit status).
older_flow() {
  local rc=0
  OLDER_RC=0
  info ''
  info 'Reading the release list from GitHub...'
  older_prepare || rc=$?
  case $rc in
    0) run_job older_job; OLDER_RC=$ACT_RC ;;
    2) rate_limit_fail; OLDER_RC=$RC_NAV ;;
    *) fail "$GH_ERR"; print_context; OLDER_RC=2 ;;
  esac
}

# The pick menu: the list (newest first, 0 = Back), then Run / Dry run / Back for the chosen one. pkg add
# -f allows the downgrade; the identity and settings snapshot/restore is the one of do_update. The
# connected screen still follows the latest release, so it shows the update afterwards.
older_job() {
  local i n=$OLD_N opt pick=''
  local -a tags=("${OLD_TAGS[@]}") vers=("${OLD_VERS[@]}") blks=("${OLD_BLKS[@]}")
  while :; do
    info ''
    info 'Older release (newest first)'
    for (( i = 0; i < n; i++ )); do info " $(( i + 1 ))) netbird ${vers[i]}   release ${tags[i]}"; done
    info ' 0) Back'
    # shellcheck disable=SC2031
    read -r -p "${UI_LEAD}Enter an option: " opt || { opt=0; info ''; }
    opt=$(trim "$opt")
    if [[ -n $opt ]]; then log_line "menu: older release option $opt selected"; fi
    case $opt in
      '') continue ;;
      0) exit "$RC_NAV" ;;
      [1-9])
        if (( opt > n )); then info 'Invalid option.'; continue; fi
        ;;
      *) info 'Invalid option.'; continue ;;
    esac
    pick=${tags[opt-1]}
    log_line "menu: older release $pick selected"
    # The chosen release becomes the one in REL_*; Run / Dry run / Back for it, Back returns to the list.
    ASSETS=${blks[opt-1]}
    REL_TAG=$pick
    resolve_asset REL_CL '^netbird-(.+)-'"$BOX_ARCH"'\.pkg$' || die "$RESOLVE_ERR"
    resolve_asset REL_UI '^pfSense-pkg-NetBird-(.+)-'"$BOX_ARCH"'\.pkg$' || die "$RESOLVE_ERR"
    install_release
    if [[ $IR_RESULT == done ]]; then return 0; fi
  done
}

uninstall_job() {
  JOB_HDR="Uninstall NetBird $NB_CLIENT"
  change_menu "$JOB_HDR"
  case $CHANGE_CHOICE in
    run) do_uninstall ;;
    dry) dry_uninstall_job ;;
    *) exit "$RC_NAV" ;;
  esac
}

# ---------------------------------------------------------------------------
# Screens
# ---------------------------------------------------------------------------
# Display-only formatters (the log, prompts and the logged summary keep the full forms).
# fmt_home <var> <path>: $HOME at the start becomes ~.
fmt_home() {
  local _fp=$2
  if [[ -n ${HOME:-} && $_fp == "$HOME"/* ]]; then _fp="~${_fp#"$HOME"}"; fi
  printf -v "$1" '%s' "$_fp"
}

# auto_word_short <var>: auto_word with the weekday cut to three letters (Wed) and a custom
# schedule without the brackets. auto_word / auto_sched_text / AUTO_WDAYS stay as they are.
auto_word_short() {
  local _ws _wi
  _ws=$(auto_word)
  for (( _wi = 0; _wi < ${#AUTO_WDAYS[@]}; _wi++ )); do
    _ws=${_ws//"${AUTO_WDAYS[_wi]}"/"${AUTO_WDAYS[_wi]:0:3}"}
  done
  if [[ $_ws == 'custom ('*')' ]]; then _ws="custom ${_ws#custom (}"; _ws=${_ws%)}; fi
  printf -v "$1" '%s' "$_ws"
}

# fmt_lastrun <var> <time>: `2026-10-17 03:30:05` -> `10-17 03:30`.
fmt_lastrun() {
  local _lt=$2
  if [[ $_lt =~ ^[0-9]{4}-([0-9]{2}-[0-9]{2})[[:space:]]+([0-9]{2}:[0-9]{2}) ]]; then
    _lt="${BASH_REMATCH[1]} ${BASH_REMATCH[2]}"
  else
    ui_sanitize _lt "$_lt"
    ui_shorten _lt "$_lt" 16
  fi
  printf -v "$1" '%s' "$_lt"
}

# fmt_lastres <var> <result>: the coloured word for the last auto-update result.
fmt_lastres() {
  local _lr=$2
  case $_lr in
    uptodate)               ui_c _lr ok 'ok' ;;
    updated)                ui_c _lr ok 'updated' ;;
    updated-not-connected)  ui_c _lr fail 'not connected' ;;
    skipped-*)              ui_c _lr warn 'skipped' ;;
    failed-*)               ui_c _lr fail 'failed' ;;
    *)                      ui_sanitize _lr "$_lr"; ui_shorten _lr "$_lr" 12 ;;
  esac
  printf -v "$1" '%s' "$_lr"
}

# auto_row <var>: the Auto-update row of the connected screen, with colour markers. One line.
#   not read                       ▲ unknown                                     yellow
#   no job, nothing left behind    off                                           plain
#   no job, files left             ▲ off · files left on firewall                yellow
#   job, runner missing / differs  <schedule> <tz> · ▲ runner missing / differs  yellow part
#   job, runner current            <schedule> <tz> · last run MM-DD HH:MM <word>
#     word: uptodate ok (green), updated updated (green), updated-not-connected not connected
#     (red), skipped-* skipped (yellow), failed-* failed (red), anything else plain
auto_row() {
  local _ar _aw _az='' _ax _at _al
  if [[ ${AU_READ:-0} != 1 ]]; then ui_c _ar warn "$G_WARN unknown"; printf -v "$1" '%s' "$_ar"; return 0; fi
  auto_runner_state
  if (( ${AU_JOBS:-0} == 0 )); then
    if [[ $AU_RSTATE == missing && ${AU_HASDIR:-0} != 1 ]]; then
      _ar='off'
    else
      ui_c _ar warn "$G_WARN off $U_MID files left on firewall"
    fi
    printf -v "$1" '%s' "$_ar"
    return 0
  fi
  auto_word_short _aw
  if [[ -n ${AU_TZ:-} ]]; then _az=" $AU_TZ"; fi
  case $AU_RSTATE in
    missing) ui_c _ax warn "$G_WARN runner missing"; _ar="$_aw$_az $U_MID $_ax" ;;
    other)   ui_c _ax warn "$G_WARN runner differs"; _ar="$_aw$_az $U_MID $_ax" ;;
    *)
      _ar="$_aw$_az"
      if [[ -n ${AU_LAST_TIME:-} ]]; then
        fmt_lastrun _at "$AU_LAST_TIME"
        fmt_lastres _al "${AU_LAST_RESULT:-?}"
        _ar+=" $U_MID last run $_at $_al"
      fi
      ;;
  esac
  printf -v "$1" '%s' "$_ar"
}

start_screen() {
  local home auth
  downloads_dir
  fmt_home home "$DL_DIR"
  ui_sanitize home "$home"
  ui_shorten home "$home" $(( UI_W - ${#UI_PFX} - UI_KVW ))
  if (( KEY_GIVEN )); then
    ui_sanitize auth "$KEY_NAME"
    auth="key $auth only"
  else
    auth='like ssh (agent / ~/.ssh key, else password)'
  fi
  ui_open "pfnetbird $SCRIPT_VERSION $U_H$U_H$U_H maintain NetBird on pfSense, the community way"
  ui_blank
  ui_kv 'Connection' 'not connected'
  ui_kv 'Auth' "$auth"
  ui_kv 'Backups' "$home"
  ui_kv 'Logging' "$(log_state_word)"
  ui_section 'Menu'
  ui_menu2 '1) Connect to firewall' "2) Logging: $(log_state_word) (toggle)" '0) Exit'
  ui_close
}

log_state_word() { if (( LOG_ON )); then printf 'on'; else printf 'off'; fi; }
# Connected menu: logging is on but no log file could be opened, so nothing is written.
log_menu_word() { if (( LOG_ON )) && [[ -z $LOG_FILE ]]; then printf 'off (cannot write)'; else log_state_word; fi; }

session_screen() {
  local ed nbtxt reltxt status item4 acbtxt n
  local title_r sub vv ver abi auth nbv pkv rel_v rel_p statv acbv acbk logv lhome autov
  local -a items=()
  acbtxt=${ACB_TXT:-unknown}
  acbtxt=${acbtxt#ACB: }
  acbtxt=${acbtxt/#ACB not available: /not available: }
  if [[ -n $BOX_EDITION && $BOX_EDITION != unknown ]]; then ed="pfSense $BOX_EDITION"; else ed='pfSense'; fi

  # The old text forms are kept: the one logged summary line below is built from them.
  if (( STATE_STAGE >= 2 )); then
    if (( NB_INSTALLED )); then
      nbtxt="$NB_CLIENT (pfSense-pkg-NetBird ${NB_PKG:-not installed})"
    else
      nbtxt='not installed'
    fi
  else
    nbtxt='unknown'
  fi

  if (( STATE_STAGE >= 3 )); then
    reltxt="$REL_TAG (netbird $REL_CL_VER, pfSense-pkg-NetBird $REL_UI_VER)"
    if (( ! NB_INSTALLED )); then
      status='not installed'
      item4="Install NetBird $REL_CL_VER"
    else
      if version_ge "$NB_CLIENT" "$REL_CL_VER"; then status='up to date'
      else status="update available ($NB_CLIENT -> $REL_CL_VER)"; fi
      if is_same_version; then item4="Reinstall NetBird $REL_CL_VER"
      else item4="Update NetBird $U_ARR $REL_CL_VER"; fi
    fi
  else
    reltxt='unknown (lookup failed)'
    status='unknown'
    item4='Install or update NetBird'
  fi

  # --- display forms ---
  # Title right part: user@host (fqdn); the (fqdn) is dropped when it does not fit.
  ui_sanitize vv "$CONN_USER@$CONN_HOST"
  title_r=$vv
  if [[ -n ${BOX_FQDN:-} && $BOX_FQDN != "$CONN_HOST" ]]; then
    if (( ${#SCRIPT_VERSION} + 11 + ${#vv} + ${#BOX_FQDN} + 3 <= UI_W - 8 )); then title_r="$vv ($BOX_FQDN)"; fi
  fi
  # Subtitle: edition and version (-RELEASE dropped), FreeBSD major, package ABI, auth.
  ver=${BOX_VERSION:-}
  ver=${ver/-RELEASE/}
  ui_sanitize ver "$ver"
  sub=$ed
  if [[ -n $ver ]]; then sub+=" $ver"; fi
  if [[ -n ${BOX_MAJOR:-} ]]; then sub+=" $U_MID FreeBSD $BOX_MAJOR"; fi
  if [[ -n ${BOX_ABI:-} ]]; then ui_sanitize abi "$BOX_ABI"; sub+=" $U_MID $abi"; fi
  ui_map sub "$sub"
  if (( KEY_GIVEN )); then
    # The key name gives way first, so the box facts stay whole.
    ui_sanitize auth "$KEY_NAME"
    ui_shorten auth "$auth" $(( UI_W - ${#UI_PFX} - ${#sub} - 3 - 9 ))
    ui_map auth " $U_MID auth key $auth"
  else
    ui_map auth " $U_MID auth like ssh"
  fi
  if (( ${#sub} + ${#auth} <= UI_W - ${#UI_PFX} )); then sub+=$auth; fi   # else drop auth before cutting
  ui_shorten sub "$sub" $(( UI_W - ${#UI_PFX} ))

  # NetBird section.
  if (( STATE_STAGE >= 2 )); then
    if (( NB_INSTALLED )); then
      ui_sanitize nbv "${NB_CLIENT:-?}"
      ui_sanitize pkv "${NB_PKG:-not installed}"
      nbv="$nbv   pfSense-pkg-NetBird $pkv"
    else
      nbv=$U_EM
    fi
  else
    nbv='unknown'
  fi
  if (( STATE_STAGE >= 3 )); then
    ui_sanitize rel_v "$REL_CL_VER"
    ui_sanitize rel_p "$REL_UI_VER"
    ui_sanitize ver "$REL_TAG"
    rel_p="$rel_v   pfSense-pkg-NetBird $rel_p   release $ver"
    case $status in
      'not installed')   ui_c statv warn "$G_DOT not installed" ;;
      'up to date')      ui_c statv ok "$G_DOT up to date" ;;
      *)                 ui_c statv warn "$G_DOT update available" ;;
    esac
  else
    if (( REL_LIMITED )); then rel_p=unknown; else rel_p=$U_EM; fi
    if (( STATE_STAGE >= 2 )); then ui_c statv warn "$G_WARN lookup failed"; else ui_c statv warn "$G_WARN unknown"; fi
  fi

  # Safety section.
  ui_sanitize acbk "$acbtxt"
  if (( ACB_OK )); then ui_c acbv ok "$G_OK enabled, encryption password set"; else ui_c acbv warn "$G_WARN $acbk"; fi
  auto_row autov
  if (( LOG_ON )) && [[ -n $LOG_FILE ]]; then
    fmt_home lhome "$LOG_FILE"
    ui_sanitize lhome "$lhome"
    ui_shorten lhome "$lhome" $(( UI_W - ${#UI_PFX} - UI_KVW - 5 ))
    logv="on $U_MID $lhome"
  elif (( LOG_ON )); then
    ui_c logv warn "$G_WARN off (the log file could not be created)"
  else
    logv='off'
  fi

  # Menu: 1 Check, 2 Backup only, 3 Install/Update; then Uninstall only when NetBird is installed;
  # Auto-update when NetBird is installed or a job or runner is left over; Logging stays last.
  items=('1) Check (refresh status)' '2) Backup only' "3) $item4")
  n=4
  MENU_UN='none'; MENU_AU='none'
  if (( STATE_STAGE >= 2 && NB_INSTALLED )); then
    MENU_UN=$n; items+=("$n) Uninstall NetBird"); n=$(( n + 1 ))
  fi
  if (( STATE_STAGE >= 2 )) && { (( NB_INSTALLED )) || auto_present; }; then
    MENU_AU=$n; auto_word_short vv; items+=("$n) Auto-update: $vv"); n=$(( n + 1 ))
  fi
  MENU_LOG=$n; items+=("$n) Logging: $(log_menu_word)")

  # The screen itself is not copied to the log line by line; one summary line is.
  LOG_MUTE=1
  ui_open "pfnetbird $SCRIPT_VERSION" "$title_r"
  ui_blank
  printf '%s%s\n' "$UI_PFX" "$sub"
  ui_section 'NetBird'
  ui_kv 'Installed' "$nbv"
  ui_kv 'Latest' "$rel_p"
  ui_kv 'Status' "$statv"
  ui_section 'Safety'
  ui_kv 'ACB' "$acbv"
  ui_kv 'Auto-update' "$autov"
  ui_kv 'Log' "$logv"
  ui_section 'Menu'
  ui_menu1 "${items[@]}" '0) Disconnect SSH'
  ui_close
  LOG_MUTE=0
  log_line "screen: NetBird=$nbtxt; latest=$reltxt; status=$status; auto=$(auto_word)"
}

# ---------------------------------------------------------------------------
# Loops
# ---------------------------------------------------------------------------
# Connected screen. Returns when disconnected or when the session was lost.
session_loop() {
  local opt need_refresh=1 first=1 rc
  SESSION_RC=0
  while :; do
    if (( need_refresh )); then
      need_refresh=0
      run_job refresh_job
      if (( JOB_LOST )); then SESSION_RC=2; return 0; fi
      load_state
      REL_LIMITED=0
      if (( ACT_RC == 0 )); then refresh_release; fi
      if (( ACT_RC != 0 || REL_LIMITED )); then pause_menu; fi
    fi
    # The first screen of a session is not cleared, so "Login OK" stays visible above it.
    if (( first )); then first=0; else clear_screen; fi
    session_screen
    while :; do
      read -r -p "${UI_LEAD}Enter an option: " opt || { opt=0; info ''; }
      opt=$(trim "$opt")
      if [[ -n $opt ]]; then log_line "menu: option $opt selected"; fi
      case $opt in
        '') ;;
        0)
          disconnect_remote 'Disconnected.'
          SESSION_RC=0
          return 0
          ;;
        "$MENU_LOG")
          if (( LOG_ON )) && [[ -n $LOG_FILE ]]; then
            log_line 'logging disabled'
            LOG_ON=0
            ui_say ok 'Logging is off.'; log_line 'Logging is off.'
          else
            # Off, or on without a log file (cannot write): switch on and try to open the log again.
            LOG_ON=1
            if [[ -z $LOG_FILE ]]; then log_open "$CONN_HOST" retry; fi
            if [[ -n $LOG_FILE ]]; then
              log_line 'logging enabled'
              ui_say ok 'Logging is on.'; log_line 'Logging is on.'
            else
              ui_say fail "Logging could not start ($LOG_WHY)"   # no log is open, so nothing is logged
            fi
          fi
          pause_menu
          break
          ;;
        1)
          info 'Reading the firewall and the latest NetBird release...'
          need_refresh=1
          break
          ;;
        3)
          if (( STATE_STAGE < 3 )); then
            fail 'the release information is not available; use option 1 to try again'
            continue
          fi
          DOWNLOADED=1
          run_job install_job
          if (( JOB_LOST )); then SESSION_RC=2; return 0; fi
          rc=$ACT_RC
          if (( rc == RC_OLDER )); then
            older_flow
            if (( JOB_LOST )); then SESSION_RC=2; return 0; fi
            rc=$OLDER_RC
          fi
          run_job remote_cleanup_job
          if (( JOB_LOST )); then SESSION_RC=2; return 0; fi
          DOWNLOADED=0
          if (( rc != RC_NAV )); then pause_menu; fi
          info ''
          need_refresh=1
          break
          ;;
        "$MENU_UN")
          if [[ $MENU_UN == none ]]; then info 'Invalid option.'; continue; fi
          run_job uninstall_job
          if (( JOB_LOST )); then SESSION_RC=2; return 0; fi
          rc=$ACT_RC
          run_job remote_cleanup_job
          if (( JOB_LOST )); then SESSION_RC=2; return 0; fi
          if (( rc != RC_NAV )); then pause_menu; fi
          info ''
          need_refresh=1
          break
          ;;
        "$MENU_AU")
          if [[ $MENU_AU == none ]]; then info 'Invalid option.'; continue; fi
          run_job auto_job
          if (( JOB_LOST )); then SESSION_RC=2; return 0; fi
          rc=$ACT_RC
          run_job remote_cleanup_job
          if (( JOB_LOST )); then SESSION_RC=2; return 0; fi
          if (( rc != RC_NAV )); then pause_menu; fi
          info ''
          need_refresh=1
          break
          ;;
        2)
          run_job backup_job
          if (( JOB_LOST )); then SESSION_RC=2; return 0; fi
          if (( ACT_RC != RC_NAV )); then pause_menu; fi
          info ''
          need_refresh=1
          break
          ;;
        *) info 'Invalid option.' ;;
      esac
    done
  done
}

# Start screen. Exits 0 on option 0 or Ctrl-D. With --host there is no start screen: connect at once
# and end after the session (host_run). Otherwise Connect, Logging and Exit; after Disconnect, a lost
# session, a cancelled or a failed login the start screen comes back.
start_loop() {
  local opt
  if [[ -n $HOST_ARG ]]; then host_run; fi
  while :; do
    clear_screen
    start_screen
    while :; do
      read -r -p "${UI_LEAD}Enter an option: " opt || { info ''; exit 0; }
      opt=$(trim "$opt")
      case $opt in
        '') ;;
        0) exit 0 ;;
        1) break ;;
        2) LOG_ON=$(( 1 - LOG_ON )); continue 2 ;;
        *) info 'Invalid option.' ;;
      esac
    done
    connect_flow
    if (( CONNECTED )); then
      info 'Reading the firewall and the latest NetBird release...'
      session_loop
    fi
    # Failed connect, cancelled connect, "Disconnected." or "Connection lost.": read it first.
    pause_menu
  done
}

# With --host: connects, runs the session and exits: 0 after Disconnect or a cancel, 2 when the login
# failed or the session was lost.
host_run() {
  connect_flow
  if (( ! CONNECTED )); then exit "$CONN_RC"; fi
  info 'Reading the firewall and the latest NetBird release...'
  session_loop
  exit "$SESSION_RC"
}

# Fails the connect: the ERROR line, a clean state, and CONN_RC=2 (--host exits 2 on it).
connect_fail() {
  fail_w "$1"
  disconnect_remote
  CONN_RC=2
}

# Asks for the firewall and the user (or takes them from --host, once), validates, warns about the
# NetBird range, and logs in. Sets CONNECTED=1 on success. CONN_RC is 0 for a cancel and 2 for an
# error (printed here). The firewall question takes [user@]host and is checked like --host; a wrong
# entry shows the same error and asks again. End of input is an error, so the loops always end.
connect_flow() {
  local host user ans
  CONNECTED=0; CONN_RC=0

  host=''; user=''
  if [[ -n $HOST_ARG ]]; then
    host=$HOST_ARG; user=$HOST_USER
    HOST_ARG=''; HOST_USER=''      # used once; a later Connect asks as usual
  fi
  while [[ -z $host ]]; do
    ui_prompt ans 'Firewall (user@host):' || { connect_fail 'invalid firewall IP or host name'; return 0; }
    HOST_ARG=$(trim "$ans"); HOST_USER=''
    split_host_arg
    if [[ -n $HOST_ERR ]]; then fail "$HOST_ERR"; HOST_ARG=''; HOST_USER=''; continue; fi
    host=$HOST_ARG; user=$HOST_USER
    HOST_ARG=''; HOST_USER=''
  done
  if ! test_hostname "$host"; then connect_fail 'invalid firewall IP or host name'; return 0; fi
  while [[ -z $user ]]; do
    ui_prompt ans 'Username:' || { connect_fail 'invalid user name'; return 0; }
    ans=$(trim "$ans")
    if ! test_username "$ans"; then fail 'invalid user name'; continue; fi
    user=$ans
  done
  if ! test_username "$user"; then connect_fail 'invalid user name'; return 0; fi

  if is_netbird_range "$host"; then
    warn_w "$host is in the NetBird range (100.64.0.0/10). An update or uninstall stops NetBird and could cut this session. Use the LAN address if you can."
    if ! read_yes_no 'Continue over the NetBird address? [y/N]'; then
      info 'Cancelled.'
      disconnect_remote
      return 0
    fi
  fi

  if (( KEY_GIVEN )); then
    info "Logging in with key $KEY_NAME (no password fallback). The script never sees a passphrase."
  else
    info_w 'Logging in like ssh: a key from your SSH agent (e.g. 1Password) or ~/.ssh is used if the firewall accepts it; approve it if 1Password asks. Otherwise ssh asks for the password below. The script never sees either.'
  fi
  connect_remote "$host" "$user"
  if (( ! LOGIN_OK )); then CONN_RC=2; return 0; fi
  LOG_DAY=$(date +%Y%m%d)
  log_open "$host"
  log_line "login OK: $user@$host"
  if (( KEY_GIVEN )); then log_line "auth=key key=$KEY_NAME"; else log_line 'auth=ssh'; fi
  CONN_HOST=$host
  CONN_USER=$user
  CONNECTED=1
}

# [user@]host in HOST_ARG: splits it (HOST_USER, HOST_ARG) and checks both. HOST_ERR is the error
# text, or empty when it is fine.
split_host_arg() {
  local h=$HOST_ARG
  HOST_ERR=''
  if [[ $h == *@* ]]; then
    HOST_USER=${h%@*}
    HOST_ARG=${h##*@}
  fi
  if ! test_hostname "$HOST_ARG"; then HOST_ERR='invalid firewall IP or host name'; return 0; fi
  if [[ $h == *@* ]] && ! test_username "$HOST_USER"; then HOST_ERR='invalid user name'; fi
  return 0
}

# --host [user@]host: split and validate before anything else happens (before the login).
check_host_arg() {
  if (( HOST_TWICE )); then die 'firewall given twice'; fi
  split_host_arg
  if [[ -n $HOST_ERR ]]; then die "$HOST_ERR"; fi
}

main() {
  parse_args "$@"
  ui_init
  check_deps
  assert_interactive
  if (( KEY_GIVEN )); then check_key_file; fi
  if (( HOST_GIVEN )); then check_host_arg; fi

  STATE_FILE=$(mktemp) || die 'cannot create a temp file'
  reset_state
  start_loop
  exit 0
}

trap '' PIPE
trap cleanup EXIT
trap 'on_err $LINENO $?' ERR
trap 'exit 2' INT TERM

main "$@"
