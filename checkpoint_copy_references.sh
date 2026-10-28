#!/usr/bin/env bash
# Adds OBJECT2 wherever OBJECT1 is directly referenced in groups or rules.
# Run as root in Expert mode on the Management Server / MDS.
# Requirements: mgmt_cli, jq (or $CPDIR/jq/jq), Bash 4+.
# Dry run by default; --apply performs a single publish at the end.

set -euo pipefail
umask 077

usage() {
  cat <<'USAGE'
Usage:
  ./checkpoint_copy_references.sh [--domain DOMAIN] [--apply] OBJECT1 OBJECT2

Examples (Expert mode, root, on the Check Point Management Server):
  ./checkpoint_copy_references.sh HOST_OLD HOST_NEW
  ./checkpoint_copy_references.sh GROUP_OLD GROUP_NEW
  ./checkpoint_copy_references.sh -d "Domain1" HOST_OLD HOST_NEW
  ./checkpoint_copy_references.sh -d "Domain1" HOST_OLD HOST_NEW --apply

Authentication: mgmt_cli -r true login (no username or password prompt).
The script reuses this session for all queries and changes, publishes once,
then logs out. It does not install policy.

Options:
  -d, --domain DOMAIN    MDS domain (omit for single-domain SMS)
  --apply               Apply changes and publish
  --max-nodes N         Maximum objects queried with where-used (2000)
  --publish-timeout N   Maximum publish wait, in seconds (600)
  -h, --help            Show this help

OBJECT1 and OBJECT2 may each be a host, network, or regular group.
Scope: regular groups and Access Control rules (source/destination).
Does not modify NAT, Threat Prevention, HTTPS Inspection, or special groups.
Duplicates are detected by UID/group membership, not overlapping IP ranges.
Circular group memberships are skipped.
USAGE
}

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }

DOMAIN=''
APPLY=0
MAX_NODES=2000
PUBLISH_TIMEOUT=600
POSITIONAL=()
while (( $# )); do
  case "$1" in
    -d|--domain) (( $# >= 2 )) || die "Missing value for $1"; DOMAIN=$2; shift 2 ;;
    --apply) APPLY=1; shift ;;
    --max-nodes) (( $# >= 2 )) || die "Missing value for $1"; MAX_NODES=$2; shift 2 ;;
    --publish-timeout) (( $# >= 2 )) || die "Missing value for $1"; PUBLISH_TIMEOUT=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    --) shift; while (( $# )); do POSITIONAL+=("$1"); shift; done ;;
    -*) die "Unknown option: $1" ;;
    *) POSITIONAL+=("$1"); shift ;;
  esac
done
(( ${#POSITIONAL[@]} == 2 )) || { usage >&2; exit 2; }
[[ $MAX_NODES =~ ^[1-9][0-9]*$ && $PUBLISH_TIMEOUT =~ ^[1-9][0-9]*$ ]] || die "Limits must be positive integers"
OBJ1_NAME=${POSITIONAL[0]}
OBJ2_NAME=${POSITIONAL[1]}
[[ $OBJ1_NAME != "$OBJ2_NAME" ]] || { printf 'Both object names are identical. No changes.\n'; exit 0; }

(( EUID == 0 )) || die "Run as root in Expert mode to use mgmt_cli -r true"
command -v mgmt_cli >/dev/null 2>&1 || die "mgmt_cli is not available on this server"
if command -v jq >/dev/null 2>&1; then
  JQ_BIN=$(command -v jq)
elif [[ -n ${CPDIR:-} && -x ${CPDIR}/jq/jq ]]; then
  JQ_BIN=${CPDIR}/jq/jq
else
  die 'jq not found (including $CPDIR/jq/jq)'
fi

SESSION_FILE=''
SESSION_ACTIVE=0
WRITE_ATTEMPTED=0
PUBLISH_ATTEMPTED=0
PUBLISHED=0

cleanup() {
  local result=$?
  trap - EXIT
  if (( SESSION_ACTIVE )); then
    if (( WRITE_ATTEMPTED && ! PUBLISH_ATTEMPTED )); then
      printf 'Discarding unpublished changes from this session...\n' >&2
      mgmt_cli -f json -s "$SESSION_FILE" discard >/dev/null 2>&1 || warn "Discard failed; check the session in SmartConsole"
    elif (( PUBLISH_ATTEMPTED && ! PUBLISHED )); then
      warn "Publish was requested, but the result is unconfirmed. Check the task in Management"
    fi
    mgmt_cli -f json -s "$SESSION_FILE" logout >/dev/null 2>&1 || warn "Could not log out of the API session"
  fi
  if [[ -n $SESSION_FILE && -f $SESSION_FILE ]]; then
    rm -f -- "$SESSION_FILE"
  fi
  exit "$result"
}
trap cleanup EXIT

SESSION_FILE=$(mktemp /tmp/cp_copy_references.sid.XXXXXXXX)
login_options=(-f json -r true)
[[ -z $DOMAIN ]] || login_options+=(-d "$DOMAIN")
mgmt_cli "${login_options[@]}" login > "$SESSION_FILE" || die "Local login with -r true failed"
"$JQ_BIN" -e '.sid | strings | length > 0' "$SESSION_FILE" >/dev/null || die "Login did not return a valid SID"
SESSION_ACTIVE=1

# Store each mgmt_cli response in API_JSON (avoid subshells to preserve the cache).
API_JSON=''
API_ERROR=''
api_call() {
  local output rc=0
  output=$(mgmt_cli -f json -s "$SESSION_FILE" "$@" 2>&1) || rc=$?
  API_JSON=$output
  API_ERROR=''
  if ! "$JQ_BIN" -e 'type=="object"' <<< "$output" >/dev/null 2>&1; then
    API_ERROR="Non-JSON response from mgmt_cli: $output"
    return 1
  fi
  API_ERROR=$("$JQ_BIN" -r '[.code // "", .message // ""] | join(": ")' <<< "$output")
  if (( rc != 0 )) || "$JQ_BIN" -e 'has("code")' <<< "$output" >/dev/null; then
    return 1
  fi
  return 0
}

require_api() {
  api_call "$@" || die "mgmt_cli $*: $API_ERROR"
}

missing_object() {
  local lower=${API_ERROR,,}
  [[ $lower == *not_found* || $lower == *'not found'* || $lower == *'does not exist'* || $lower == *'could not find'* ]]
}

RESOLVED_UID=''
resolve_object() {
  local name=$1 kind found=0
  RESOLVED_UID=''
  for kind in host network group; do
    if api_call show "$kind" name "$name" details-level standard; then
      "$JQ_BIN" -e --arg name "$name" --arg kind "$kind" \
        '.name==$name and .type==$kind and (.uid|type)=="string"' <<< "$API_JSON" >/dev/null \
        || die "Unexpected response from show $kind for $name"
      RESOLVED_UID=$("$JQ_BIN" -r '.uid' <<< "$API_JSON")
      ((found+=1))
    elif ! missing_object; then
      die "show $kind $name: $API_ERROR"
    fi
  done
  (( found == 1 )) || die "Expected exactly one host/network/group named '$name' (found: $found)"
}

resolve_object "$OBJ1_NAME"
OBJ1_UID=$RESOLVED_UID
resolve_object "$OBJ2_NAME"
OBJ2_UID=$RESOLVED_UID
[[ $OBJ1_UID != "$OBJ2_UID" ]] || { printf 'Same UID. No changes.\n'; exit 0; }

declare -A WHERE_CACHE=()
WHERE_RESULT=''
where_direct() {
  local uid=$1 total count
  if [[ ! -v WHERE_CACHE[$uid] ]]; then
    (( ${#WHERE_CACHE[@]} < MAX_NODES )) || die "--max-nodes limit reached; no changes will be made"
    require_api where-used uid "$uid" indirect false details-level standard
    "$JQ_BIN" -e '."used-directly" | type=="object"' <<< "$API_JSON" >/dev/null \
      || die "where-used($uid) did not return used-directly"
    total=$("$JQ_BIN" -r '."used-directly".total // -1' <<< "$API_JSON")
    count=$("$JQ_BIN" -r '[."used-directly" | to_entries[] | .value | select(type=="array") | length] | add // 0' <<< "$API_JSON")
    [[ $total =~ ^[0-9]+$ ]] || die "where-used($uid) did not return a valid total"
    (( total <= count )) || die "Incomplete where-used($uid) response (total=$total, visible=$count)"
    WHERE_CACHE[$uid]=$API_JSON
  fi
  WHERE_RESULT=${WHERE_CACHE[$uid]}
}

# Ancestors include the object itself and all groups containing it.
# Use only used-directly to avoid indirect-depth limits.
ANCESTORS=()
walk_ancestors() {
  local root=$1 current gid index=0
  local -a queue=("$root")
  local -A seen=()
  while (( index < ${#queue[@]} )); do
    current=${queue[index]}
    ((index+=1))
    [[ -v seen[$current] ]] && continue
    seen[$current]=1
    where_direct "$current"
    while IFS= read -r gid; do
      [[ -n $gid ]] || continue
      [[ -v seen[$gid] ]] || queue+=("$gid")
    done < <("$JQ_BIN" -r '."used-directly".objects[]? | select(.type=="group") | .uid' <<< "$WHERE_RESULT")
  done
  ANCESTORS=("${!seen[@]}")
}

printf '\nDomain: %s\nObject1: %s (%s)\nObject2: %s (%s)\n' \
  "${DOMAIN:-SMS / local context}" "$OBJ1_NAME" "$OBJ1_UID" "$OBJ2_NAME" "$OBJ2_UID"

where_direct "$OBJ1_UID"
DIRECT_OBJ1=$WHERE_RESULT

declare -A COVERED=()
walk_ancestors "$OBJ2_UID"
for uid in "${ANCESTORS[@]}"; do COVERED[$uid]=1; done

mapfile -t DIRECT_GROUPS < <("$JQ_BIN" -r '."used-directly".objects[]? | select(.type=="group") | .uid' <<< "$DIRECT_OBJ1")
declare -A CANDIDATE_NAME=() CANDIDATE_ANCESTORS=()
for gid in "${DIRECT_GROUPS[@]}"; do
  if [[ -v COVERED[$gid] ]]; then
    printf '= Group %s: Object2 is already included\n' "$gid"
    continue
  fi
  require_api show group uid "$gid" details-level full
  "$JQ_BIN" -e --arg id "$OBJ1_UID" \
    '[.members[]? | if type=="string" then . else .uid end] | index($id) != null' <<< "$API_JSON" >/dev/null \
    || die "where-used and show-group disagree for $gid"
  CANDIDATE_NAME[$gid]=$("$JQ_BIN" -r '.name' <<< "$API_JSON")
done

# Build the parent-group graph before planning, processing child groups first.
for gid in "${!CANDIDATE_NAME[@]}"; do
  walk_ancestors "$gid"
  CANDIDATE_ANCESTORS[$gid]=" ${ANCESTORS[*]} "
done

order_lines=()
for gid in "${!CANDIDATE_NAME[@]}"; do
  depth=0
  for maybe_parent in "${!CANDIDATE_NAME[@]}"; do
    [[ $maybe_parent == "$gid" ]] && continue
    [[ ${CANDIDATE_ANCESTORS[$gid]} == *" $maybe_parent "* ]] && ((depth+=1))
  done
  order_lines+=("$depth $gid")
done
ORDERED_GROUPS=()
if (( ${#order_lines[@]} )); then
  mapfile -t ORDERED_GROUPS < <(printf '%s\n' "${order_lines[@]}" | sort -k1,1nr -k2,2 | awk '{print $2}')
fi

PLAN_GROUPS=()
for gid in "${ORDERED_GROUPS[@]}"; do
  if [[ -v COVERED[$gid] ]]; then
    printf '= Group %s: already covered by a child group\n' "${CANDIDATE_NAME[$gid]}"
    continue
  fi
  # Adding OBJECT2 to a group that is already inside OBJECT2 creates a cycle.
  if [[ ${CANDIDATE_ANCESTORS[$gid]} == *" $OBJ2_UID "* ]]; then
    warn "Skipping group ${CANDIDATE_NAME[$gid]}: adding $OBJ2_NAME would create a circular group membership"
    continue
  fi
  PLAN_GROUPS+=("$gid")
  for uid in ${CANDIDATE_ANCESTORS[$gid]}; do COVERED[$uid]=1; done
done

PLAN_RULE_IDS=()
PLAN_RULE_LAYERS=()
PLAN_RULE_NAMES=()
PLAN_RULE_FIELDS=()
declare -A SEEN_RULES=()
RULE_LINES=$("$JQ_BIN" -r \
  '."used-directly"."access-control-rules"[]? | [(.rule|if type=="object" then .uid else . end), (.layer|if type=="object" then .uid else . end)] | join("\t")' \
  <<< "$DIRECT_OBJ1") || die "Could not parse access-rule references"
RULE_RELATIONS=()
if [[ -n $RULE_LINES ]]; then mapfile -t RULE_RELATIONS <<< "$RULE_LINES"; fi
for relation in "${RULE_RELATIONS[@]}"; do
  IFS=$'\t' read -r rid layer <<< "$relation"
  [[ -n $rid && -n $layer ]] || die "where-used returned a rule without a UID/layer: $relation"
  key="$layer/$rid"
  [[ ! -v SEEN_RULES[$key] ]] || continue
  SEEN_RULES[$key]=1
  require_api show access-rule uid "$rid" layer "$layer" details-level standard
  RULE_JSON=$API_JSON
  rule_name=$("$JQ_BIN" -r '.name // (."rule-number"|tostring) // .uid' <<< "$RULE_JSON")
  found=0
  for field in source destination; do
    "$JQ_BIN" -e --arg field "$field" '.[$field] | type=="array"' <<< "$RULE_JSON" >/dev/null \
      || die "Rule $rid does not have a valid $field list"
    if ! "$JQ_BIN" -e --arg field "$field" --arg id "$OBJ1_UID" \
      '[.[$field][] | if type=="string" then . else .uid end] | index($id) != null' <<< "$RULE_JSON" >/dev/null; then
      continue
    fi
    found=1
    already=0
    while IFS= read -r member; do
      [[ -n $member ]] || continue
      if [[ -v COVERED[$member] ]]; then already=1; break; fi
    done < <("$JQ_BIN" -r --arg field "$field" \
      '.[$field][] | if type=="string" then . else .uid end' <<< "$RULE_JSON")
    any_value=$("$JQ_BIN" -r --arg field "$field" \
      '[.[$field][] | if type=="object" then (.name // "") else . end] | index("Any") != null' \
      <<< "$RULE_JSON") || die "Could not check 'Any' in rule $rid [$field]"
    case "$any_value" in
      true) already=1 ;;
      false) ;;
      *) die "Unexpected 'Any' check result in rule $rid [$field]: $any_value" ;;
    esac
    if (( already )); then
      printf '= Rule %s [%s]: Object2 is already covered directly or through a group\n' "$rule_name" "$field"
    else
      PLAN_RULE_IDS+=("$rid")
      PLAN_RULE_LAYERS+=("$layer")
      PLAN_RULE_NAMES+=("$rule_name")
      PLAN_RULE_FIELDS+=("$field")
    fi
  done
  (( found )) || warn "Rule $rule_name appears in where-used but not in source/destination"
done

for field in nat-rules threat-prevention-rules https-rules; do
  amount=$("$JQ_BIN" -r --arg field "$field" '."used-directly"[$field] | length // 0' <<< "$DIRECT_OBJ1")
  (( amount == 0 )) || warn "$amount reference(s) in $field are out of scope"
done
while IFS= read -r entry; do
  [[ -n $entry ]] && warn "Unsupported/special object: $entry"
done < <("$JQ_BIN" -r '."used-directly".objects[]? | select(.type != "group") | "\(.name // .uid) (\(.type))"' <<< "$DIRECT_OBJ1")

printf '\nCHANGE PLAN:\n'
for gid in "${PLAN_GROUPS[@]}"; do printf ' + GROUP %s (%s)\n' "${CANDIDATE_NAME[$gid]}" "$gid"; done
for ((i=0; i<${#PLAN_RULE_IDS[@]}; i++)); do
  printf ' + RULE %s [%s], layer=%s, uid=%s\n' \
    "${PLAN_RULE_NAMES[i]}" "${PLAN_RULE_FIELDS[i]}" "${PLAN_RULE_LAYERS[i]}" "${PLAN_RULE_IDS[i]}"
done
printf 'Total: %s groups and %s rule fields\n' "${#PLAN_GROUPS[@]}" "${#PLAN_RULE_IDS[@]}"

if (( ! APPLY )); then
  printf '\nDRY RUN: no changes made. Add --apply to apply and publish.\n'
  exit 0
fi
if (( ${#PLAN_GROUPS[@]} == 0 && ${#PLAN_RULE_IDS[@]} == 0 )); then
  printf 'No changes to publish.\n'
  exit 0
fi

printf '\nApplying changes...\n'
for gid in "${PLAN_GROUPS[@]}"; do
  WRITE_ATTEMPTED=1
  require_api set group uid "$gid" members.add "$OBJ2_UID"
  printf ' OK group %s\n' "${CANDIDATE_NAME[$gid]}"
done
for ((i=0; i<${#PLAN_RULE_IDS[@]}; i++)); do
  WRITE_ATTEMPTED=1
  require_api set access-rule uid "${PLAN_RULE_IDS[i]}" layer "${PLAN_RULE_LAYERS[i]}" \
    "${PLAN_RULE_FIELDS[i]}.add" "$OBJ2_UID"
  printf ' OK rule %s [%s]\n' "${PLAN_RULE_NAMES[i]}" "${PLAN_RULE_FIELDS[i]}"
done

PUBLISH_ATTEMPTED=1
require_api publish --sync false
TASK_ID=$("$JQ_BIN" -r '."task-id" // ""' <<< "$API_JSON") || die "Could not parse publish task-id"
[[ -n $TASK_ID ]] || die "publish did not return a task-id"
printf 'Publishing... task %s\n' "$TASK_ID"
deadline=$((SECONDS + PUBLISH_TIMEOUT))
while :; do
  require_api show task task-id "$TASK_ID" details-level full
  status=$("$JQ_BIN" -r '.tasks[0].status // "unknown"' <<< "$API_JSON")
  case "$status" in
    succeeded) PUBLISHED=1; printf 'PUBLISHED successfully (policy not installed).\n'; break ;;
    failed|"partially succeeded"|canceled|cancelled) die "Publish $status: $API_JSON" ;;
    "in progress"|pending) ;;
    *) die "Unknown publish status: $status" ;;
  esac
  (( SECONDS < deadline )) || die "Publish timed out; check task $TASK_ID in Management"
  sleep 2
done
