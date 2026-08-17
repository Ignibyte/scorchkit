#!/usr/bin/env bash
# Repository-owned ticket and phase workflow. Agent adapters call this script;
# planning files remain the authoritative state.

set -uo pipefail

SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
SOURCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT_DIR="${SCORCHKIT_PIPELINE_ROOT:-$SOURCE_ROOT}"
PLANNING="$ROOT_DIR/docs/planning"
TICKETS="$PLANNING/tickets"
ACTIVE="$PLANNING/pipeline/active"
COMPLETED="$PLANNING/pipeline/completed"
TEMPLATES="$PLANNING/pipeline/_templates"

usage() {
    cat <<'USAGE'
usage: bin/pipeline.sh COMMAND [ARGS]

  doctor
  status
  check
  intake SLUG TITLE...
  create SLUG TYPE TITLE...
  start plan|design|implement|inspect|validate|complete
  pass  plan|design|implement|inspect|validate|complete
  receipt
  selftest
USAGE
}

frontmatter_value() {
    local file="$1" key="$2"
    awk -v key="$key" '
        $0 == "---" { fences++; next }
        fences == 1 && index($0, key ":") == 1 {
            sub("^" key ":[[:space:]]*", "")
            print
            exit
        }
    ' "$file"
}

replace_frontmatter() {
    local file="$1" key="$2" value="$3" temporary
    temporary="$(mktemp "$file.XXXXXX")" || return 1
    awk -v key="$key" -v value="$value" '
        BEGIN { changed = 0 }
        !changed && index($0, key ":") == 1 {
            print key ": " value
            changed = 1
            next
        }
        { print }
        END { if (!changed) exit 3 }
    ' "$file" > "$temporary" || {
        rm -f "$temporary"
        return 1
    }
    mv "$temporary" "$file"
}

replace_literal() {
    local file="$1" old="$2" new="$3" temporary
    temporary="$(mktemp "$file.XXXXXX")" || return 1
    awk -v old="$old" -v new="$new" '
        {
            line = $0
            while ((position = index(line, old)) != 0) {
                line = substr(line, 1, position - 1) new substr(line, position + length(old))
                changed = 1
            }
            print line
        }
        END { if (!changed) exit 3 }
    ' "$file" > "$temporary" || {
        rm -f "$temporary"
        return 1
    }
    mv "$temporary" "$file"
}

render_template() {
    local template="$1" destination="$2" number="$3" slug="$4"
    local title="$5" type="$6" date="$7" uuid="$8" line
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line//\{\{NUMBER\}\}/$number}"
        line="${line//\{\{SLUG\}\}/$slug}"
        line="${line//\{\{TITLE\}\}/$title}"
        line="${line//\{\{TYPE\}\}/$type}"
        line="${line//\{\{DATE\}\}/$date}"
        line="${line//\{\{UUID\}\}/$uuid}"
        printf '%s\n' "$line"
    done < "$template" > "$destination"
}

active_spec() {
    local specs
    shopt -s nullglob
    specs=("$ACTIVE"/*.spec.md)
    shopt -u nullglob
    if [ "${#specs[@]}" -eq 0 ]; then
        return 1
    fi
    if [ "${#specs[@]}" -ne 1 ]; then
        echo "pipeline invariant failed: ${#specs[@]} active specs exist" >&2
        return 2
    fi
    printf '%s\n' "${specs[0]}"
}

require_active() {
    local spec
    spec="$(active_spec)" || {
        echo "no active pipeline; create one with: bash bin/pipeline.sh create SLUG TYPE TITLE" >&2
        return 1
    }
    printf '%s\n' "$spec"
}

section_has_content() {
    local file="$1" heading="$2"
    awk -v heading="$heading" '
        $0 == heading { inside = 1; next }
        inside && /^## / { exit }
        inside {
            line = $0
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
            if (line == "" || line == "-" || line ~ /^</ || line ~ /:$/) next
            if (line ~ /^\|[-|[:space:]]+\|$/) next
            if (line ~ /^\| # \|/ || line ~ /^\| ID /) next
            found = 1
        }
        END { exit !found }
    ' "$file"
}

inspect_has_disposition() {
    local file="$1"
    awk '
        $0 == "## Phase 3.5 — Inspect ledger" { inside = 1; next }
        inside && /^## / { exit }
        inside && /^\|/ && $0 !~ /^\|[-|[:space:]]+\|$/ && $0 !~ /^\| # \|/ {
            if ($0 !~ /<.*>/) found = 1
        }
        END { exit !found }
    ' "$file"
}

generate_uuid() {
    if command -v uuidgen >/dev/null 2>&1; then
        uuidgen | tr '[:upper:]' '[:lower:]'
    elif command -v python3 >/dev/null 2>&1; then
        python3 -c 'import uuid; print(uuid.uuid4())'
    else
        echo "uuid generator is required" >&2
        return 1
    fi
}

next_ticket_number() {
    # The backticks in this expression are literal Markdown delimiters.
    # shellcheck disable=SC2016
    sed -n 's/.*Next ticket number[^`]*`\([0-9][0-9]*\)`.*/\1/p' \
        "$TICKETS/INDEX.md" | sed -n '1p'
}

update_ticket_index_for_create() {
    local number="$1" next="$2" title="$3" type="$4" slug="$5" temporary row
    temporary="$(mktemp "$TICKETS/INDEX.md.XXXXXX")" || return 1
    row="| $number | [$title](open/TICKET-$number-$slug.md) | $type | open |"
    awk -v next_number="$next" -v row="$row" '
        /^\*\*Next ticket number:\*\*/ { print "**Next ticket number:** `" next_number "`"; next }
        { print }
        /<!-- OPEN-TICKETS -->/ { print row }
    ' "$TICKETS/INDEX.md" > "$temporary" || { rm -f "$temporary"; return 1; }
    grep -Fqx "$row" "$temporary" || {
        echo "ticket index has no open-ticket insertion marker" >&2
        rm -f "$temporary"
        return 1
    }
    mv "$temporary" "$TICKETS/INDEX.md"
}

remove_ticket_index_row() {
    local number="$1" temporary
    temporary="$(mktemp "$TICKETS/INDEX.md.XXXXXX")" || return 1
    awk -v prefix="| $number |" 'index($0, prefix) != 1 { print }' \
        "$TICKETS/INDEX.md" > "$temporary" && mv "$temporary" "$TICKETS/INDEX.md"
}

create_intake() {
    local slug="$1"
    shift
    local title="$*" date destination
    [[ "$slug" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]] || {
        echo "intake slug must be lowercase kebab-case" >&2
        return 2
    }
    [ -n "$title" ] || { echo "intake title is required" >&2; return 2; }
    date="$(date +%F)"
    destination="$PLANNING/intake/INTAKE-$slug.md"
    mkdir -p "$PLANNING/intake"
    [ ! -e "$destination" ] || { echo "$destination already exists" >&2; return 1; }
    render_template "$PLANNING/_templates/intake.md" "$destination" "" "$slug" \
        "$title" "" "$date" ""
    echo "created $destination"
}

create_pipeline() {
    local slug="$1" type="$2"
    shift 2
    local title="$*" raw_number number next date uuid ticket spec notes aar
    [[ "$slug" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ ]] || {
        echo "pipeline slug must be lowercase kebab-case" >&2
        return 2
    }
    case "$type" in feature | bug | chore | spike | docs | refactor) ;;
        *) echo "type must be feature, bug, chore, spike, docs, or refactor" >&2; return 2 ;;
    esac
    [ -n "$title" ] && [[ "$title" != *'|'* ]] || {
        echo "a nonempty title without a pipe character is required" >&2
        return 2
    }
    if active_spec >/dev/null 2>&1; then
        echo "an active pipeline already exists; complete it before creating another" >&2
        return 1
    fi

    raw_number="$(next_ticket_number)"
    [[ "$raw_number" =~ ^[0-9]+$ ]] || { echo "ticket index has no valid next number" >&2; return 1; }
    number="$(printf '%03d' "$((10#$raw_number))")"
    next="$(printf '%03d' "$((10#$raw_number + 1))")"
    date="$(date +%F)"
    uuid="$(generate_uuid)" || return 1
    ticket="$TICKETS/open/TICKET-$number-$slug.md"
    spec="$ACTIVE/$slug.spec.md"
    notes="$ACTIVE/$slug.notes.md"
    aar="$PLANNING/knowledge/aar/AAR-$number-$slug.md"
    mkdir -p "$TICKETS/open" "$ACTIVE" "$PLANNING/knowledge/aar"
    for output in "$ticket" "$spec" "$notes" "$aar"; do
        [ ! -e "$output" ] || { echo "$output already exists" >&2; return 1; }
    done

    render_template "$PLANNING/_templates/ticket.md" "$ticket" "$number" "$slug" \
        "$title" "$type" "$date" "$uuid"
    render_template "$TEMPLATES/spec.md" "$spec" "$number" "$slug" \
        "$title" "$type" "$date" "$uuid"
    render_template "$TEMPLATES/notes.md" "$notes" "$number" "$slug" \
        "$title" "$type" "$date" "$uuid"
    render_template "$PLANNING/knowledge/aar/TEMPLATE.md" "$aar" "$number" "$slug" \
        "$title" "$type" "$date" "$uuid"
    if ! update_ticket_index_for_create "$number" "$next" "$title" "$type" "$slug"; then
        rm -f "$ticket" "$spec" "$notes" "$aar"
        return 1
    fi
    echo "created TICKET-$number and active pipeline $slug"
    echo "fill the ticket/spec/AAR recall, then: bash bin/pipeline.sh pass plan"
}

phase_status() {
    case "$1:$2" in
        plan:start) echo 'Phase 1 — Plan: in progress' ;;
        plan:pass) echo 'Phase 1 — Plan PASS; ready for Phase 2 — Design' ;;
        design:start) echo 'Phase 2 — Design: in progress' ;;
        design:pass) echo 'Phase 2 — Design PASS; ready for Phase 3 — Implement' ;;
        implement:start) echo 'Phase 3 — Implement: in progress' ;;
        implement:pass) echo 'Phase 3 — Implement PASS; ready for Phase 3.5 — Inspect' ;;
        inspect:start) echo 'Phase 3.5 — Inspect: in progress' ;;
        inspect:pass) echo 'Phase 3.5 — Inspect PASS; ready for Phase 4 — Validate' ;;
        validate:start) echo 'Phase 4 — Validate: in progress' ;;
        validate:pass) echo 'Phase 4 — Validate PASS; ready for Phase 5 — Complete' ;;
        complete:start) echo 'Phase 5 — Complete: in progress' ;;
        complete:pass) echo 'Phase 5 — Complete PASS; ready for delivery' ;;
        *) return 1 ;;
    esac
}

previous_phase() {
    case "$1" in
        design) echo plan ;;
        implement) echo design ;;
        inspect) echo implement ;;
        validate) echo inspect ;;
        complete) echo validate ;;
        *) return 1 ;;
    esac
}

start_phase() {
    local phase="$1" spec current expected new previous
    spec="$(require_active)" || return 1
    current="$(frontmatter_value "$spec" status)"
    if [ "$phase" = "plan" ]; then
        expected="$(phase_status plan start)"
        [ "$current" = "$expected" ] || {
            echo "plan has already advanced: $current" >&2
            return 1
        }
        echo "plan is already in progress"
        return 0
    fi
    previous="$(previous_phase "$phase")" || { echo "unknown phase: $phase" >&2; return 2; }
    expected="$(phase_status "$previous" pass)"
    new="$(phase_status "$phase" start)"
    [ "$current" = "$expected" ] || {
        echo "cannot start $phase; expected '$expected', found '$current'" >&2
        return 1
    }
    replace_frontmatter "$spec" status "$new"
    echo "started $phase"
}

validate_phase_evidence() {
    local phase="$1" spec="$2" notes ticket aar receipt_mode
    notes="${spec%.spec.md}.notes.md"
    ticket="$ROOT_DIR/$(frontmatter_value "$spec" ticket_doc)"
    aar="$ROOT_DIR/$(frontmatter_value "$spec" aar)"
    [ -f "$notes" ] && [ -f "$ticket" ] && [ -f "$aar" ] || {
        echo "pipeline links are incomplete" >&2
        return 1
    }
    case "$phase" in
        plan)
            if grep -qE '<[^>]+>|\{\{[^}]+\}\}' "$spec" "$ticket" "$aar"; then
                echo "plan still contains template placeholders" >&2
                return 1
            fi
            grep -q '| REQ-[0-9][0-9][0-9] |.* shall .*|' "$spec" || {
                echo "plan needs at least one EARS requirement using 'shall'" >&2
                return 1
            }
            section_has_content "$notes" '## Phase 1 — Plan' || {
                echo "plan notes need recalled knowledge and confirmation evidence" >&2
                return 1
            }
            ;;
        design)
            section_has_content "$notes" '## Phase 2 — Design' || {
                echo "design notes need architecture and regression evidence" >&2
                return 1
            }
            ;;
        implement)
            section_has_content "$notes" '## Phase 3 — Implement' || {
                echo "implementation notes need changed behavior and design-conformance evidence" >&2
                return 1
            }
            ;;
        inspect)
            inspect_has_disposition "$notes" || {
                echo "inspect ledger needs at least one reviewed finding or explicit no-finding disposition" >&2
                return 1
            }
            ;;
        validate)
            section_has_content "$notes" '## Phase 4 — Validate' || {
                echo "validation notes need real test and gate outcomes" >&2
                return 1
            }
            # shellcheck source=bin/gate-state.sh
            . "$ROOT_DIR/bin/gate-state.sh" || return 1
            scorchkit_verify_gate_receipt || {
                echo "validation requires a matching DIFF, FULL, or approved focused-repair receipt" >&2
                return 1
            }
            receipt_mode="$(scorchkit_gate_receipt_mode)" || return 1
            case "$receipt_mode" in
                diff | full) ;;
                focused-repair)
                    [ "$(frontmatter_value "$spec" ticket)" = "TICKET-002" ] || {
                        echo "focused-repair validation is not approved for this ticket" >&2
                        return 1
                    }
                    ;;
                *)
                    echo "validation receipt has an unsupported mode: $receipt_mode" >&2
                    return 1
                    ;;
            esac
            ;;
        complete)
            [ "$(frontmatter_value "$aar" status)" = "submitted" ] || {
                echo "complete requires the linked AAR to have status: submitted" >&2
                return 1
            }
            [[ "$(frontmatter_value "$aar" submitted)" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || {
                echo "complete requires the linked AAR to have a submitted YYYY-MM-DD date" >&2
                return 1
            }
            [[ "$(frontmatter_value "$aar" effectiveness)" =~ ^[1-5]([[:space:]-]|$) ]] || {
                echo "complete requires the linked AAR to have an effectiveness score from 1–5" >&2
                return 1
            }
            section_has_content "$notes" '## Phase 5 — Complete' || {
                echo "complete notes need documentation, AAR, and archive evidence" >&2
                return 1
            }
            ;;
        *) echo "unknown phase: $phase" >&2; return 2 ;;
    esac
}

rewrite_archive_links() {
    local spec="$1" ticket="$2" active_spec_relative="$3" open_ticket_relative="$4"
    local completed_spec_relative="$5" closed_ticket_relative="$6"
    replace_literal "$spec" "$open_ticket_relative" "$closed_ticket_relative" || return 1
    replace_literal "$ticket" "$active_spec_relative" "$completed_spec_relative"
}

archive_pipeline() {
    local spec="$1" notes ticket aar number date completed_spec completed_notes closed_ticket
    local active_spec_relative open_ticket_relative completed_spec_relative closed_ticket_relative
    notes="${spec%.spec.md}.notes.md"
    ticket="$ROOT_DIR/$(frontmatter_value "$spec" ticket_doc)"
    aar="$ROOT_DIR/$(frontmatter_value "$spec" aar)"
    number="$(frontmatter_value "$ticket" ticket_number)"
    date="$(date +%F)"
    mkdir -p "$COMPLETED" "$TICKETS/closed"
    completed_spec="$COMPLETED/$(basename "$spec")"
    completed_notes="$COMPLETED/$(basename "$notes")"
    closed_ticket="$TICKETS/closed/$(basename "$ticket")"
    for destination in "$completed_spec" "$completed_notes" "$closed_ticket"; do
        [ ! -e "$destination" ] || {
            echo "archive destination already exists: $destination" >&2
            return 1
        }
    done
    grep -q "^| $number |" "$TICKETS/INDEX.md" || {
        echo "open ticket $number has no queue row to close" >&2
        return 1
    }
    completed_spec_relative="${completed_spec#"$ROOT_DIR/"}"
    closed_ticket_relative="${closed_ticket#"$ROOT_DIR/"}"
    active_spec_relative="${spec#"$ROOT_DIR/"}"
    open_ticket_relative="${ticket#"$ROOT_DIR/"}"
    rewrite_archive_links "$spec" "$ticket" "$active_spec_relative" "$open_ticket_relative" \
        "$completed_spec_relative" "$closed_ticket_relative" || return 1
    replace_frontmatter "$spec" status "$(phase_status complete pass)" || return 1
    replace_frontmatter "$ticket" status "done" || return 1
    replace_frontmatter "$ticket" closed "$date" || return 1
    mv "$spec" "$completed_spec"
    mv "$notes" "$completed_notes"
    mv "$ticket" "$closed_ticket"
    remove_ticket_index_row "$number" || return 1
    echo "closed TICKET-$number and archived its pipeline"
    echo "rerun the ticket's delivery-gate mode before committing; archival invalidated the prior receipt"
    [ -f "$aar" ]
}

pass_phase() {
    local phase="$1" spec current expected new ticket
    spec="$(require_active)" || return 1
    current="$(frontmatter_value "$spec" status)"
    expected="$(phase_status "$phase" start)" || { echo "unknown phase: $phase" >&2; return 2; }
    [ "$current" = "$expected" ] || {
        echo "cannot pass $phase; expected '$expected', found '$current'" >&2
        return 1
    }
    validate_phase_evidence "$phase" "$spec" || return 1
    if [ "$phase" = "complete" ]; then
        archive_pipeline "$spec"
        return $?
    fi
    new="$(phase_status "$phase" pass)"
    replace_frontmatter "$spec" status "$new" || return 1
    if [ "$phase" = "plan" ]; then
        ticket="$ROOT_DIR/$(frontmatter_value "$spec" ticket_doc)"
        replace_frontmatter "$ticket" status in-progress || return 1
    fi
    echo "passed $phase"
}

pipeline_status() {
    local spec status ticket
    if ! spec="$(active_spec)"; then
        echo "no active pipeline"
        return 0
    fi
    status="$(frontmatter_value "$spec" status)"
    ticket="$(frontmatter_value "$spec" ticket)"
    echo "$ticket — $status"
    echo "spec: ${spec#"$ROOT_DIR/"}"
    echo "notes: ${spec%.spec.md}.notes.md"
}

pipeline_check() {
    local required spec ticket aar open_file number failures=0 count=0
    for required in \
        "$TICKETS/INDEX.md" \
        "$PLANNING/_templates/ticket.md" \
        "$TEMPLATES/spec.md" \
        "$TEMPLATES/notes.md" \
        "$PLANNING/knowledge/aar/TEMPLATE.md"; do
        [ -f "$required" ] || { echo "missing pipeline artifact: $required" >&2; failures=1; }
    done
    shopt -s nullglob
    for spec in "$ACTIVE"/*.spec.md; do count=$((count + 1)); done
    shopt -u nullglob
    [ "$count" -le 1 ] || { echo "more than one active pipeline" >&2; failures=1; }
    if [ "$count" -eq 1 ]; then
        spec="$(active_spec)" || failures=1
        ticket="$ROOT_DIR/$(frontmatter_value "$spec" ticket_doc)"
        aar="$ROOT_DIR/$(frontmatter_value "$spec" aar)"
        [ -f "$ticket" ] || { echo "active spec links a missing ticket" >&2; failures=1; }
        [ -f "$aar" ] || { echo "active spec links a missing AAR" >&2; failures=1; }
        [ -f "${spec%.spec.md}.notes.md" ] || { echo "active spec has no notes pair" >&2; failures=1; }
    fi
    shopt -s nullglob
    for open_file in "$TICKETS/open"/TICKET-*.md; do
        number="$(frontmatter_value "$open_file" ticket_number)"
        grep -q "^| $number |" "$TICKETS/INDEX.md" || {
            echo "open ticket $number has no queue row" >&2
            failures=1
        }
    done
    shopt -u nullglob
    [ "$failures" -eq 0 ] || return 1
    echo "pipeline structure OK ($count active)"
}

doctor() {
    local failures=0 tool hook_path
    for tool in cargo git jq shellcheck; do
        if command -v "$tool" >/dev/null 2>&1; then
            echo "$tool: OK"
        else
            echo "$tool: MISSING"
            failures=1
        fi
    done
    pipeline_check || failures=1
    hook_path="$(git -C "$ROOT_DIR" config --get core.hooksPath 2>/dev/null || true)"
    if [ "$hook_path" = ".githooks" ]; then
        echo "commit hook: wired"
    else
        echo "commit hook: NOT WIRED (run git config core.hooksPath .githooks)"
        failures=1
    fi
    if [ -n "${DATABASE_URL:-}" ] && command -v pg_isready >/dev/null 2>&1 \
        && pg_isready -d "$DATABASE_URL" >/dev/null 2>&1; then
        echo "postgres: ready"
    else
        echo "postgres: unavailable (required only for delivery gate:21)"
    fi
    pipeline_status
    return "$failures"
}

receipt_status() {
    # shellcheck source=bin/gate-state.sh
    . "$ROOT_DIR/bin/gate-state.sh" || return 1
    if scorchkit_verify_gate_receipt; then
        echo "delivery receipt matches current worktree (mode: $(scorchkit_gate_receipt_mode))"
    else
        echo "delivery receipt is missing or stale" >&2
        return 1
    fi
}

selftest() {
    local fixture tickets specs archive_spec_probe archive_ticket_probe active_link open_link
    fixture="$(mktemp -d /tmp/scorchkit-pipeline.XXXXXX)" || return 1
    PIPELINE_FIXTURE="$fixture"
    trap 'rm -rf "${PIPELINE_FIXTURE:-}"' EXIT
    mkdir -p "$fixture/docs/planning/pipeline" "$fixture/docs/planning/tickets/open" \
        "$fixture/docs/planning/tickets/closed" "$fixture/docs/planning/knowledge/aar"
    cp -R "$SOURCE_ROOT/docs/planning/_templates" "$fixture/docs/planning/"
    cp -R "$SOURCE_ROOT/docs/planning/pipeline/_templates" "$fixture/docs/planning/pipeline/"
    mkdir -p "$fixture/docs/planning/pipeline/active" "$fixture/docs/planning/pipeline/completed"
    cp "$SOURCE_ROOT/docs/planning/knowledge/aar/TEMPLATE.md" \
        "$fixture/docs/planning/knowledge/aar/TEMPLATE.md"
    cp "$SOURCE_ROOT/docs/planning/tickets/INDEX.md" "$fixture/docs/planning/tickets/INDEX.md"
    SCORCHKIT_PIPELINE_ROOT="$fixture" bash "$SCRIPT_PATH" create probe chore 'Probe ticket' \
        >/dev/null || return 1
    shopt -s nullglob
    tickets=("$fixture/docs/planning/tickets/open"/TICKET-*-probe.md)
    specs=("$fixture/docs/planning/pipeline/active"/*.spec.md)
    shopt -u nullglob
    [ "${#tickets[@]}" -eq 1 ] || {
        echo "pipeline selftest failed: create did not allocate exactly one ticket" >&2
        return 1
    }
    [ "${#specs[@]}" -eq 1 ] || {
        echo "pipeline selftest failed: create did not allocate exactly one spec" >&2
        return 1
    }
    if SCORCHKIT_PIPELINE_ROOT="$fixture" bash "$SCRIPT_PATH" start design \
        >/dev/null 2>&1; then
        echo "pipeline selftest failed: design started before plan passed" >&2
        return 1
    fi
    if SCORCHKIT_PIPELINE_ROOT="$fixture" bash "$SCRIPT_PATH" pass plan \
        >/dev/null 2>&1; then
        echo "pipeline selftest failed: placeholder plan evidence passed" >&2
        return 1
    fi
    if SCORCHKIT_PIPELINE_ROOT="$fixture" bash "$SCRIPT_PATH" create second chore Second \
        >/dev/null 2>&1; then
        echo "pipeline selftest failed: second active pipeline was allowed" >&2
        return 1
    fi
    SCORCHKIT_PIPELINE_ROOT="$fixture" bash "$SCRIPT_PATH" check >/dev/null || return 1
    archive_spec_probe="$fixture/archive-spec-probe.md"
    archive_ticket_probe="$fixture/archive-ticket-probe.md"
    cp "${specs[0]}" "$archive_spec_probe"
    cp "${tickets[0]}" "$archive_ticket_probe"
    active_link="$(frontmatter_value "$archive_ticket_probe" pipeline_spec)"
    open_link="$(frontmatter_value "$archive_spec_probe" ticket_doc)"
    rewrite_archive_links "$archive_spec_probe" "$archive_ticket_probe" \
        "$active_link" "$open_link" \
        'docs/planning/pipeline/completed/probe.spec.md' \
        'docs/planning/tickets/closed/TICKET-999-probe.md' || return 1
    if [ "$(frontmatter_value "$archive_spec_probe" ticket_doc)" != \
        'docs/planning/tickets/closed/TICKET-999-probe.md' ] \
        || [ "$(frontmatter_value "$archive_ticket_probe" pipeline_spec)" != \
            'docs/planning/pipeline/completed/probe.spec.md' ] \
        || grep -Fq "$open_link" "$archive_spec_probe" \
        || grep -Fq "$active_link" "$archive_ticket_probe"; then
        echo "pipeline selftest failed: archive links were not rewritten" >&2
        return 1
    fi
    echo "pipeline selftest OK"
}

command_name="${1:-}"
case "$command_name" in
    doctor) doctor ;;
    status) pipeline_status ;;
    check) pipeline_check ;;
    intake)
        [ "$#" -ge 3 ] || { usage >&2; exit 2; }
        shift
        create_intake "$@"
        ;;
    create)
        [ "$#" -ge 4 ] || { usage >&2; exit 2; }
        shift
        create_pipeline "$@"
        ;;
    start | pass)
        [ "$#" -eq 2 ] || { usage >&2; exit 2; }
        action="$1"
        phase="$2"
        if [ "$action" = start ]; then start_phase "$phase"; else pass_phase "$phase"; fi
        ;;
    receipt) receipt_status ;;
    selftest) selftest ;;
    *) usage >&2; exit 2 ;;
esac
