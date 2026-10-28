# Check Point Copy References

A Bash script for Check Point Security Management Server (SMS) and Multi-Domain Server (MDS) that adds **OBJECT2** wherever **OBJECT1** is referenced directly in supported groups or Access Control rule fields.

OBJECT1 and OBJECT2 can each be a **host**, **network**, or **regular group**. The script follows nested groups to avoid redundant rule changes and checks for circular group membership.

## Requirements

- Run in **Expert mode as root** on the Management Server or MDS.
- Check Point `mgmt_cli` and `jq` (or `$CPDIR/jq/jq`).
- Bash 4 or later.
- Management API access for the local administrator (`mgmt_cli -r true`). No username or password is requested.

## Usage

```bash
chmod +x checkpoint_copy_references.sh

# Single-domain SMS: preview only
./checkpoint_copy_references.sh HOST_OLD HOST_NEW

# Multi-Domain Server: preview only
./checkpoint_copy_references.sh -d "Domain1" HOST_OLD HOST_NEW

# Apply changes and publish
./checkpoint_copy_references.sh -d "Domain1" HOST_OLD HOST_NEW --apply

# Groups are also supported
./checkpoint_copy_references.sh GROUP_OLD GROUP_NEW --apply
```

Omit `-d` on a single-domain SMS. On an MDS, provide the intended domain name or identifier with `-d`.

By default, the script produces a **dry-run change plan**. Nothing is modified until you supply `--apply`.

## Behavior

1. Resolves both object names to their Management API UIDs.
2. Finds groups and Access Control rules directly referencing OBJECT1.
3. Plans additions of OBJECT2 to the relevant groups first.
4. Skips direct rule additions when OBJECT2 is already present or is covered through a referenced group (including nested groups).
5. Checks for duplicate memberships and skips additions that would create circular group references.
6. With `--apply`, performs the planned changes in one Management API session and **publishes** the session once.

## Scope and limitations

- Updates **regular groups** and **Access Control** rule **source/destination** fields.
- Does **not directly edit NAT rules**, Threat Prevention rules, HTTPS Inspection rules, or special groups.
- Changing a group that a NAT rule references can **indirectly change that NAT rule's behavior**. Review the dry-run plan with this in mind.
- Duplicate detection is based on object UIDs and group membership, **not on overlapping IP ranges**.
- The script **does not install policy**. Install the appropriate policy separately after reviewing the changes.
- Direct references to unsupported object/rule types are reported as warnings.

Run `./checkpoint_copy_references.sh --help` for the complete argument list, including `--max-nodes` and `--publish-timeout`.

> **Safety tip:** Run without `--apply` first and verify the change plan, especially when objects are reused in shared or nested groups.
