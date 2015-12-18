import base64
import os
import shutil
import socket
import tempfile

from shlex import split
from subprocess import check_call

from charms.reactive import hook
from charms.reactive import remove_state
from charms.reactive import set_state
from charms.reactive import when
from charms.reactive import when_not

from charmhelpers.core import hookenv
from charmhelpers.core import unitdata
from charmhelpers.core.hookenv import is_leader
from charmhelpers.core.hookenv import leader_set
from charmhelpers.core.hookenv import leader_get
from contextlib import contextmanager


@when_not('easyrsa installed')
def install():
    '''Install the easy-rsa software that is required for this layer.'''
    apt = 'apt-get install -y git openssl'
    check_call(split(apt))
    if os.path.isdir('easy-rsa'):
        shutil.rmtree('easy-rsa')
    git = 'git clone https://github.com/OpenVPN/easy-rsa.git'
    hookenv.log(git)
    check_call(split(git))
    with chdir('easy-rsa/easyrsa3'):
        check_call(split('./easyrsa --batch init-pki 2>&1'))
    set_state('easyrsa installed')


@when('easyrsa installed')
def check_ca_status():
    '''Called when the configuration values have changed.'''
    config = hookenv.config()
    if config.changed('root_certificate'):
        remove_state('certificate authority available')
        if is_leader():
            root_cert = _decode(config.get('root_certificate'))
            hookenv.log('Leader is creating the certificate authority.')
            certificate_authority = create_certificate_authority(root_cert)
            leader_set({'certificate_authority': certificate_authority})
            install_ca(certificate_authority)
            # The leader can create the server certificate based on CA.
            hookenv.log('Leader is creating server certificate.')
            create_server_certificate()


@hook('leader-settings-changed')
def leader_settings_changed():
    '''When the leader settings changes the followers can get the certificate
    and install the certificate on their own system.'''
    # Get the current CA value from leader_get.
    ca = leader_get('certificate_authority')
    if ca:
        hookenv.log('Installing the CA.')
        install_ca(ca)


@when('create certificate signing request')
def create_csr(tls):
    '''Create a certificate signing request (CSR). Only the followers need to
    run this operation.'''
    if not is_leader():
        # Must remove the path characters from the unit name.
        path_name = _path_safe_name(hookenv.local_unit())
        # The Common Name is the public address of the system.
        cn = hookenv.unit_public_ip()
        hookenv.log('Creating the CSR for {0}'.format(cn))
        with chdir('easy-rsa/easyrsa3'):
            sans = get_sans()
            # Create a CSR for this system with the subject and SANs.
            gen_req = './easyrsa --batch --req-cn={0} --subject-alt-name={1} ' \
                      'gen-req {2} nopass 2>&1'.format(cn, sans, path_name)
            check_call(split(gen_req))
            # Read the CSR file.
            req_file = 'pki/reqs/{0}.req'.format(path_name)
            with open(req_file, 'r') as fp:
                csr = fp.read()
            # Set the CSR on the relation object.
            tls.set_csr(csr)
    else:
        hookenv.log('The leader does not need to create a CSR.')


@when('sign certificate signing request')
def import_sign(tls):
    '''Import and sign the certificate signing request (CSR). Only the leader
    can sign the requests.'''
    if is_leader():
        hookenv.log('The leader needs to sign the csr requests.')
        # Get all the requests that are queued up to sign.
        csr_map = tls.get_csr_map()
        # Iterate over the unit names related to CSRs.
        for unit_name, csr in csr_map.items():
            path_name = _path_safe_name(unit_name)
            with chdir('easy-rsa/easyrsa3'):
                temp_file = tempfile.NamedTemporaryFile(suffix='.csr')
                with open(temp_file.name, 'w') as fp:
                    fp.write(csr)
                if not os.path.isfile('pki/reqs/{0}.req'.format(path_name)):
                    hookenv.log('Importing csr from {0}'.format(path_name))
                    # Create the command to import the request using path name.
                    import_req = './easyrsa --batch import-req {0} {1} 2>&1'
                    # easy-rsa import-req /tmp/temporary.csr path_name
                    check_call(split(import_req.format(temp_file.name,
                                                       path_name)))
                if not os.path.isfile('pki/issued/{0}.crt'.format(path_name)):
                    hookenv.log('Signing csr from {0}'.format(path_name))
                    # Create a command that signs the request.
                    sign_req = './easyrsa --batch sign-req server {0} 2>&1'
                    check_call(split(sign_req.format(path_name)))
                # Read in the signed certificate.
                cert_file = 'pki/issued/{0}.crt'.format(path_name)
                with open(cert_file, 'r') as fp:
                    certificate = fp.read()
                hookenv.log('Leader sending signed certificate over relation.')
                # Send the certificate over the relation.
                tls.set_cert(unit_name, certificate)


@when('signed certificate available')
@when_not('server certificate available')
def copy_server_cert(tls):
    '''Copy the certificate from the relation to the key value store.'''
    # Get the signed certificate from the relation object.
    cert = tls.get_signed_cert()
    if cert:
        set_server_cert(cert)
        remove_state('signed certificate available')


def set_server_cert(server_cert):
    '''Set the serve certificate on the key value store of the unit, and set
    the final state for layers to consume.'''
    # Set cert on the unitdata key value store so other layers can get it.
    unitdata.kv().set('tls.server.certificate', server_cert)
    # Set the final state for the other layers to know when they can
    # retrieve the server certificate.
    set_state('server certificate available')


@when_not('certificate authority available')
@when('easyrsa installed')
def create_certificate_authority(certificate_authority=None):
    '''Return the CA and server certificates for this system. If the CA is
    empty, generate a self signged certificate authority.'''
    # followers are not special, do not generate a ca
    if not is_leader():
        return
    with chdir('easy-rsa/easyrsa3'):
        ca_file = 'pki/ca.crt'
        # Check if an old CA exists.
        if os.path.isfile(ca_file):
            # Initialize easy-rsa (by deleting old pki) so a new CA can be created.
            init = './easyrsa --batch init-pki 2>&1'
            check_call(split(init))
        # When the CA is not null write the CA file..
        if certificate_authority:
            # Write the certificate authority from configuration.
            with open(ca_file, 'w') as fp:
                fp.write(certificate_authority)
        else:
            # The Certificate Authority does not exist, build a self signed one.
            # The Common Name (CN) for a certificate must be an IP or hostname.
            cn = hookenv.unit_public_ip()
            # Create a self signed CA with the CN, stored pki/ca.crt
            build_ca = './easyrsa --batch "--req-cn={0}" build-ca nopass 2>&1'
            check_call(split(build_ca.format(cn)))
            # Read the CA so we can return the contents from this method.
            with open(ca_file, 'r') as fp:
                certificate_authority = fp.read()
    set_state('certificate authority available')
    return certificate_authority


def create_server_certificate():
    '''Create the server certificate.'''
    # Use the public ip as the Common Name for the server certificate.
    cn = hookenv.unit_public_ip()
    with chdir('easy-rsa/easyrsa3'):
        server_file = 'pki/issued/{0}.crt'.format(cn)
        # Do not regenerate the server certificate if it already exists.
        if not os.path.isfile(server_file):
            # Create a server certificate for the server based on the CN.
            server = './easyrsa --batch --req-cn={0} --subject-alt-name={1} ' \
                     'build-server-full {0} nopass 2>&1'.format(cn, get_sans())
            check_call(split(server))
            # Read the server certificate from the filesystem.
            with open(server_file, 'r') as fp:
                cert = fp.read()
            set_server_cert(cert)


def install_ca(certificate_authority):
    '''Install a certificiate authority on the system.'''
    ca_file = '/usr/local/share/ca-certificates/{0}.crt'.format(
        hookenv.service_name())
    # Write the contents of certificate authority to the file.
    with open(ca_file, 'w') as fp:
        fp.write(certificate_authority)
    # Update the trusted CAs on this system.
    check_call(split('update-ca-certificates 2>&1'))


def get_sans(ip_list=None, dns_list=None):
    '''Return a string suitable for the easy-rsa subjectAltNames, if both
    ip_list and dns_list parameters are empty the method will generate a valid
    sans string with the public IP, private IP, and hostname of THIS system.'''
    sans = []
    for ip in ip_list or []:
        sans.append('IP:{0}'.format(ip))
    for dns in dns_list or []:
        sans.append('DNS:{0}'.format(dns))
    if not sans:
        # Create a default subject alternate name (SAN) string for this system.
        sans.append('IP:{0},IP:{1},DNS:{2}'.format(hookenv.unit_public_ip(),
                                                   hookenv.unit_private_ip(),
                                                   socket.gethostname()))
    return ','.join(sans)


def _decode(encoded):
    '''Base64 decode a string by handing any decoding errors.'''
    try:
        return base64.b64decode(encoded)
    except:
        hookenv.log('Error decoding string {0}'.format(encoded))
        raise


def _path_safe_name(unit_name):
    '''Remove the special characters in a unit name (eg. tls/1 -> tls_1)'''
    return unit_name.replace('/', '_')


@contextmanager
def chdir(path):
    '''Change the current working directory to a different directory for a code
    block and return the previous directory after the block exits.'''
    old_dir = os.getcwd()
    os.chdir(path)
    yield
    os.chdir(old_dir)
