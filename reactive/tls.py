import base64
import os

from shlex import split
from subprocess import check_call

from charms.reactive import set_state
from charms.reactive import when
from charms.reactive import when_not

from charmhelpers.core import hookenv
from charmhelpers.core.host import chdir
from charmhelpers.core.hookenv import resource_get

from charms.leadership import leader_set
from charms.leadership import leader_get


@when_not('tls.easyrsa.installed')
def install():
    '''Install the easy-rsa software that is required for this layer.'''
    path = None
    # Try to get the resource from Juju.
    try:
        path = resource_get('easyrsa')
    except Exception as e:
        hookenv.log('Unable to fetch resource:\n{0}'.format(e))
    if path:
        # Expand the archive in the charm directory creating an easy-rsa dir.
        untar = 'tar -xvzf {0} -C {1}'.format(path, hookenv.charm_dir())
        check_call(split(untar))
    else:
        hookenv.log('Resource easyrsa unavailble.')
        # git = 'git clone https://github.com/OpenVPN/easy-rsa.git'
        # hookenv.log(git)
        # check_call(split(git))
    # Create an absolute path to easy-rsa that is not affected by cwd.
    easy_rsa_directory = os.path.join(hookenv.charm_dir(), 'easy-rsa')
    # Create an absolute path to the easyrsa3 directory.
    easyrsa3_directory = os.path.join(easy_rsa_directory, 'easyrsa3')
    with chdir(easyrsa3_directory):
        check_call(split('./easyrsa --batch init-pki 2>&1'))
    set_state('tls.easyrsa.installed')


@when('tls.easyrsa.installed')
@when_not('tls.easyrsa.configured')
def configure_easyrsa():
    ''' Transitional state, allowing other layer(s) to modify config before we
    proceed generating the certificates and working with PKI. '''
    charm_dir = hookenv.charm_dir()
    # Create an absolute path to the file which will not be impacted by cwd.
    openssl_file = os.path.join(charm_dir, 'easy-rsa/easyrsa3/openssl-1.0.cnf')
    # Update EasyRSA configuration with the capacity to copy CSR Requested
    # Extensions through to the resulting certificate. This can be tricky,
    # and the implications are not fully clear on this.
    with open(openssl_file, 'r') as f:
        conf = f.readlines()
    # idempotency is a thing
    if 'copy_extensions = copy\n' not in conf:
        for idx, line in enumerate(conf):
            if '[ CA_default ]' in line:
                conf.insert(idx + 1, "copy_extensions = copy\n")
        with open(openssl_file, 'w+') as f:
            f.writelines(conf)
    set_state('tls.easyrsa.configured')


@when('tls.easyrsa.installed', 'tls.client.authorization.required')
@when('leadership.is_leader')
@when_not('tls.client.authorization.added')
def add_client_authorization():
    '''easyrsa has a default OpenSSL configuration that does not support
    client authentication. Append "clientAuth" to the server ssl certificate
    configuration. This is not default, to enable this in your charm set the
    reactive state 'tls.client.authorization.required'.
    '''
    hookenv.log('Configuring SSL PKI for clientAuth')

    # Get the absolute path to the charm directory.
    charm_dir = hookenv.charm_dir()
    # Create the relative path to the server file.
    server_file = 'easy-rsa/easyrsa3/x509-types/server'
    # Use an absolute path so current directory does not affect the result.
    openssl_config = os.path.join(charm_dir, server_file)
    hookenv.log('Updating {0}'.format(openssl_config))
    # Read the file in.
    with open(openssl_config, 'r') as f:
        existing_template = f.readlines()

    # Enable client and server authorization for certificates
    xtype = [w.replace('serverAuth', 'serverAuth, clientAuth') for w in existing_template]  # noqa
    # Write the configuration file back out.
    with open(openssl_config, 'w+') as f:
        f.writelines(xtype)
    set_state('tls.client.authorization.added')


@when('tls.easyrsa.configured')
@when('leadership.is_leader')
@when_not('tls.certificate.authority.available')
def create_certificate_authority():
    '''Return the CA and server certificates for this system. If the CA is
    empty, generate a self signged certificate authority.'''
    # Create an absolute path so current directory does not affect the result.
    easyrsa3_dir = os.path.join(hookenv.charm_dir(), 'easy-rsa/easyrsa3')
    with chdir(easyrsa3_dir):
        ca_file = 'pki/ca.crt'
        key_file = 'pki/private/ca.key'
        # Build a self signed Certificate Authority/
        # The Common Name (CN) for a certificate must be an IP or hostname.
        cn = hookenv.unit_public_ip()
        # Create a self signed CA with the CN, stored pki/ca.crt
        build_ca = './easyrsa --batch "--req-cn={0}" build-ca nopass 2>&1'
        check_call(split(build_ca.format(cn)))
        # Read the CA so we can return the contents from this method.
        with open(ca_file, 'r') as stream:
            certificate_authority = stream.read()
        with open(key_file, 'r') as stream:
            ca_key = stream.read()
        # Set these values on the leadership data.
        leader_set({'certificate_authority': certificate_authority})
        leader_set({'certificate_authority_key': ca_key})
        # Install the CA on this system as a trusted CA.
        install_ca(certificate_authority)
        client_cert, client_key = create_client_certificate()
        leader_set({'client_certificate': client_cert})
        leader_set({'client_key': client_key})
    set_state('tls.certificate.authority.available')


@when('client.available', 'tls.certificate.authority.available')
@when('leadership.is_leader')
def send_ca(tls):
    '''A certificates relationship has been established, read the CA off disk
    and send it on the certificates relationship.'''
    certificate_authority = leader_get('certificate_authority')
    tls.set_ca(certificate_authority)

    client_cert = leader_get('client_certificate')
    client_key = leader_get('client_key')
    tls.set_client_cert(client_cert, client_key)


@when('client.server.cert.requested')
def create_server_cert(tls):
    '''Create a server cert with the information from the relation object.'''
    requests = tls.get_server_requests()
    for unit_name, request in requests.items():
        cn = request.get('common_name')
        sans = request.get('sans')
        name = request.get('certificate_name')
        server_cert, server_key = create_server_certificate(cn, sans, name)
        tls.set_server_cert(unit_name, server_cert, server_key)


def create_server_certificate(cn, san_list, name='server'):
    '''Create the server certificate and server key from a common name, list of
    Subject Alt Names, and the certificate name.'''
    server_cert = None
    server_key = None
    # Create an absolute path so current directory does not affect the result.
    easyrsa3_dir = os.path.join(hookenv.charm_dir(), 'easy-rsa/easyrsa3')
    with chdir(easyrsa3_dir):
        # Create the path to the server certificate.
        cert_file = 'pki/issued/{0}.crt'.format(name)
        # Create the path to the server key.
        key_file = 'pki/private/{0}.key'.format(name)
        # Do not regenerate the server certificate if it already exists.
        if not os.path.isfile(cert_file) and not os.path.isfile(key_file):
            # Get a string compatible with easyrsa for the subject-alt-names.
            sans = get_sans(san_list)
            # Create a server certificate for the server based on the CN.
            server = './easyrsa --batch --req-cn={0} --subject-alt-name={1} ' \
                     'build-server-full {2} nopass 2>&1'.format(cn, sans, name)
            check_call(split(server))
        # Read the server certificate from the filesystem.
        with open(cert_file, 'r') as stream:
            server_cert = stream.read()
        # Read the server key from the filesystem.
        with open(key_file, 'r') as stream:
            server_key = stream.read()
    return server_cert, server_key


def create_client_certificate(name='client'):
    '''Create the client certificate and client key.'''
    client_cert = None
    client_key = None
    # Create an absolute path so current directory does not affect the result.
    easyrsa3_dir = os.path.join(hookenv.charm_dir(), 'easy-rsa/easyrsa3')
    with chdir(easyrsa3_dir):
        # Create a path to the client certificate.
        cert_file = 'pki/issued/{0}.crt'.format(name)
        # Create a path to the client key.
        key_file = 'pki/private/{0}.key'.format(name)
        # Do not regenerate the client certificate if it already exists.
        if not os.path.isfile(cert_file) and not os.path.isfile(key_file):
            # Create a client certificate and key.
            client = './easyrsa build-client-full {0} nopass 2>&1'.format(name)
            check_call(split(client))
        # Read the client certificate from the filesystem.
        with open(cert_file, 'r') as stream:
            client_cert = stream.read()
        with open(key_file, 'r') as stream:
            client_key = stream.read()
    return client_cert, client_key


def install_ca(certificate_authority):
    '''Install a certificiate authority on the system by calling the
    update-ca-certificates command.'''
    name = hookenv.service_name()
    ca_file = '/usr/local/share/ca-certificates/{0}.crt'.format(name)
    hookenv.log('Writing CA to {0}'.format(ca_file))
    # Write the contents of certificate authority to the file.
    with open(ca_file, 'w') as fp:
        fp.write(certificate_authority)
    # Update the trusted CAs on this system.
    check_call(['update-ca-certificates'])
    message = 'Generated ca-certificates.crt for {0}'.format(name)
    hookenv.log(message)


def get_sans(address_list=[]):
    '''Return a string suitable for the easy-rsa subjectAltNames.'''
    sans = []
    for address in address_list:
        if _is_ip(address):
            sans.append('IP:{0}'.format(address))
        else:
            sans.append('DNS:{0}'.format(address))
    return ','.join(sans)


def _is_ip(address):
    '''Return True if the address is an IP address, false otherwise.'''
    import ipaddress
    try:
        # This method will raise a ValueError if argument is not an IP address.
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def _decode(encoded):
    '''Base64 decode a string by handing any decoding errors.'''
    try:
        return base64.b64decode(encoded)
    except:
        hookenv.log('Error decoding string {0}'.format(encoded))
        raise
