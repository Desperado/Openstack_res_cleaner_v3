#!/usr/bin/env python
# -*- coding: utf-8 -*-

from keystoneclient.v3 import client as ks_client
from novaclient.v1_1 import client as nv_client
from cinderclient.v1 import client as cr_client
from neutronclient.neutron import client as nr_client
from glanceclient import Client as gl_client
import time
import logging
from optparse import OptionParser


parser = OptionParser()
parser.add_option('-a', '--admin', dest='admin_username')
parser.add_option('-p', '--password', dest='admin_password')
parser.add_option('-e', '--endpoint', dest='endpoint')
parser.add_option('-u', '--username', dest='user_name')

options, args = parser.parse_args()
options_dict = vars(options)

LOG_LEVEL='INFO'


class ColorizingStreamHandler(logging.StreamHandler):
    color_map = {
        'black': 0,
        'red': 1,
        'green': 2,
        'yellow': 3,
        'blue': 4,
        'magenta': 5,
        'cyan': 6,
        'white': 7,
    }
    level_map = {
        logging.DEBUG: (None, 'yellow', True),
        logging.WARNING: (None, 'green', False),
        logging.INFO: (None, 'blue', True),
        logging.ERROR: (None, 'red', True),
        logging.CRITICAL: ('red', 'white', True),
    }
    csi = '\x1b['
    reset = '\x1b[0m'

    @property
    def is_tty(self):
        isatty = getattr(self.stream, 'isatty', None)
        return isatty and isatty()

    def emit(self, record):
        try:
            message = self.format(record)
            stream = self.stream
            if not self.is_tty:
                stream.write(message)
            else:
                self.output_colorized(message)
            stream.write(getattr(self, 'terminator', '\n'))
            self.flush()
        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.handleError(record)

    def output_colorized(self, message):
        self.stream.write(message)

    def colorize(self, message, record):
        if record.levelno in self.level_map:
            bg, fg, bold = self.level_map[record.levelno]
            params = []
            if bg in self.color_map:
                params.append(str(self.color_map[bg] + 40))
            if fg in self.color_map:
                params.append(str(self.color_map[fg] + 30))
            if bold:
                params.append('1')
            if params:
                message = ''.join((self.csi, ';'.join(params),
                                   'm', message, self.reset))
        return time.strftime("%d-%m-%Y-%H-%M-%S") + ': ' + message

    def format(self, record):
        message = logging.StreamHandler.format(self, record)
        if self.is_tty:
            # Don't colorize any traceback
            parts = message.split('\n', 1)
            parts[0] = self.colorize(parts[0], record)
            message = '\n'.join(parts)
        return message


def set_logger():
    root = logging.getLogger()
    root.setLevel(LOG_LEVEL)
    root.addHandler(ColorizingStreamHandler())

ADMIN_USERNAME = options_dict['admin_username']
ADMIN_PASSWORD = options_dict['admin_password']
HOSTNAME = options_dict['endpoint']
USER_NAME = options_dict['user_name']

ADMIN_DOMAIN_NAME = 'Default'
AUTH_URL = HOSTNAME

set_logger()


def authenticate(username, password, auth_url, domain_name=None, project_id=None):
    return ks_client.Client(username=username, password=password,
                            domain_name=domain_name,
                            project_id=project_id,
                            auth_url=auth_url)


def get_user_project_id(auth_client, user_name):
    users = auth_client.users.list()
    for user in users:
        if user.name == user_name:
            project_id = user.default_project_id
            logging.debug(u'DEBUG: User Project ID is - {}'.format(project_id))
            return project_id


def get_admin_id(auth_client, admin_name):
    users=auth_client.users.list()
    for user in users:
        if user.name == admin_name:
            return user.id


def get_role_id(auth_client, role_name):
    roles=auth_client.roles.list()
    for role in roles:
        if role.name == role_name:
            return role.id


def grant_admin_role_in_project(auth, admin_role_id, admin_id, project_id):
    auth.roles.grant(admin_role_id, user=admin_id, project=project_id)


def revoke_admin_role_in_project(auth, admin_role_id, admin_id, project_id):
    auth.roles.revoke(admin_role_id, user=admin_id, project=project_id)


def get_compute_admin(auth_client, admin_username, user_project_id):
    compute_endpoints = \
        auth_client.service_catalog.get_endpoints('compute', 'public')
    compute_url = compute_endpoints['compute'][0]['url']
    nv_cl = nv_client.Client(admin_username, auth_client.auth_token,
                             user_project_id, auth_url=compute_url,
                             auth_token=auth_client.auth_token)
    nv_cl.client.auth_token = auth.auth_token
    nv_cl.client.management_url = compute_url
    return nv_cl


def get_compute_client(auth_client, admin_username, user_project_id):
    compute_endpoints = \
        auth_client.service_catalog.get_endpoints('compute', 'public')
    compute_url = compute_endpoints['compute'][0]['url']
    logging.debug(u'DEBUG: User compute url is - {}'.format(compute_url))
    nv_cl = nv_client.Client(admin_username, auth_client.auth_token,
                             user_project_id, auth_url=compute_url,
                             auth_token=auth_client.auth_token)
    nv_cl.client.auth_token = auth_client.auth_token
    nv_cl.client.management_url = compute_url
    return nv_cl


def get_neutron_client(auth_client):
    network_endpoints = \
        auth_client.service_catalog.get_endpoints('network', 'public')
    NEUTRON_URL = network_endpoints['network'][0]['url']
    nr_cl = nr_client.Client('2.0', endpoint_url=NEUTRON_URL,
                             token=auth_client.auth_token)
    return nr_cl


def get_glance_client(auth_client):
    image_endpoints = \
        auth_client.service_catalog.get_endpoints('image', 'public')
    GLANCE_URL = image_endpoints['image'][0]['url']
    gl_cl = gl_client('1', endpoint=GLANCE_URL, token=auth_client.auth_token)
    return gl_cl


def get_cinder_client(auth_client, admin_username, user_project_id):
    volume_endpoints = \
        auth_client.service_catalog.get_endpoints('volume', 'public')
    cinder_url = volume_endpoints['volume'][0]['url']
    logging.debug(u'DEBUG: User cinder url is - {}'.format(cinder_url))
    c_cl = cr_client.Client(admin_username, auth_client.auth_token,
                            user_project_id, auth_url=cinder_url)
    c_cl.client.auth_token = auth_client.auth_token
    c_cl.client.management_url = cinder_url
    return c_cl


def delete_servers(compute_client):
    """Delete all servers(instances)"""

    instance_list = compute_client.servers.list()
    for server in instance_list:
        server.reset_state()
        logging.warn(u'WARN: Instance: {} deleting'.format(server.name))
        server.delete()
        time.sleep(2)
    while compute_client.servers.list():
        time.sleep(5)
        logging.warn(u'WARN: Instances still deleting: '
                     u'{}'.format(compute_client.servers.list()))


def delete_keypairs(compute_client):
    keypairs_list = compute_client.keypairs.list()
    logging.debug(u'DEBUG: keypairs list is - {}'.format(keypairs_list))
    for keypair in keypairs_list:
        logging.warn(u'WARN: Deleting keypair: {} '.format(keypair.name))
        keypair.delete()


def delete_security_groups(compute_client):
    security_groups = compute_client.security_groups.list()
    for group in security_groups:
        logging.warn(u'WARN: Deleting Security Group: '
                         u'{}'.format(group.name))
        group.delete()


def delete_volumes(cinder_client):
    volume_list = cinder_client.volumes.list()
    logging.debug('Debug: List volumes: {}'.format(volume_list))
    for volume in volume_list:
        logging.warn(u'WARN: Deleting Volume: '
                     u'{}'.format(volume.display_name))
        volume.delete()
    while cinder_client.volumes.list():
        time.sleep(2)
        logging.warn(u'WARN: Volumes still deleting: '
                     u'{}'.format(volume_list))


def delete_volumes_snapshots(cinder_client):
    sn_from_volume_list = cinder_client.volume_snapshots.list()
    logging.debug('Debug: List snapshots from volume: '
                  '{}'.format(sn_from_volume_list))
    for snap in sn_from_volume_list:
        logging.warn(u'WARN: Deleting Snapshot from volume: '
                     u'{}'.format(snap.display_name))
        snap.delete()
    while cinder_client.volume_snapshots.list():
        time.sleep(2)
        logging.warn(u'WARN: Volume snapshots still deleting: '
                     u'{}'.format(cinder_client.volume_snapshots.list()))


def delete_images(glance_client):

    images_list = glance_client.images.findall()
    my_images = []
    for image in images_list:
        if image.owner == user_project_id:
            my_images.append(image)
    logging.debug(u'Debug: User Images list: {}'.format(my_images))
    for image in my_images:
        logging.warn(u'WARN: Deleting user image: {}'.format(image.name))
        image.delete()
        time.sleep(2)


def clean_networks(neutron_client, user_project_id):
    """Delete networks, floating IPs, routers, subnets"""

    floating_ips = neutron_client.list_floatingips()['floatingips']
    networks = neutron_client.list_networks()['networks']
    routers = neutron_client.list_routers()['routers']
    subnets = neutron_client.list_subnets()['subnets']
    ports = neutron_client.list_ports()['ports']
    security_group_rules = neutron_client.list_security_group_rules()['security_group_rules']

    for ip in floating_ips:
        if ip['tenant_id'] == user_project_id:
            neutron_client.delete_floatingip(ip['id'])
            logging.warn(u'WARN: Deleting floating IP')

    mynetworks = []
    mysubnets = []
    myrouters = []
    myports = []
    my_security_group_rules = []

    for network in networks:
        if network['tenant_id'] == user_project_id:
            mynetworks.append(network)
    for subnet in subnets:
        if subnet['tenant_id'] == user_project_id:
            mysubnets.append(subnet)

    for router in routers:
        if router['tenant_id'] == user_project_id:
            myrouters.append(router)

    for port in ports:
        if port['tenant_id'] == user_project_id:
            myports.append(port)

    for rule in security_group_rules:
        if rule['tenant_id'] == user_project_id:
            my_security_group_rules.append(rule)

    for rule in my_security_group_rules:
        logging.warn(u'WARN: Removing security group rule')
        neutron_client.delete_security_group_rule(rule['id'])

    for router in myrouters:
        logging.warn(u'WARN: Removing router interfaces')
        for port in ports:
            if port['device_id'] == router['id']:
                subnet = port['fixed_ips'][0]['subnet_id']
                try:
                    body = {'subnet_id': subnet}
                    neutron_client.remove_interface_router(router['id'], body)
                    time.sleep(0.5)
                except Exception:
                    pass
        logging.warn(u'WARN: Deleting router: {}'.format(router['name']))
        neutron_client.delete_router(router['id'])

    for subnet in mysubnets:
        logging.warn(u'WARN: Deleting subnet: {}'.format(subnet['name']))
        neutron_client.delete_subnet(subnet['id'])
        time.sleep(0.5)

    for network in mynetworks:
        logging.warn(u'WARN: Deleting network: {}'.format(network['name']))
        neutron_client.delete_network(network['id'])
        time.sleep(0.5)


def up_network_qoutas(neutron_client, user_project_id):
    qouta_body = {u'quota': {u'subnet': 10, u'network': 10, u'floatingip': 50,
                             u'security_group_rule': 100, u'security_group': 10,
                             u'router': 10, u'port': 50}}
    neutron_client.update_quota(user_project_id, qouta_body)


def lower_network_qoutas(neutron_client, user_project_id):
    qouta_body = {u'quota': {u'subnet': 0, u'network': 0, u'floatingip': 0,
                             u'security_group_rule': 4, u'security_group': 1,
                             u'router': 0, u'port': 0}}
    neutron_client.update_quota(user_project_id, qouta_body)


def up_qoutas(compute_client):
    compute_client.quotas.update(user_project_id, cores=6, fixed_ips=-1,
                                 floating_ips=6, injected_file_content_bytes=10240,
                                 injected_file_path_bytes=255, injected_files=5,
                                 instances=6, key_pairs=10, metadata_items=128,
                                 ram=16384, security_group_rules=5, security_groups=5)


def lower_volume_qoutas(cinder_client):
    cinder_client.quotas.update(user_project_id, gigabytes=0, snapshots=0, volumes=0)


def lower_qoutas(compute_client):
    compute_client.quotas.update(user_project_id, cores=0, fixed_ips=0,
                                 floating_ips=0, injected_file_content_bytes=0,
                                 injected_file_path_bytes=0, injected_files=0,
                                 instances=0, key_pairs=0, metadata_items=0, ram=0,
                                 security_group_rules=0, security_groups=1)


auth = authenticate(ADMIN_USERNAME, ADMIN_PASSWORD, AUTH_URL, ADMIN_DOMAIN_NAME, None)


admin_id = get_admin_id(auth, ADMIN_USERNAME)
admin_role_id = get_role_id(auth, 'admin')
user_project_id = get_user_project_id(auth, USER_NAME)
grant_admin_role_in_project(auth, admin_role_id, admin_id, user_project_id)
auth = authenticate(ADMIN_USERNAME, ADMIN_PASSWORD, AUTH_URL, None, user_project_id)
compute_cl = get_compute_client(auth, ADMIN_USERNAME, user_project_id)
cinder_cl = get_cinder_client(auth, ADMIN_USERNAME, user_project_id)
neutron_cl = get_neutron_client(auth)
glance_cl = get_glance_client(auth)

logging.info('<== User images deletion ==>')
delete_images(glance_cl)

logging.info('<== Instances deletion ==>')
delete_servers(compute_cl)

logging.info('<== Volume snapshots deletion ==>')
delete_volumes_snapshots(cinder_cl)

logging.info('<== Volumes deletion ==>')
delete_volumes(cinder_cl)

logging.info('<== Limiting volume quotas ==>')
lower_volume_qoutas(cinder_cl)

# Disable deletion of keypairs
# logging.info('<== Keypairs deletion ==>')
# delete_keypairs(compute_cl)

logging.info('<== Limiting compute quotas ==>')
lower_qoutas(compute_cl)

logging.info('<== Networks deletion ==>')
clean_networks(neutron_cl, user_project_id)

logging.info('<== Security groups deletion ==>')
delete_security_groups(compute_cl)


logging.info('<== Limiting network quotas ==>')
lower_network_qoutas(neutron_cl, user_project_id)

### Up qoutas again - for testing only ###
#up_qoutas(compute_cl)
#up_network_qoutas(neutron_cl, user_project_id)

logging.info('<== Revoke admin role in project ==>')

revoke_admin_role_in_project(auth, admin_role_id, admin_id, user_project_id)
logging.info('<== Clean resources completed ==>')
