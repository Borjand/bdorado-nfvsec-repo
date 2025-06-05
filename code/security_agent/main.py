import os
import time
import threading
import subprocess
import random
import logging
from json import loads, dumps
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import NoBrokersAvailable
from pyroute2 import IPRoute

# --- Logging setup ---
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# --- Deactivate Kafka logging verbosity ---
logging.getLogger("kafka").setLevel(logging.CRITICAL + 1)
logging.getLogger("kafka.conn").setLevel(logging.CRITICAL + 1)
logging.getLogger("kafka.client").setLevel(logging.CRITICAL + 1)

# --- Read environment variables ---
vnf_id = os.getenv("VNF_ID", "VNF_A")
public_key = os.getenv("PUBLIC_KEY", "default-pkey")
broker_address = os.getenv("BROKER_ADDRESS", "kafka:9094")
vnffg_topic = os.getenv("VNF_FG_TOPIC", "vnffg_topic")
declaration_timeout = int(os.getenv("DECLARATION_TIMEOUT_MS", "1000"))
preferred_mechanisms = os.getenv("PREFERRED_MECHANISMS", "MACsec/manual,IPsec/manual").split(',')

# --- Wait for Kafka to become available ---
def wait_for_kafka(broker, retries=10, delay=2):
    for attempt in range(retries):
        try:
            consumer = KafkaConsumer(
                bootstrap_servers=[broker],
                request_timeout_ms=1000,
                consumer_timeout_ms=1000
            )
            consumer.close()
            logger.info(f"Kafka is available (attempt {attempt + 1})")
            return
        except NoBrokersAvailable:
            logger.warning(f"Kafka not available, retrying in {delay}s (attempt {attempt + 1}/{retries})")
            time.sleep(delay)
    raise RuntimeError("Kafka not available after maximum retries.")

# --- Generate symmetric key ---
def get_random_key(n_bits):
    return hex(random.getrandbits(n_bits))[2:]

# --- Generate MACsec key ID ---
def get_macsec_key_id(index):
    return str(index // 10) + str(index % 10)

# --- Generate IPsec SPI (Security Parameter Index) ---
def generate_spi(vnf_id):
    return hex(abs(hash(vnf_id)) % (2**32))

# --- Configure MACsec manually ---
def macsec_manual(vl_id, declarations, interface, prefixlen):
    macsec_if_name = f"macsec_{interface['name']}"
    logger.info(f"Configuring MACsec for {vl_id} on {interface['name']}")

    try:
        subprocess.run(['ip', 'link', 'add', 'link', interface['name'], macsec_if_name, 'type', 'macsec'], check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to create MACsec interface: {e}")
        return

    for declaration in declarations:
        for mech in declaration['security_mechanisms']:
            if mech['mechanism'] == 'MACsec/manual':
                params = mech['parameters']
                if declaration['vnf_id'] == vnf_id:
                    subprocess.run(['ip', 'macsec', 'add', macsec_if_name, 'tx', 'sa', '0', 'pn', '100', 'on', 'key', params['key_id'], params['key']], check=True)
                else:
                    subprocess.run(['ip', 'macsec', 'add', macsec_if_name, 'rx', 'address', params['MAC_address'], 'port', '1'], check=True)
                    subprocess.run(['ip', 'macsec', 'add', macsec_if_name, 'rx', 'address', params['MAC_address'], 'port', '1', 'sa', '0', 'pn', '100', 'on', 'key', params['key_id'], params['key']], check=True)
                break

    ip = IPRoute()
    try:
        link_index = ip.link_lookup(ifname=interface['name'])[0]
        ip.addr('del', index=link_index, address=interface['IP_address'], mask=prefixlen)
        logger.info(f"Removed IP {interface['IP_address']}/{prefixlen} from {interface['name']}")

        macsec_index = ip.link_lookup(ifname=macsec_if_name)[0]
        ip.addr('add', index=macsec_index, address=interface['IP_address'], mask=prefixlen)
        logger.info(f"Assigned IP {interface['IP_address']}/{prefixlen} to {macsec_if_name}")

        ip.link('set', index=macsec_index, state='up')
    except Exception as e:
        logger.error(f"Failed to migrate IP: {e}")

# --- Placeholder: Configure IPsec manually ---
def ipsec_manual(vl_id, declarations, interface):
    logger.info(f"[TODO] Configure IPsec/manual for {vl_id} on {interface['name']}")
    # This is a placeholder for actual implementation

def select_security_mechanism(declarations, preferred_mechanisms):
    """
    Select a security mechanism supported by all VNFs in the virtual link.

    If only one mechanism is common, it is selected directly.
    If multiple are available, the selection follows the preference list
    of the VNF with the lexicographically smallest ID (to ensure deterministic behavior).
    """
    logger.info(f"Selecting security mechanism based on preferences: {preferred_mechanisms}")

    # Collect supported mechanisms for each VNF
    supported_mechs_by_vnf = {}
    preferences_by_vnf = {}

    for declaration in declarations:
        vnf = declaration["vnf_id"]
        mechs = {mech["mechanism"] for mech in declaration["security_mechanisms"]}
        supported_mechs_by_vnf[vnf] = mechs
        preferences_by_vnf[vnf] = [mech["mechanism"] for mech in declaration["security_mechanisms"]]

        logger.info(f"VNF {vnf} supports mechanisms: {mechs}")

    # Determine common mechanisms among all VNFs
    common_mechs = set.intersection(*supported_mechs_by_vnf.values())
    logger.info(f"Common mechanisms supported by all VNFs: {common_mechs}")

    if not common_mechs:
        logger.error("No common security mechanism could be agreed upon.")
        return None

    if len(common_mechs) == 1:
        selected = next(iter(common_mechs))
        logger.info(f"Only one common mechanism found: {selected}")
        return selected

    # Deterministically select the VNF with the lowest ID
    selected_vnf = sorted(preferences_by_vnf.keys())[0]
    logger.info(f"Using preference list of VNF with lowest ID: {selected_vnf}")

    # Pick the first mechanism from its list that is in the common set
    for mech in preferences_by_vnf[selected_vnf]:
        if mech in common_mechs:
            logger.info(f"Selected mechanism: {mech}")
            return mech

    logger.warning("Could not match any mechanism from the lowest-ID VNF's preference list.")
    return None

# --- Build declaration based on preferred mechanisms ---
def build_declaration(preferences, interface, index):
    mechanisms = []

    for mech in preferences:
        if mech == 'MACsec/manual':
            mechanisms.append({
                'mechanism': 'MACsec/manual',
                'parameters': {
                    'MAC_address': interface['MAC_address'],
                    'key': get_random_key(128),
                    'key_id': get_macsec_key_id(index)
                }
            })
        elif mech == 'IPsec/manual':
            mechanisms.append({
                'mechanism': 'IPsec/manual',
                'parameters': {
                    'IP_address': interface['IP_address'],
                    'spi': hex(random.getrandbits(32)),
                    'encryption_key': get_random_key(256),
                    'auth_key': get_random_key(256)
                }
            })

    return {
        'vnf_id': vnf_id,
        'security_mechanisms': mechanisms,
        'digital_signature': ''
    }


# --- Worker thread to apply security settings ---
def security_agent_worker(vl, interface, prefixlen):
    logger.info(f"Worker started for link {vl['vl_id']}")
    messages = KafkaConsumer(
        vl['vl_id'],
        bootstrap_servers=[broker_address],
        auto_offset_reset='earliest',
        consumer_timeout_ms=declaration_timeout,
        value_deserializer=lambda x: loads(x.decode('utf-8'))
    )

    declarations = [msg.value for msg in messages]
    logger.info(f"Declarations received: {len(declarations)}")

    selected = select_security_mechanism(declarations, preferred_mechanisms)
    logger.info(f"Selected security mechanism for {vl['vl_id']}: {selected}")

    if selected == 'MACsec/manual':
        macsec_manual(vl['vl_id'], declarations, interface, prefixlen)
    elif selected == 'IPsec/manual':
        ipsec_manual(vl['vl_id'], declarations, interface)

# --- Main logic ---
def main():
    wait_for_kafka(broker_address)

    producer = KafkaProducer(
        bootstrap_servers=[broker_address],
        value_serializer=lambda x: dumps(x).encode('utf-8')
    )

    consumer = KafkaConsumer(
        vnffg_topic,
        bootstrap_servers=[broker_address],
        value_deserializer=lambda x: loads(x.decode('utf-8'))
    )

    for vnf_fg in consumer:
        vnf_fg = vnf_fg.value
        for vl in vnf_fg:
            for index, neighbour in enumerate(vl['neighbours']):
                if neighbour['vnf_id'] == vnf_id:
                    logger.info(f"Found matching link for {vnf_id}: {neighbour}")

                    ip = IPRoute()
                    if_name = neighbour['interface']
                    link_index = ip.link_lookup(ifname=if_name)[0]
                    MAC_address = ip.get_links(link_index)[0].get_attr('IFLA_ADDRESS')
                    addr_info = ip.get_addr(index=link_index, family=2)[0]
                    IP_address = addr_info.get_attr('IFA_ADDRESS')
                    prefixlen = addr_info['prefixlen']

                    interface = {
                        'name': if_name,
                        'MAC_address': MAC_address,
                        'IP_address': IP_address
                    }

                    key = get_random_key(128)
                    key_id = get_macsec_key_id(index)
                    spi = generate_spi(vnf_id)

                    declaration = build_declaration(preferred_mechanisms, interface, index)

                    producer.send(vl['vl_id'], value=declaration)
                    producer.flush()
                    logger.info(f"Declaration published in topic {vl['vl_id']}: {declaration}")

                    worker = threading.Thread(target=security_agent_worker, name=vl['vl_id'], args=(vl, interface, prefixlen))
                    worker.start()
                    break

if __name__ == "__main__":
    main()
