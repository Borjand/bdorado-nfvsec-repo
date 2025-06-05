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

# --- Reduce Kafka logging verbosity ---
logging.getLogger("kafka").setLevel(logging.WARNING)
logging.getLogger("kafka.conn").setLevel(logging.WARNING)
logging.getLogger("kafka.client").setLevel(logging.WARNING)

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

# --- Select security mechanism based on consensus ---
def select_security_mechanism(declarations, preferences):
    """
    Selects the best common mechanism among all declarations, based on local preference order.
    Logs each step of the consensus process.
    """
    logger.info(f"Selecting security mechanism based on preferences: {preferences}")
    
    sets_of_mechs = []
    for decl in declarations:
        mechs = {mech['mechanism'] for mech in decl['security_mechanisms']}
        logger.info(f"VNF {decl['vnf_id']} supports mechanisms: {mechs}")
        sets_of_mechs.append(mechs)

    if not sets_of_mechs:
        logger.warning("No mechanisms declared by any VNF.")
        return None

    common_mechanisms = set.intersection(*sets_of_mechs)
    logger.info(f"Common mechanisms supported by all VNFs: {common_mechanisms}")

    for preferred in preferences:
        if preferred in common_mechanisms:
            logger.info(f"Selected mechanism: {preferred}")
            return preferred

    logger.warning("No common mechanism found among preferences and declarations.")
    return None


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

    selected = select_security_mechanism(declarations)
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

                    declaration = {
                        'vnf_id': vnf_id,
                        'security_mechanisms': [
                            {
                                'mechanism': 'MACsec/manual',
                                'parameters': {
                                    'MAC_address': MAC_address,
                                    'key': key,
                                    'key_id': key_id
                                }
                            },
                            {
                                'mechanism': 'IPsec/manual',
                                'parameters': {
                                    'IP_address': IP_address,
                                    'spi': spi,
                                    'encryption_key': get_random_key(256),
                                    'auth_key': get_random_key(256)
                                }
                            }
                        ],
                        'digital_signature': ''
                    }

                    producer.send(vl['vl_id'], value=declaration)
                    producer.flush()
                    logger.info(f"Declaration published in topic {vl['vl_id']}: {declaration}")

                    worker = threading.Thread(target=security_agent_worker, name=vl['vl_id'], args=(vl, interface, prefixlen))
                    worker.start()
                    break

if __name__ == "__main__":
    main()
