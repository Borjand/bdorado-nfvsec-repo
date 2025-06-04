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

# --- Logging Configuration ---
logging.basicConfig(
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# --- Environment Variables ---
vnf_id = os.getenv("VNF_ID", "VNF_A")
public_key = os.getenv("PUBLIC_KEY", "default-pkey")
broker_address = os.getenv("BROKER_ADDRESS", "kafka:9094")
vnffg_topic = os.getenv("VNF_FG_TOPIC", "vnffg_topic")
declaration_timeout = int(os.getenv("DECLARATION_TIMEOUT_MS", "1000"))

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

# --- Generate random symmetric key ---
def get_random_key(n_bits):
    return hex(random.getrandbits(n_bits))[2:]

# --- Generate MACsec key ID ---
def get_macsec_key_id(index):
    return str(index // 10) + str(index % 10)

# --- Configure MACsec manually ---
def macsec_manual(vl_id, declarations, interface):
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
    macsec_if_number = ip.link_lookup(ifname=macsec_if_name)[0]
    ip.link('set', index=macsec_if_number, state='up')

    # Move IP address from original interface to MACsec interface
    try:
        ip_addr = interface['IP_address']
        ip.link('set', index=ip.link_lookup(ifname=interface['name'])[0], state='down')
        ip.addr('del', index=ip.link_lookup(ifname=interface['name'])[0], address=ip_addr, mask=24)
        ip.addr('add', index=macsec_if_number, address=ip_addr, mask=24)
        logger.info(f"IP {ip_addr} moved from {interface['name']} to {macsec_if_name}")
    except Exception as e:
        logger.error(f"Failed to migrate IP: {e}")

# --- Select security mechanism ---
def select_security_mechanism(declarations):
    return 'MACsec/manual'

# --- Worker thread to configure security ---
def security_agent_worker(vl, interface):
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

    option = select_security_mechanism(declarations)
    if option == 'MACsec/manual':
        macsec_manual(vl['vl_id'], declarations, interface)

# --- Main Logic ---
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
                    IP_address = ip.get_addr(index=link_index, family=2)[0].get_attr('IFA_ADDRESS')

                    interface = {
                        'name': if_name,
                        'MAC_address': MAC_address,
                        'IP_address': IP_address,
                    }

                    key = get_random_key(128)
                    key_id = get_macsec_key_id(index)

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
                            }
                        ],
                        'digital_signature': ''
                    }

                    producer.send(vl['vl_id'], value=declaration)
                    producer.flush()
                    logger.info(f"Declaration published in topic {vl['vl_id']}: {declaration}")

                    worker = threading.Thread(target=security_agent_worker, name=vl['vl_id'], args=(vl, interface))
                    worker.start()
                    break

if __name__ == "__main__":
    main()
