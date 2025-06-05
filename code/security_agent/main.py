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

# --- Environment variables ---
vnf_id = os.getenv("VNF_ID", "VNF_A")
public_key = os.getenv("PUBLIC_KEY", "default-pkey")
broker_address = os.getenv("BROKER_ADDRESS", "kafka:9094")
vnffg_topic = os.getenv("VNF_FG_TOPIC", "vnffg_topic")
declaration_timeout = int(os.getenv("DECLARATION_TIMEOUT_MS", "1000"))
preferred_mechanisms = os.getenv("PREFERRED_MECHANISMS", "MACsec/manual,IPsec/manual").split(",")

# --- Wait until Kafka is available ---
def wait_for_kafka(broker, retries=10, delay=2):
    for attempt in range(retries):
        try:
            consumer = KafkaConsumer(
                bootstrap_servers=[broker],
                request_timeout_ms=1000,
                consumer_timeout_ms=1000
            )
            consumer.close()
            logging.info(f"Kafka is available (attempt {attempt + 1})")
            return
        except NoBrokersAvailable:
            logging.warning(f"Kafka not available, retrying in {delay}s (attempt {attempt + 1}/{retries})")
            time.sleep(delay)
    raise RuntimeError("Kafka not available after maximum retries.")

# --- Generate a random symmetric key ---
def get_random_key(n_bits):
    return hex(random.getrandbits(n_bits))[2:]

# --- Generate MACsec key ID ---
def get_macsec_key_id(index):
    return str(index // 10) + str(index % 10)

# --- Generate IPsec SPI ---
def get_spi(index):
    return 10000 + index  # Simple offset to avoid low-value conflicts

# --- Generate security declaration for a VNF ---
def generate_declaration(mac_addr, ip_addr, index):
    mechanisms = []

    if "MACsec/manual" in preferred_mechanisms:
        key = get_random_key(128)
        key_id = get_macsec_key_id(index)
        mechanisms.append({
            "mechanism": "MACsec/manual",
            "parameters": {
                "MAC_address": mac_addr,
                "key": key,
                "key_id": key_id
            }
        })

    if "IPsec/manual" in preferred_mechanisms:
        encryption_key = get_random_key(256)
        authentication_key = get_random_key(256)
        spi = get_spi(index)
        mechanisms.append({
            "mechanism": "IPsec/manual",
            "parameters": {
                "IP_address": ip_addr,
                "encryption_key": encryption_key,
                "authentication_key": authentication_key,
                "spi": spi
            }
        })

    return {
        "vnf_id": vnf_id,
        "security_mechanisms": mechanisms,
        "digital_signature": ""  # Placeholder for future implementation
    }

# --- Select common mechanism across declarations ---
def select_security_mechanism(declarations):
    declared_sets = [
        set(mech["mechanism"] for mech in decl["security_mechanisms"])
        for decl in declarations
    ]
    common_mechs = set.intersection(*declared_sets)
    for pref in preferred_mechanisms:
        if pref in common_mechs:
            return pref
    return None

# --- Configure MACsec manually ---
def macsec_manual(vl_id, declarations, interface):
    macsec_if_name = f"macsec_{interface['name']}"
    logging.info(f"Configuring MACsec for {vl_id} on {interface['name']}")

    try:
        subprocess.run(['ip', 'link', 'add', 'link', interface['name'], macsec_if_name, 'type', 'macsec'], check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to create MACsec interface: {e}")
        return

    for declaration in declarations:
        for mech in declaration['security_mechanisms']:
            if mech['mechanism'] != 'MACsec/manual':
                continue

            params = mech['parameters']
            if declaration['vnf_id'] == vnf_id:
                subprocess.run(['ip', 'macsec', 'add', macsec_if_name, 'tx', 'sa', '0', 'pn', '100', 'on', 'key', params['key_id'], params['key']], check=True)
            else:
                subprocess.run(['ip', 'macsec', 'add', macsec_if_name, 'rx', 'address', params['MAC_address'], 'port', '1'], check=True)
                subprocess.run(['ip', 'macsec', 'add', macsec_if_name, 'rx', 'address', params['MAC_address'], 'port', '1', 'sa', '0', 'pn', '100', 'on', 'key', params['key_id'], params['key']], check=True)

    ip = IPRoute()
    macsec_if_number = ip.link_lookup(ifname=macsec_if_name)[0]
    ip.link('set', index=macsec_if_number, state='up')

# --- Thread worker per virtual link ---
def security_agent_worker(vl, interface):
    logging.info(f"Worker started for link {vl['vl_id']}")
    messages = KafkaConsumer(
        vl['vl_id'],
        bootstrap_servers=[broker_address],
        auto_offset_reset='earliest',
        consumer_timeout_ms=declaration_timeout,
        value_deserializer=lambda x: loads(x.decode('utf-8'))
    )

    declarations = [msg.value for msg in messages]
    logging.info(f"Declarations received: {len(declarations)}")

    selected = select_security_mechanism(declarations)
    if selected == "MACsec/manual":
        macsec_manual(vl['vl_id'], declarations, interface)
    elif selected == "IPsec/manual":
        logging.info("IPsec/manual selected (implementation pending)")
    else:
        logging.warning("No compatible security mechanism found.")

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
                    logging.info(f"Found matching link for {vnf_id}: {neighbour}")

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

                    declaration = generate_declaration(MAC_address, IP_address, index)
                    producer.send(vl['vl_id'], value=declaration)
                    producer.flush()
                    logging.info(f"Declaration published in topic {vl['vl_id']}: {declaration}")

                    worker = threading.Thread(target=security_agent_worker, name=vl['vl_id'], args=(vl, interface))
                    worker.start()
                    break

if __name__ == "__main__":
    main()
