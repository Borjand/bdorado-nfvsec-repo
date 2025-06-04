import os
import json
import random
import threading
import subprocess
from kafka import KafkaConsumer, KafkaProducer
from pyroute2 import IPRoute

# Load configuration from environment variables
VNF_ID = os.environ.get("VNF_ID", "VNF_A")
PUBLIC_KEY = os.environ.get("PUBLIC_KEY", "public-key-a")
BROKER_ADDRESS = os.environ.get("BROKER_ADDRESS", "kafka:9092")
VNFFG_TOPIC = os.environ.get("VNFFG_TOPIC", "vnffg_topic")
DECLARATION_TIMEOUT_MS = int(os.environ.get("DECLARATION_TIMEOUT", "500"))

# Create an instance of IPRoute to interact with network interfaces
ip = IPRoute()

# Generate a random hexadecimal key of 'n_bits' bits
def get_random_key(n_bits: int) -> str:
    return hex(random.getrandbits(n_bits))[2:]

# Return a two-digit MACsec key ID based on the index
def get_macsec_key_id(index: int) -> str:
    return f"{index:02d}"

# Retrieve network interface details by name
def resolve_interface_by_name(name: str) -> dict:
    idx_list = ip.link_lookup(ifname=name)
    if not idx_list:
        raise RuntimeError(f"Interface '{name}' not found")
    idx = idx_list[0]
    link = ip.get_links(idx)[0]
    addr_list = ip.get_addr(index=idx)
    ip_address = addr_list[0].get_attr("IFA_ADDRESS") if addr_list else ""
    return {
        "name": name,
        "MAC_address": link.get_attr("IFLA_ADDRESS"),
        "IP_address": ip_address,
        "index": idx
    }

# Configure MACsec on the given interface using received declarations
def configure_macsec(vl_id: str, declarations: list, interface: dict):
    macsec_if_name = f"macsec_{interface['name']}"
    print(f"[INFO] Configuring MACsec for {vl_id} on {interface['name']}")

    try:
        # Create the MACsec virtual interface
        subprocess.run(["ip", "link", "add", "link", interface['name'], macsec_if_name, "type", "macsec"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to create MACsec interface: {e}")
        return

    # Iterate over all received declarations
    for declaration in declarations:
        for mech in declaration.get("security_mechanisms", []):
            if mech["mechanism"] == "MACsec/manual":
                params = mech["parameters"]
                if declaration["vnf_id"] == VNF_ID:
                    # Configure transmit security association (SA)
                    subprocess.run(["ip", "macsec", "add", macsec_if_name, "tx", "sa", "0", "pn", "100", "on",
                                    "key", params["key_id"], params["key"]], check=True)
                else:
                    # Configure receive channel and security association (SA)
                    subprocess.run(["ip", "macsec", "add", macsec_if_name, "rx", "address", params["MAC_address"], "port", "1"], check=True)
                    subprocess.run(["ip", "macsec", "add", macsec_if_name, "rx", "address", params["MAC_address"], "port", "1",
                                    "sa", "0", "pn", "100", "on", "key", params["key_id"], params["key"]], check=True)
                break

    # Bring up the MACsec interface
    ip.link("set", index=interface["index"], state="up")
    print(f"[INFO] MACsec configured on {macsec_if_name}")

# Background thread to handle configuration for each virtual link
def security_agent_worker(vl: dict, interface: dict):
    topic = vl["vl_id"]
    consumer = KafkaConsumer(
        topic,
        bootstrap_servers=[BROKER_ADDRESS],
        auto_offset_reset='earliest',
        consumer_timeout_ms=DECLARATION_TIMEOUT_MS,
        value_deserializer=lambda x: json.loads(x.decode('utf-8'))
    )
    declarations = [msg.value for msg in consumer]
    if len(declarations) == 0:
        print(f"[WARN] No declarations received for {topic}")
        return
    configure_macsec(topic, declarations, interface)

# Main function to initialize Kafka and process topology messages
def main():
    consumer = KafkaConsumer(
        VNFFG_TOPIC,
        bootstrap_servers=[BROKER_ADDRESS],
        value_deserializer=lambda x: json.loads(x.decode('utf-8'))
    )

    producer = KafkaProducer(
        bootstrap_servers=[BROKER_ADDRESS],
        value_serializer=lambda x: json.dumps(x).encode('utf-8')
    )

    # Process incoming topologies from the Kafka topic
    for message in consumer:
        topology = message.value
        for vl in topology:
            for i, neighbour in enumerate(vl.get("neighbours", [])):
                if neighbour["vnf_id"] == VNF_ID:
                    interface_name = neighbour["interface"]  # Use 'interface' field from JSON
                    interface = resolve_interface_by_name(interface_name)
                    secret_key = get_random_key(128)
                    key_id = get_macsec_key_id(i)

                    # Build declaration message with supported security mechanisms
                    declaration = {
                        "vnf_id": VNF_ID,
                        "security_mechanisms": [
                            {
                                "mechanism": "MACsec/manual",
                                "parameters": {
                                    "MAC_address": interface["MAC_address"],
                                    "key": secret_key,
                                    "key_id": key_id
                                }
                            }
                        ],
                        "digital_signature": ""
                    }

                    print(f"[INFO] Publishing declaration for {vl['vl_id']}")
                    producer.send(vl["vl_id"], value=declaration)
                    producer.flush()

                    # Start worker thread for this virtual link
                    worker = threading.Thread(target=security_agent_worker, args=(vl, interface), name=vl["vl_id"])
                    worker.start()
                    break

# Entry point
if __name__ == "__main__":
    main()
