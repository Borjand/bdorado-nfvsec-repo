from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
import json
import os
import logging
from kafka import KafkaProducer

app = FastAPI()
logging.basicConfig(level=logging.INFO)

BROKER_ADDRESS = os.getenv("BROKER_ADDRESS", "localhost:9092")

producer = KafkaProducer(
    bootstrap_servers=[BROKER_ADDRESS],
    value_serializer=lambda x: json.dumps(x).encode('utf-8')
)

class Neighbour(BaseModel):
    vnf_id: str
    interface: str
    publickey: str

    class Config:
        extra = "forbid"

class VirtualLink(BaseModel):
    vl_id: str
    neighbours: List[Neighbour]

    class Config:
        extra = "forbid"

@app.post("/topology")
async def publish_topology(topology: List[VirtualLink]):
    try:
        producer.send("vnffg_topic", value=[vl.dict() for vl in topology])
        producer.flush()
        logging.info("Topology published successfully.")
        return {"status": "ok", "message": "Topology published"}
    except Exception as e:
        logging.error(f"Kafka error: {e}")
        raise HTTPException(status_code=500, detail=f"Kafka error: {str(e)}")
