from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

import json

from azure.eventhub import EventData, EventHubProducerClient


@dataclass
class EventHubClient:
    connection_string: str
    eventhub_name: str

    def send(self, event: Dict[str, Any]) -> None:
        producer = EventHubProducerClient.from_connection_string(
            conn_str=self.connection_string,
            eventhub_name=self.eventhub_name,
        )
        with producer:
            batch = producer.create_batch()
            batch.add(EventData(body=json.dumps(event)))
            producer.send_batch(batch)
