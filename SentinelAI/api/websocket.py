import json
from typing import List
from fastapi import WebSocket

class WebSocketManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast_incident(self, message_data: dict):
        # Convert datetime objects if any to strings via json dumps
        serialized = json.dumps(message_data, default=str)
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(serialized)
            except Exception:
                disconnected.append(connection)
        for conn in disconnected:
            self.disconnect(conn)

ws_manager = WebSocketManager()
