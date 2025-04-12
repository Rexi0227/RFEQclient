from rfeq_client import RFEQClient
import json

def handle_message(data):
    if data["type"] == "pga":
        print(data["content"])
    

client = RFEQClient(username="example@gmail.com", password="example", on_message=handle_message)
client.login()
client.connect_ws()
