from rfeq_client import RFEQClient

def handle_message(data):
    print(data)

client = RFEQClient(username="eample@gmail.com", password="example", on_message=handle_message)
client.login()
client.connect_ws()
