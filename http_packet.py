import sys
import time
from datetime import datetime, timedelta
sys.path.append('./lib/')
import pymongo
while True:
    start_time = datetime.now() - timedelta(minutes=2)
    mongo_db = pymongo.MongoClient('mongodb://10.101.130.213/sniffer').sniffer
    p_cur = mongo_db.packet.find({
            'tcp_packet_info.body': {
                '$regex': r'.*HTTP.*'
            }
        })
    for start_packet in p_cur:
        ack = start_packet['tcp_packet_info']['acknowledgement']
        session_packets = mongo_db.packet.find({
            'tcp_packet_info.acknowledgement': ack
        }).sort([('tcp_packet_info.sequence', pymongo.ASCENDING)])
        message = ''
        for packet  in session_packets:
            message += packet['tcp_packet_info']['body']
        start_packet['http_body'] = message
        mongo_db.http_packet.save(start_packet)

    mongo_db.packet.remove({
        'time': {
            '$lt': start_time
        }
    })
    time.sleep(20)
