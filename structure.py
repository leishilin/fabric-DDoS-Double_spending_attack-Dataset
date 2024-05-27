import pickle
from math import floor

import numpy as np
import torch
from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from torch_geometric.data import Data

label_notes = {
    "normal": 0,
    "double-spend-1": 1,
    "double-spend-2": 2,
    "double-spend-3": 3,
    "double-spend-4": 4,
    "double-spend-5": 5,
    "DDoS-orderer-1": 6,
    "DDoS-orderer-2": 7,
    "DDoS-orderer-3": 8,
    "DDoS-orderer-4": 9,
    "DDoS-orderer-5": 10,
    "DDoS-peer-1": 11,
    "DDoS-peer-2": 12,
    "DDoS-peer-3": 13,
    "DDoS-peer-4": 14,
    "DDoS-peer-5": 15
}

# 创建一个空字典来存储key-value对
ip_dict = {}
node = 0
num_classes = 8
num_node = 16
node_kinds = torch.zeros([num_node])
# 打开文件，'r'表示读取模式
with open(sys.argv[4], 'r') as file:
    # 逐行读取文件
    for line in file:
        # 去除行尾的换行符，并使用split()函数按空格分割
        key, value, _ = line.strip().split(' ')
        # 将value从字符串转换为整数
        value = int(value)
        # 将key和value存入字典
        ip_dict[key] = node
        node_kinds[node] = int(value)
        node += 1

edge_index = [[i, j] for i in range(num_node) for j in range(num_node)]
edge_index = torch.LongTensor(edge_index).t().contiguous()


def store_struct(edge_attr, viewed, label, filename='periods.pkl'):
    with open(filename, 'ab') as f:
        try:
            y = label_notes[label]
        except KeyError:
            return
        x = torch.cat([node_kinds.view(-1, 1), viewed.view(-1, 1)], dim=1)
        # 转换为PyTorch Geometric的Data对象
        data = Data(x=x, edge_index=edge_index, edge_attr=edge_attr, y=y)
        pickle.dump(data, f)


class LogFileIterator:
    def __init__(self, filename):
        self.file = open(filename, 'r')
        self.line = None
        self._advance_to_next_line()

    def __iter__(self):
        return self

    def __next__(self):
        if self.line is None:
            raise StopIteration
        timestamp_str, message = self.line.split(' ', 1)
        timestamp = float(timestamp_str)  # 转换为整数
        self._advance_to_next_line()
        return timestamp, message

    def _advance_to_next_line(self):
        self.line = self.file.readline().strip()
        if not self.line:
            self.file.close()
            self.line = None


last_double_spend_timestamp = 0
last_DDoS_start_timestamp = 0
last_attack_start_timestamp = 0
last_attack_end_timestamp = 0
msg = ''


def get_label(time):
    global last_double_spend_timestamp
    global last_DDoS_start_timestamp
    global last_attack_start_timestamp
    global last_attack_end_timestamp
    global msg

    while time > last_attack_end_timestamp:
        try:
            timestamp, msg = next(log_file_iterator)
        except StopIteration:
            return "end"

        c = msg[0]
        if c == 'D':
            last_attack_start_timestamp = last_DDoS_start_timestamp = timestamp
            timestamp, _ = next(log_file_iterator)
            last_attack_end_timestamp = timestamp

        elif c == 'd':
            last_attack_start_timestamp = last_double_spend_timestamp = timestamp
            last_attack_end_timestamp = timestamp + 0.1

    if time < last_attack_start_timestamp:
        d = last_double_spend_timestamp - time
        if (d < 0.1) & (d > 0):
            return f"double-spend-{msg[-1]}"
        return "normal"

    else:
        c = msg[-3]
        if c == '0':
            p = msg[-4:]
            s = floor((int(p) - 7048) / 3)
            return f"DDoS-orderer-{s}"
        else:
            return f"DDoS-peer-{c}"


def is_possible_tls_packet(tcp_packet):
    payload = bytes(tcp_packet[TCP].payload)
    if len(payload) >= 2 and payload[:2] in [b'\x16\x03', b'\x16\x01']:
        return True
    return False


def is_syn_packet(tcp_packet):
    return (tcp_packet.flags & 0x02) != 0


def process_pcap(pcap_file, storage_file):
    global node
    global ip_dict
    # 使用PcapReader逐步读取pcap文件
    with PcapReader(pcap_file) as reader:
        base_time = 0
        period_time = 0
        pkt_matrix = torch.zeros([num_node, num_node])
        byte_matrix = torch.zeros([num_node, num_node])
        tls_pkt_matrix = torch.zeros([num_node, num_node])
        tls_bytes_matrix = torch.zeros([num_node, num_node])
        main_port_send_pkt_matrix = torch.zeros([num_node, num_node])
        main_port_send_bytes_matrix = torch.zeros([num_node, num_node])
        main_port_rcv_pkt_matrix = torch.zeros([num_node, num_node])
        main_port_rcv_bytes_matrix = torch.zeros([num_node, num_node])
        viewed = torch.zeros([node], dtype=torch.float)
        for packet_data in reader:
            # 如果packet_data已经是IP层或更上层的包，则直接使用它
            # 否则，假设它有一个Ether层，并获取IP层
            if IP in packet_data:
                packet = packet_data
            elif Ether in packet_data:
                packet = packet_data[Ether].payload
            else:
                # 如果不是Ether或IP层，则跳过这个包
                continue
            if base_time == 0:
                period_time = base_time = math.floor(packet.time / 0.1) * 0.1
            if packet.time - period_time > 0.1:
                label = get_label(period_time)
                period_time = math.floor(packet.time / 0.1) * 0.1
                edge_attr = torch.cat([pkt_matrix.view(-1, 1), byte_matrix.view(-1, 1), tls_pkt_matrix.view(-1, 1),
                                       tls_bytes_matrix.view(-1, 1), main_port_send_pkt_matrix.view(-1, 1),
                                       main_port_send_bytes_matrix.view(-1, 1), main_port_rcv_pkt_matrix.view(-1, 1),
                                       main_port_rcv_bytes_matrix.view(-1, 1)], dim=1)
                store_struct(edge_attr, viewed, label, storage_file)
                pkt_matrix = torch.zeros([num_node, num_node])
                byte_matrix = torch.zeros([num_node, num_node])
                tls_pkt_matrix = torch.zeros([num_node, num_node])
                tls_bytes_matrix = torch.zeros([num_node, num_node])
                main_port_send_pkt_matrix = torch.zeros([num_node, num_node])
                main_port_send_bytes_matrix = torch.zeros([num_node, num_node])
                main_port_rcv_pkt_matrix = torch.zeros([num_node, num_node])
                main_port_rcv_bytes_matrix = torch.zeros([num_node, num_node])
                viewed = torch.zeros([node], dtype=torch.float)
            pkt_size = len(packet[IP])
            try:
                a = ip_dict[packet[IP].src]
                b = ip_dict[packet[IP].dst]
            except KeyError:
                continue
            pkt_matrix[a][b] += 1
            byte_matrix[a][b] += pkt_size
            if TCP in packet:
                if is_possible_tls_packet(packet[TCP]):
                    tls_pkt_matrix[a][b] += 1
                    tls_bytes_matrix[a][b] += pkt_size
            if packet[TCP].sport < 10000:
                main_port_send_pkt_matrix[a][b] += 1
                main_port_send_bytes_matrix[a][b] += pkt_size
            if packet[TCP].dport < 10000:
                main_port_rcv_pkt_matrix[a][b] += 1
                main_port_rcv_bytes_matrix[a][b] += pkt_size
                if is_syn_packet(packet[TCP]):
                    viewed[b] += 1


pcap_file = sys.argv[1]  # 你的大型输入pcap文件
storage_file = sys.argv[2]  # 输出文件的名称
log_file_iterator = LogFileIterator(sys.argv[3])
process_pcap(pcap_file, storage_file)
print("finish")
