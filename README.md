# fabric-DDoS-Double_spending_attack-Dataset
1, file 1.txt and 2.txt are the attack_log produced by the attacker.

   it tells each double-spend attack when to carry out and each DDoS attack when to begin and when to end.


2, file node_info_1.txt and node_info_2.txt are the infomation of nodes.

   in these two files, every line discribes a node.

   the format is:"ip type main_port"

   type 3 means peers, type 2 means orderers, type 1 means other ips, type 0 means the Gateway.


3, you can use command "python structure.py pcapfile pklfile attack_log node_info" to transfer an pcap file to our pickle file

   the program uses append mode, so please manually clean up when you need to overwrite the pkl file.   
