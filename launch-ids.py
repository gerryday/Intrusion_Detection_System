#!/usr/bin/python3

import sys
import csv
import numpy as np
import pandas as pd
import keras as keras
from keras.models import load_model
from sklearn.preprocessing import Normalizer

import subprocess
import queue
import threading
import time

from io import StringIO


def main():
	print("\n\n\n")
	
	header = ["duration","protocol_type","service","flag","src_bytes",
	"dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
	"logged_in","num_compromised","root_shell","su_attempted","num_root",
	"num_file_creations","num_shells","num_access_files","num_outbound_cmds",
	"is_host_login","is_guest_login","count","srv_count","serror_rate",
	"srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
	"diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
	"dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
	"dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
	"dst_host_rerror_rate","dst_host_srv_rerror_rate"]

	protocol_mapping = {'icmp': 0, 'tcp': 1, 'udp': 2}
	#service_mapping = {'IRC': 0, 'X11': 1, 'Z39_50': 2, 'auth': 3, 'bgp': 4, 'courier': 5, 'csnet_ns': 6, 'ctf': 7, 'daytime': 8, 'discard': 9, 'domain': 10, 'domain_u': 11, 'echo': 12, 'eco_i': 13, 'ecr_i': 14, 'efs': 15, 'exec': 16, 'finger': 17, 'ftp': 18, 'ftp_data': 19, 'gopher': 20, 'hostnames': 21, 'http': 22, 'http_443': 23, 'imap4': 24, 'iso_tsap': 25, 'klogin': 26, 'kshell': 27, 'ldap': 28, 'link': 29, 'login': 30, 'mtp': 31, 'name': 32, 'netbios_dgm': 33, 'netbios_ns': 34, 'netbios_ssn': 35, 'netstat': 36, 'nnsp': 37, 'nntp': 38, 'ntp_u': 39, 'other': 40, 'pm_dump': 41, 'pop_2': 42, 'pop_3': 43, 'printer': 44, 'private': 45, 'red_i': 46, 'remote_job': 47, 'rje': 48, 'shell': 49, 'smtp': 50, 'sql_net': 51, 'ssh': 52, 'sunrpc': 53, 'supdup': 54, 'systat': 55, 'telnet': 56, 'tftp_u': 57, 'tim_i': 58, 'time': 59, 'urh_i': 60, 'urp_i': 61, 'uucp': 62, 'uucp_path': 63, 'vmnet': 64, 'whois': 65,'80':22,'22':52}
	#service_mapping = {'IRC': 0, 'X11': 1, 'Z39_50': 2, 'auth': 3, 'bgp': 4, 'courier': 5, 'csnet_ns': 6, 'ctf': 7, 'daytime': 8, 'discard': 9, 'domain': 10, 'domain_u': 11, 'echo': 12, 'eco_i': 13, 'ecr_i': 14, 'efs': 15, 'exec': 16, 'finger': 17, 'ftp': 18, 'ftp_data': 19, 'gopher': 20, 'hostnames': 21, 'http_443': 23, 'imap4': 24, 'iso_tsap': 25, 'klogin': 26, 'kshell': 27, 'ldap': 28, 'link': 29, 'login': 30, 'mtp': 31, 'name': 32, 'netbios_dgm': 33, 'netbios_ns': 34, 'netbios_ssn': 35, 'netstat': 36, 'nnsp': 37, 'nntp': 38, 'ntp_u': 39, 'other': 40, 'pm_dump': 41, 'pop_2': 42, 'pop_3': 43, 'printer': 44, 'private': 45, 'red_i': 46, 'remote_job': 47, 'rje': 48, 'shell': 49, 'smtp': 50, 'sql_net': 51, 'sunrpc': 53, 'supdup': 54, 'systat': 55, 'telnet': 56, 'tftp_u': 57, 'tim_i': 58, 'time': 59, 'urh_i': 60, 'urp_i': 61, 'uucp': 62, 'uucp_path': 63, 'vmnet': 64, 'whois': 65,80:22,22:52}
	service_mapping = {'IRC': 0, 'X11': 1, 'Z39_50': 2, 'auth': 3, 'bgp': 4, 'courier': 5, 'csnet_ns': 6, 'ctf': 7, 'daytime': 8, 'discard': 9, 'domain': 10, 'domain_u': 11, 'echo': 12, 'eco_i': 13, 'ecr_i': 14, 'efs': 15, 'exec': 16, 'finger': 17, 'ftp': 18, 'ftp_data': 19, 'gopher': 20, 'hostnames': 21, 'http': 22, 'http_443': 23, 'imap4': 24, 'iso_tsap': 25, 'klogin': 26, 'kshell': 27, 'ldap': 28, 'link': 29, 'login': 30, 'mtp': 31, 'name': 32, 'netbios_dgm': 33, 'netbios_ns': 34, 'netbios_ssn': 35, 'netstat': 36, 'nnsp': 37, 'nntp': 38, 'ntp_u': 39, 'other': 40, 'pm_dump': 41, 'pop_2': 42, 'pop_3': 43, 'printer': 44, 'private': 45, 'red_i': 46, 'remote_job': 47, 'rje': 48, 'shell': 49, 'smtp': 50, 'sql_net': 51, 'ssh': 52, 'sunrpc': 53, 'supdup': 54, 'systat': 55, 'telnet': 56, 'tftp_u': 57, 'tim_i': 58, 'time': 59, 'urh_i': 60, 'urp_i': 61, 'uucp': 62, 'uucp_path': 63, 'vmnet': 64, 'whois': 65,80:22,22:52,53:11,547:66,8:13}
	flag_mapping = {'OTH': 0, 'REJ': 1, 'RSTO': 2, 'RSTOS0': 3, 'RSTR': 4, 'S0': 5, 'S1': 6, 'S2': 7, 'S3': 8, 'SF': 9, 'SH': 10}
	label_mapping = {'back.': 0, 'buffer_overflow.': 1, 'ftp_write.': 2, 'guess_passwd.': 3, 'imap.': 4, 'ipsweep.': 5, 'land.': 6, 'loadmodule.': 7, 'multihop.': 8, 'neptune.': 9, 'nmap.': 10, 'normal.': 11, 'perl.': 12, 'phf.': 13, 'pod.': 14, 'portsweep.': 15, 'rootkit.': 16, 'satan.': 17, 'smurf.': 18, 'spy.': 19, 'teardrop.': 20, 'warezclient.': 21, 'warezmaster.': 22}

	#model = load_model('kddcup99_model1.h5')
	model = load_model('kddcup99_model20210425_11_1_05.h5')
	
	hnd = subprocess.Popen(['/home/blake/capkdd.sh'],stdout=subprocess.PIPE)
	
	
	stdout_queue = queue.Queue()
	stdout_reader = AsynchronousFileReader(hnd.stdout, stdout_queue)
	stdout_reader.start()
	
	total = 0
	bad = 0
	while (hnd.poll() == None):
		while not stdout_reader.eof():
			while not stdout_queue.empty():
				#line = stdout_queue.get()
				test_data = pd.read_csv(StringIO(stdout_queue.get()),names=header)
				
				#print(test_data.size)
				#print(test_data)
				
				#if (not isinstance(test_data['protocol_type'],numbers.Number):
				test_data['protocol_type'] = test_data['protocol_type'].map(protocol_mapping)
				test_data['service'] = test_data['service'].map(service_mapping)
				test_data['flag'] = test_data['flag'].map(flag_mapping)
				
				test_dataset = test_data.values
				
				#print("line num: " + str(linenum))
				total += 1
				#print(test_dataset)
				#print(test_dataset.size)

				scaler = Normalizer().fit(test_dataset)
				X_norm = scaler.transform(test_dataset)

				test_dataset = np.reshape(X_norm, (X_norm.shape[0],X_norm.shape[1],1))

				prediction = np.argmax(model.predict(test_dataset), axis=-1)
				if (prediction[0] != 11): bad += 1
				print(list(label_mapping.keys())[list(label_mapping.values()).index(prediction[0])])

				#print (line)#testing
			time.sleep(.1)
	
	print("Total: " + str(total))
	print("Bad: " + str(bad))
	hnd.kill()
	hnd.stdout.close()



class AsynchronousFileReader(threading.Thread):
	'''
	https://www.stefaanlippens.net/python-asynchronous-subprocess-pipe-reading/
	
	
	Helper class to implement asynchronous reading of a file
	in a separate thread. Pushes read lines on a queue to
	be consumed in another thread.
	'''

	def __init__(self, fd, q):
		assert isinstance(q, queue.Queue)
		assert callable(fd.readline)
		threading.Thread.__init__(self)
		self._fd = fd
		self._queue = q
	'''The body of the tread: read lines and put them on the queue.'''
	def run(self):
		for line in iter(self._fd.readline, b''):
			self._queue.put(line.decode('utf-8').strip())
			#self._queue.put(repr(line).strip())

	def eof(self):
		'''Check whether there is no more content to expect.'''
		return not self.is_alive() and self._queue.empty()



if __name__ == "__main__":
	main()