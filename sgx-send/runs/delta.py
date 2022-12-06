import re, csv
import pandas as pd

# df = pd.read_csv('/home/mohit/Documents/cav_project/sgx-send/runs/send_rcv_times.csv')
# df = pd.read_csv('/home/mohit/Documents/cav_project/sgx-send/runs/2/sgx-run-2.csv')
df = pd.read_csv('/home/mohit/Documents/cav_project/sgx-send/runs/3/sgx-runtime-3.csv')


for i in range(len(df)):
    sendtt = df.values[i][0]
    rcvtt = df.values[i][1]

    sendt = re.search('^(?P<h>\d+):(?P<m>\d+):(?P<s>\d+):(?P<ms>\d+):(?P<mis>\d+):(?P<ns>\d+)', df.values[i][0], re.MULTILINE)
    rcvt = re.search('^(?P<h>\d+):(?P<m>\d+):(?P<s>\d+):(?P<ms>\d+):(?P<mis>\d+):(?P<ns>\d+)', df.values[i][1], re.MULTILINE)


    print(sendtt + ', ' + rcvtt, end = ', ')
    diff_h = int(rcvt.group('h')) - int(sendt.group('h'))    
    print(str(diff_h) + ':', end = '' )
    diff_m = int(rcvt.group('m')) - int(sendt.group('m'))        
    print(str(diff_m) + ':', end = '' )
    diff_s = int(rcvt.group('s')) - int(sendt.group('s'))        
    print(str(diff_s) + ':', end = '' )
    diff_ms = int(rcvt.group('ms')) - int(sendt.group('ms'))        
    print(str(diff_ms) + ':', end = '' )
    diff_mis = int(rcvt.group('mis')) - int(sendt.group('mis'))        
    print(str(diff_mis) + ':', end = '' )
    diff_ns = int(rcvt.group('ns')) - int(sendt.group('ns'))        
    print(str(diff_ns) + ':', end = ', ' )


    if (diff_s == 1):
        
        ms_format = (diff_ms + 1000)*.001 if diff_ms > 0 else 0 

        print("{0:.3f}".format(ms_format))

    elif (diff_s == 0):

        ms_format = diff_ms*.001 if diff_ms > 0 else 0

        print("{0:.3f}".format(ms_format))






# print(lemma_name.group('lemma_name'))