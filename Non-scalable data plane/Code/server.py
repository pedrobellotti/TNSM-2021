import os

porta = 14001
for i in range (2500):
    cmd = ('iperf -u -f k -s -p %d &' % (porta))
    porta += 1
    os.system(cmd)
    #print (cmd)

#Abre os servidores de ping UDP
os.system("socat UDP-LISTEN:7000,fork PIPE &")
os.system("socat UDP-LISTEN:7001,fork PIPE &")