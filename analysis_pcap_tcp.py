import dpkt
import socket


class Flow:
    def __init__(self, srcIp, srcPort, dstIp, dstPort, transactions, time):
        self.srcIp = srcIp
        self.srcPort = srcPort
        self.dstIp = dstIp
        self.dstPort = dstPort
        self.transactions = transactions
        self.receive = []
        self.time = time
        self.dataSize = 0
        self.MSS = 0
        self.rtt = 0
        self.prevAck = 0
        self.prevPrevAck = 0
        self.dup = 0
        self.loss = 0
        self.dupOrLoss = False
        self.congestionWindow = []
        self.rttCount = 0
        self.count = 1
        self.initSeq = 0
        self.relativeSeq = 0
        self.rttStamp = 0
        self.windowSize = 0


with open('assignment2.pcap', 'rb') as pcap_file:
    pcap = dpkt.pcap.Reader(pcap_file)  # use dpkt
    flows = []  # list to store flows
    flowCount = 1
    for timestamp, buf in pcap:
        packet = dpkt.ethernet.Ethernet(buf)
        byteCounter = 0
        ipLength = 0
        ipCounter = 0
        tcpLength = 0
        tcpCounter = 0
        tcpPart = []
        tcpOption = []
        for byte in buf:  # every byte in pkt
            if byteCounter == 14:  # start ip
                ipLength = (byte & 15) * 4  # get ip header length
                byteCounter += 1
                ipCounter += 1
            elif byteCounter > 14:
                byteCounter += 1
                if ipCounter <= ipLength and tcpCounter == 0:  # in Ip header
                    if ipCounter == ipLength:  # start tcp
                        tcpCounter += 1
                        tcpPart.append(byte)
                    else:  # haven't started tcp
                        ipCounter += 1
                elif tcpCounter != 0:  # in tcp header
                    if tcpCounter < 12:
                        tcpCounter += 1
                        tcpPart.append(byte)
                    elif tcpCounter == 12:  # tcp header length pointer
                        tcpLength = ((byte & 480) >> 4) * 4  # assign tcp length
                        tcpCounter += 1
                        tcpPart.append(byte)
                    elif tcpCounter < tcpLength:
                        tcpCounter += 1
                        tcpPart.append(byte)
                        if tcpCounter > 20:
                            tcpOption.append(byte)  # store tcp option in tcpOption arr
            else:
                byteCounter += 1
        if isinstance(packet.data, dpkt.ip.IP):  # if packet.data is instance of IP
            ip = packet.data
            tcp = ip.data       # contains ip.data
            src_ip = socket.inet_ntoa(ip.src)
            dst_ip = socket.inet_ntoa(ip.dst)
            src_port = tcp.sport
            dst_port = tcp.dport
            flags = tcp.flags  # assign values to variables
            newFlow = Flow(src_ip, src_port, dst_ip, dst_port, [], 0)  # create a new flow to add them to new flow or
            # compare with existing one
            if flags & dpkt.tcp.TH_SYN:  # if syn == 1 and flags
                if tcp.ack == 0:  # new flow introduced
                    newFlow.time = timestamp  # make start time
                    newFlow.dataSize = byteCounter - ipCounter - 14
                    newFlow.MSS = (tcpOption[2] << 8) + tcpOption[3]  # get MSS
                    flows.append(newFlow)
            if tcp.ack != 0:
                for flow in flows:
                    if newFlow.srcIp == flow.srcIp and newFlow.dstIp == flow.dstIp and newFlow.srcPort == flow.srcPort \
                            and newFlow.dstPort == flow.dstPort:  # from sender to receiver
                        flow.transactions.append([tcp.seq, tcp.ack, tcp.win, timestamp])  # add transaction to transactions
                        flow.dataSize += (byteCounter - ipCounter - 14)
                        if flow.initSeq == 0:
                            flow.initSeq = tcp.seq
                        else:
                            if tcp.seq - flow.initSeq < flow.relativeSeq:  # if curr seq - init seq < relative seq
                                flow.loss += 1  # timeout loss
                                flow.dupOrLoss = True
                            else:
                                flow.relativeSeq = tcp.seq - flow.initSeq
                                flow.dupOrLoss = False
                        if flow.rttStamp == 0:  # there is no start time
                            flow.rttStamp = timestamp
                        elif timestamp - flow.rttStamp >= flow.rtt:  # if the rtt time has reached
                            flow.windowSize += flow.count
                            flow.congestionWindow.append(flow.windowSize)
                            flow.windowSize = 0
                            flow.rttStamp = timestamp
                        else:
                            flow.windowSize += flow.count

                    elif newFlow.srcIp == flow.dstIp and newFlow.dstIp == flow.srcIp and newFlow.srcPort == flow.dstPort\
                            and newFlow.dstPort == flow.srcPort:  # from receiver to sender
                        if ((tcpPart[13] & 2) >> 1) == 1 and flow.rttCount == 0:
                            flow.rtt = timestamp - flow.time  # assign rtt
                            flow.rttCount += 1
                        if len(flow.receive) == 0:
                            flow.receive.append([tcp.seq, tcp.ack, tcp.win, timestamp])  # add to receiving transaction
                            flow.prevPrevAck = tcp.ack
                        else:
                            if len(flow.receive) == 1:
                                flow.prevAck = tcp.ack
                            else:
                                if flow.prevAck == tcp.ack and flow.prevPrevAck == tcp.ack:
                                    flow.dup += 1  # triple ack occurred
                                    flow.dupOrLoss = True
                                else:  # shift previous and prevPrev and make the curr ack prevAck
                                    flow.prevPrevAck = flow.prevAck
                                    flow.prevAck = tcp.ack
                            flow.receive.append([tcp.seq, tcp.ack, tcp.win, timestamp])
            if flags & dpkt.tcp.TH_FIN:  # flow is finished with fin sign
                for flow in flows:
                    if flow.srcIp == dst_ip and flow.dstIp == src_ip and flow.srcPort == dst_port \
                            and flow.dstPort == src_port:
                        print(f'Flow {flowCount}')
                        print(f'source IP address: {flow.srcIp}, source port: {flow.srcPort}')
                        print(f'destination IP address: {flow.dstIp}, destination port: {flow.dstPort}')
                        print('')
                        print(f'Transaction 1: ')
                        print(f'from sender to receiver: seq_num = {flow.transactions[0][0]}, '
                              f'ack_num = {flow.transactions[0][1]}'
                              f', window size = {flow.transactions[0][2]}')
                        print(
                            f'from receiver to sender : seq_num = {flow.receive[0][0]}, ack_num = {flow.receive[0][1]}'
                            f', window size = {flow.receive[0][2]}')
                        print('')
                        print('transaction 2')
                        print(f'from sender to receiver: seq_num = {flow.transactions[1][0]}, ack_num = {flow.transactions[1][1]}'
                              f', window size = {flow.transactions[1][2]}')
                        print(f'receiver to sender: seq_num = {flow.receive[1][0]}, ack_num = {flow.receive[1][1]}'
                              f', window size = {flow.receive[1][2]}')
                        print(f'data sent = {(flow.dataSize / (timestamp - flow.time)) / 1000000}' + " Mbps")
                        print('')
                        index = 0
                        for i in range(0, len(flow.congestionWindow)):
                            if index == 3:
                                break
                            else:
                                print(f'Congestion Window Size {index + 1} = {flow.congestionWindow[i]} '
                                      f'MSS, {flow.congestionWindow[i] * flow.MSS} in bytes')
                                index += 1
                        print('')
                        print(f'Retransmission from duplicated ack : {flow.dup}')
                        print(f'Retransmission from timeout: {flow.loss}')
                        flowCount += 1

                        break


