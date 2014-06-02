import csv
import matplotlib.pyplot as plt
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-f', dest='f', required=True)
args = parser.parse_args()

with open(args.f) as f:
    reader = csv.reader(f)
    reader.next()

    seqx = []
    seqy = []
    ackx = []
    acky = []

    for row in reader:
        time = float(row[1])
        src = row[2]
        row[6].index
        details = row[6]

        seqno = None
        if 'Seq=' in details:
            start = details.index('Seq=') + 4
            end = details.index(' ', start)
            seqno = int(details[start:end])
        ackno = None
        if 'Ack=' in details:
            start = details.index('Ack=') + 4
            end = details.index(' ', start)
            ackno = int(details[start:end])

        if src == '10.0.0.2' and seqno:
            seqx.append(time)
            seqy.append(seqno)

        elif src == '10.0.0.1' and ackno:
            ackx.append(time)
            acky.append(ackno)


    plt.xlabel('time')
    plt.ylabel('seqno')
    plt.plot(seqx, seqy, label='victim data')
    plt.plot(ackx, acky, label='attacker acks')
    plt.legend()
    plt.ylim(ymax=max(seqy) * 2)
    plt.show()
