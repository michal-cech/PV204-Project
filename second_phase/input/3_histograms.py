from plotly.offline import plot
import plotly.graph_objs as go
import operator
import csv
import math

def generate_histogram_ecc(file_name1, file_name2, file_name3):
    to_remove = 1000;
    csv_reader1 = csv.reader(open(file_name1), delimiter=';')
    csv_reader2 = csv.reader(open(file_name2), delimiter=';')
    csv_reader3 = csv.reader(open(file_name3), delimiter=';')
    xid1 = []
    time1 = []
    xid2 = []
    time2 = []
    xid3 = []
    time3 = []

    sorted_reader1 = sorted(csv_reader1, key=operator.itemgetter(1))
    sorted_reader2 = sorted(csv_reader2, key=operator.itemgetter(2))
    sorted_reader3 = sorted(csv_reader3, key=operator.itemgetter(1))

    for row in sorted_reader1[:-to_remove]:
        if row[0] == 'ID':
            continue
        xid1.append(row[0])
        time1.append(get_time(row[1]))

    for row in sorted_reader2[:-to_remove]:
        if row[0] == 'ID':
            continue
        xid2.append(row[0])
        time2.append(get_time(row[2]))

    for row in sorted_reader3[:-to_remove]:
        if row[0] == 'ID':
            continue
        xid3.append(row[0])
        time3.append(get_time(row[1]))

    trace = go.Histogram(
        x = time1,
        opacity = 0.75,
        autobinx = False,
        name=file_name1[4:-4].replace("_", " ").capitalize(),
    )

    trace2 = go.Histogram(
        x = time2,
        opacity = 0.75,
        autobinx = False,
        name=file_name2[4:-4].replace("_", " ").capitalize(),
    )

    trace3 = go.Histogram(
        x = time3,
        opacity = 0.75,
        autobinx = False,
        name=file_name3[4:-4].replace("_", " ").capitalize(),
    )

    data = [trace, trace2, trace3]
    layout = go.Layout(barmode='overlay', autosize=True, plot_bgcolor='#ffffff', title='ECC - ' + file_name1[4:-4].replace("_", " ").capitalize() + ' / ' + file_name2[4:-4].replace("_", " ").capitalize() + ' / ' + file_name3[4:-4].replace("_", " ").capitalize() + ' (id / time)', xaxis=dict(title='Index'), yaxis=dict(title='Value of time(ms)'))
    fig = go.Figure(data=data, layout=layout)
    plot(fig,
        filename= '../results/graphs/ecc/ecc_' +  file_name1[4:-4] + '_' + file_name2[4:-4] + '_' + file_name3[4:-4] +'.html')


def generate_histogram_rsa(file_name1, file_name2, file_name3, file_name4):
    to_remove = 1000;
    csv_reader1 = csv.reader(open(file_name1), delimiter=';')
    csv_reader2 = csv.reader(open(file_name2), delimiter=';')
    csv_reader3 = csv.reader(open(file_name3), delimiter=';')
    csv_reader4 = csv.reader(open(file_name4), delimiter=';')
    xid1 = []
    time1 = []
    xid2 = []
    time2 = []
    xid3 = []
    time3 = []
    xid4 = []
    time4 = []

    sorted_reader1 = sorted(csv_reader1, key=operator.itemgetter(1))
    sorted_reader2 = sorted(csv_reader2, key=operator.itemgetter(2))
    sorted_reader3 = sorted(csv_reader3, key=operator.itemgetter(1))
    sorted_reader4 = sorted(csv_reader4, key=operator.itemgetter(3))

    for row in sorted_reader1[:-to_remove]:
        if row[0] == 'ID':
            continue
        xid1.append(row[0])
        time1.append(get_time(row[1]))

    for row in sorted_reader2[:-to_remove]:
        if row[0] == 'ID':
            continue
        xid2.append(row[0])
        time2.append(get_time(remove_ns(row[2])))

    for row in sorted_reader3[:-to_remove]:
        if row[0] == 'ID':
            continue
        xid3.append(row[0])
        time3.append(get_time(row[1]))

    for row in sorted_reader4[:-to_remove]:
        if row[0] == 'ID':
            continue
        xid4.append(row[0])
        time4.append(get_time(remove_ns(row[3])))

    trace = go.Histogram(
        x = time1,
        opacity = 0.75,
        autobinx = False,
        name=file_name1[4:-4].replace("_", " ").capitalize(),
    )

    trace2 = go.Histogram(
        x = time2,
        opacity = 0.75,
        autobinx = False,
        name=file_name2[4:-4].replace("_", " ").capitalize(),
    )

    trace3 = go.Histogram(
        x = time3,
        opacity = 0.75,
        autobinx = False,
        name=file_name3[4:-4].replace("_", " ").capitalize(),
    )

    trace4 = go.Histogram(
        x = time4,
        opacity = 0.75,
        autobinx = False,
        name=file_name4[4:-4].replace("_", " ").capitalize(),
    )

    data = [trace, trace2, trace3, trace4]
    layout = go.Layout(barmode='overlay', autosize=True, plot_bgcolor='#ffffff', title='RSA - ' + file_name1[4:-4].replace("_", " ").capitalize() + ' / ' + file_name2[4:-4].replace("_", " ").capitalize() + ' / ' + file_name3[4:-4].replace("_", " ").capitalize() + ' / ' + file_name4[4:-4].replace("_", " ").capitalize() + ' (id / time)', xaxis=dict(title='Index'), yaxis=dict(title='Value of time(ms)'))
    fig = go.Figure(data=data, layout=layout)
    plot(fig,
        filename= '../results/graphs/rsa/rsa_' +  file_name1[4:-4] + '_' + file_name2[4:-4] + '_' + file_name3[4:-4] + '_' + file_name4[4:-4] +'.html')


def get_time(str_time):
    return float(str_time)/1000000

def remove_ns(str_time):
    return str_time[:-3]


generate_histogram_ecc('ecc_large_exponent.txt', 'ecc_random_exponent.txt', 'ecc_short_exponent.txt')
generate_histogram_rsa('rsa_high_hamming_weight_decrypt.txt', 'rsa_random_exponent_decrypt.txt', 'rsa_low_hamming_weight_decrypt.txt', 'rsa_random_message_decrypt.txt')
generate_histogram_rsa('rsa_high_hamming_weight_signature.txt', 'rsa_random_exponent_signature.txt', 'rsa_low_hamming_weight_signature.txt', 'rsa_random_message_signature.txt')
