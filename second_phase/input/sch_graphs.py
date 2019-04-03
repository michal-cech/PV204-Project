from plotly.offline import plot
from pprint import pprint
import plotly.graph_objs as go
import operator
import csv
import math

def get_graphs_time(file):
    csv_reader = csv.reader(open(file), delimiter=';')
    id = []
    t = []

    sorted_reader = sorted(csv_reader, key=operator.itemgetter(1))

    for row in sorted_reader[:-1000]:
        if row[0] == "ID":
            continue
        id.append(row[0])
        t.append(get_time(row[1]))

    plot({'data': [go.Histogram(x=t)],
         'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title=file[0:3].upper() + ' histogram - ' + file[4:-4].replace("_", " ").capitalize() + ' (time / occurrences)', xaxis=dict(title='Value of time(ms)'), yaxis=dict(title='Number of occurrences'))},
         filename= '../results/graphs/' + file[0:3] + '/' + file[:-4] + '_time.html')

    plot({'data': [go.Bar(x=id, y=t)],
         'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title=file[0:3].upper() + ' bar - ' + file[4:-4].replace("_", " ").capitalize() + ' (id / time)', xaxis=dict(title='Index'), yaxis=dict(title='Value of time(ms)'))},
         filename= '../results/graphs/' + file[0:3] + '/' + file[:-4] + '_bar.html')

def get_graphs_hw_time(file):
    csv_reader = csv.reader(open(file), delimiter=';')
    id = []
    hw = []
    t = []

    sorted_reader = sorted(csv_reader, key=operator.itemgetter(2))

    for row in sorted_reader[:-1000]:
        if row[0] == "ID":
            continue
        id.append(row[0])
        hw.append(row[1])
        t.append(get_time(row[2]))

    plot({'data': [go.Histogram(x=hw)],
         'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title=file[0:3].upper() + ' histogram - ' + file[4:-4].replace("_", " ").capitalize() + ' (hamming weight / occurrences)', xaxis=dict(title='Value of hamming weight'), yaxis=dict(title='Number of occurrences'))},
         filename= '../results/graphs/' + file[0:3] + '/' + file[:-4] + '_hw.html')

    plot({'data': [go.Histogram(x=t)],
         'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title=file[0:3].upper() + ' histogram - ' + file[4:-4].replace("_", " ").capitalize() + ' (time / occurrences)', xaxis=dict(title='Value of time(ms)'), yaxis=dict(title='Number of occurrences'))},
         filename= '../results/graphs/' + file[0:3] + '/' + file[:-4] + '_time.html')

    plot({'data': [go.Histogram2d(x=hw, y=t, colorscale='Reds')],
        'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title=file[0:3].upper() + ' histogram2d - ' + file[4:-4].replace("_", " ").capitalize() + ' (hw / time / occurences)', xaxis=dict(title='Value of hamming weight'), yaxis=dict(title='Value of time(ms)'))},
        filename= '../results/graphs/' + file[0:3] + '/' + file[:-4] + '_hist2d.html')

    plot({'data': [go.Bar(x=id, y=t)],
         'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title=file[0:3].upper() + ' bar - ' + file[4:-4].replace("_", " ").capitalize() + ' (id / time)', xaxis=dict(title='Index'), yaxis=dict(title='Value of time(ms)'))},
         filename= '../results/graphs/' + file[0:3] + '/' + file[:-4] + '_bar.html')

def get_graphs_hw_length_time(file):
    csv_reader = csv.reader(open(file), delimiter=';')
    id = []
    hw = []
    t = []

    sorted_reader = sorted(csv_reader, key=operator.itemgetter(2))

    for row in sorted_reader[:-1000]:
        if row[0] == "ID":
             continue
        id.append(row[0])
        hw.append(row[1])
        t.append(get_time(row[3]))

    plot({'data': [go.Histogram(x=hw)],
        'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title=file[0:3].upper() + ' histogram - ' + file[4:-4].replace("_", " ").capitalize() + ' (hamming weight / occurrences)', xaxis=dict(title='Value of hamming weight'), yaxis=dict(title='Number of occurrences'))},
        filename= '../results/graphs/' + file[0:3] + '/' + file[:-4] + '_hw.html')

    plot({'data': [go.Histogram(x=t)],
        'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title=file[0:3].upper() + ' histogram - ' + file[4:-4].replace("_", " ").capitalize() + ' (time / occurrences)', xaxis=dict(title='Value of time(ms)'), yaxis=dict(title='Number of occurrences'))},
        filename= '../results/graphs/' + file[0:3] + '/' + file[:-4] + '_time.html')

    plot({'data': [go.Histogram2d(x=hw, y=t, colorscale='Reds')],
        'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title=file[0:3].upper() + ' histogram2d - ' + file[4:-4].replace("_", " ").capitalize() + ' (hw / time / occurences)', xaxis=dict(title='Value of hamming weight'), yaxis=dict(title='Value of time(ms)'))},
        filename= '../results/graphs/' + file[0:3] + '/' + file[:-4] + '_hist2d.html')

    plot({'data': [go.Bar(x=id, y=t)],
        'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title=file[0:3].upper() + ' bar - ' + file[4:-4].replace("_", " ").capitalize() + ' (id / time)', xaxis=dict(title='Index'), yaxis=dict(title='Value of time(ms)'))},
        filename= '../results/graphs/' + file[0:3] + '/' + file[:-4] + '_bar.html')

def get_time(str_time):
    if ("ns" in str_time):
        str_time = str_time[:-3]

    return float(str_time)/1000000

#get_graphs_time('ecc_large_exponent.txt')
#get_graphs_hw_time('ecc_random_exponent.txt')
#get_graphs_hw_time('ecc_random_messages.txt')
#get_graphs_time('ecc_short_exponent.txt')

#get_graphs_time('rsa_high_hamming_weight_decrypt.txt')
#get_graphs_time('rsa_high_hamming_weight_signature.txt')
#get_graphs_time('rsa_low_hamming_weight_decrypt.txt')
#get_graphs_time('rsa_low_hamming_weight_signature.txt')

get_graphs_hw_time('rsa_random_exponent_decrypt.txt')
get_graphs_hw_time('rsa_random_exponent_signature.txt')
get_graphs_hw_length_time('rsa_random_message_decrypt.txt')
get_graphs_hw_length_time('rsa_random_message_signature.txt')
