from plotly.offline import plot
import plotly.graph_objs as go
import operator
from pprint import pprint
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
        t.append(get_time(row[1]) / 1000000)

    plot({'data': [go.Histogram(x=t, nbinsx = 256, autobinx = False)],
         'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title=file[0:3].upper() + ' histogram - ' + file[4:-4].replace("_", " ").capitalize() + ' (time)', xaxis=dict(title='Value of time(ms)'), yaxis=dict(title='Number of occurrences'))},
         filename= 'graphs/' + file[0:3] + '/' + file[:-4] + '_time.html')

    plot({'data': [go.Bar(x=id, y=t)],
         'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title=file[0:3].upper() + ' bar - ' + file[4:-4].replace("_", " ").capitalize() + ' (hw / time)', xaxis=dict(title='Index'), yaxis=dict(title='Value of time(ms)'))},
         filename= 'graphs/' + file[0:3] + '/' + file[:-4] + '_bar.html')

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
        t.append(get_time(row[2]) / 1000000)

    plot({'data': [go.Histogram(x=hw, nbinsx = 256, autobinx = False)],
         'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title=file[0:3].upper() + ' histogram - ' + file[4:-4].replace("_", " ").capitalize() + ' (hamming weight)', xaxis=dict(title='Value of hamming weight'), yaxis=dict(title='Number of occurrences'))},
         filename= 'graphs/' + file[0:3] + '/' + file[:-4] + '_hw.html')

    plot({'data': [go.Histogram(x=t, nbinsx = 256, autobinx = False)],
         'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title=file[0:3].upper() + ' histogram - ' + file[4:-4].replace("_", " ").capitalize() + ' (time)', xaxis=dict(title='Value of time(ms)'), yaxis=dict(title='Number of occurrences'))},
         filename= 'graphs/' + file[0:3] + '/' + file[:-4] + '_time.html')

    plot({'data': [go.Histogram2d(x=hw, y=t, nbinsx = 256, autobinx = False)],
        'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title=file[0:3].upper() + ' histogram2d - ' + file[4:-4].replace("_", " ").capitalize() + ' (hw / time / occurences)', xaxis=dict(title='Value of hamming weight'), yaxis=dict(title='Value of time(ms)'))},
        filename= 'graphs/' + file[0:3] + '/' + file[:-4] + '_hist2d.html')

    plot({'data': [go.Bar(x=id, y=t)],
         'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title=file[0:3].upper() + ' bar - ' + file[4:-4].replace("_", " ").capitalize() + ' (hw / time)', xaxis=dict(title='Index'), yaxis=dict(title='Value of time(ms)'))},
         filename= 'graphs/' + file[0:3] + '/' + file[:-4] + '_bar.html')

def get_graphs_hw_length_time(file):
    csv_reader = csv.reader(open(file), delimiter=';')
    id = []
    length = []
    hw = []
    t = []

    sorted_reader = sorted(csv_reader, key=operator.itemgetter(3))

    for row in sorted_reader[:-1000]:
        if row[0] == "ID":
         continue
        id.append(row[0])
        hw.append(row[1])
        length.append(row[2])
        t.append(get_time(row[3]) / 1000000)

    plot({'data': [go.Histogram(x=hw, nbinsx = 256, autobinx = False)],
        'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title=file[0:3].upper() + ' histogram - ' + file[4:-4].replace("_", " ").capitalize() + ' (hamming weight)', xaxis=dict(title='Value of hamming weight'), yaxis=dict(title='Number of occurrences'))},
        filename= 'graphs/' + file[0:3] + '/' + file[:-4] + '_hw.html')

    plot({'data': [go.Histogram(x=t, nbinsx = 256, autobinx = False)],
        'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title=file[0:3].upper() + ' histogram - ' + file[4:-4].replace("_", " ").capitalize() + ' (time)', xaxis=dict(title='Value of time(ms)'), yaxis=dict(title='Number of occurrences'))},
        filename= 'graphs/' + file[0:3] + '/' + file[:-4] + '_time.html')

    plot({'data': [go.Histogram2d(x=hw, y=t, nbinsx = 256, autobinx = False)],
        'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title=file[0:3].upper() + ' histogram2d - ' + file[4:-4].replace("_", " ").capitalize() + ' (hw / time / occurences)', xaxis=dict(title='Value of hamming weight'), yaxis=dict(title='Value of time(ms)'))},
        filename= 'graphs/' + file[0:3] + '/' + file[:-4] + '_hist2d.html')

    plot({'data': [go.Heatmap(x=hw, y=t, z=length)],
        'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title=file[0:3].upper() + ' heatmap - ' + file[4:-4].replace("_", " ").capitalize() + ' (hw / time / length)', xaxis=dict(title='Value of hamming weight'), yaxis=dict(title='Value of time(ms)'))},
        filename= 'graphs/' + file[0:3] + '/' + file[:-4] + '_heat.html')

    plot({'data': [go.Bar(x=id, y=t)],
        'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title=file[0:3].upper() + ' bar - ' + file[4:-4].replace("_", " ").capitalize() + ' (hw / time)', xaxis=dict(title='Index'), yaxis=dict(title='Value of time(ms)'))},
        filename= 'graphs/' + file[0:3] + '/' + file[:-4] + '_bar.html')

def get_time(str_time):
    return float(str_time[:-3])

def sort_time(val):
    return val[1]

get_graphs_hw_length_time('rsa_random_message_sign.txt')
get_graphs_hw_time('rsa_random_exponent_sign.txt')
get_graphs_time('rsa_high_hamming_weight.txt')
get_graphs_hw_length_time('rsa_random_message_decrypt.txt')
get_graphs_hw_time('rsa_random_exponent_decrypt.txt')
get_graphs_hw_time('ecc_random_message.txt')
get_graphs_hw_time('ecc_random_exponent.txt')
