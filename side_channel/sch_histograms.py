from plotly.offline import plot
import plotly.graph_objs as go
from pprint import pprint
import csv
import math

def get_graphs_hw_time(file):
    csv_reader = csv.reader(open(file), delimiter=';')
    id = []
    hw = []
    t = []

    for row in csv_reader:
        if row[0] == "ID":
            continue
        id.append(row[0])
        hw.append(row[1])
        t.append(get_time(row[2]) / 1000000)

    plot({'data': [go.Histogram(x=hw, nbinsx = 256, autobinx = False)],
         'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title=file[0:3].upper() + ' hist - Random exponent (hamming weight)', xaxis=dict(title='Value of hamming weight'), yaxis=dict(title='Number of occurrences'))},
         filename= 'graphs/' + file[0:3] + '/' + file[:-4] + '_hw.html')

    plot({'data': [go.Histogram(x=t, nbinsx = 256, autobinx = False)],
         'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title=file[0:3].upper() + ' hist - Random exponent (time)', xaxis=dict(title='Value of time(ms)'), yaxis=dict(title='Number of occurrences'))},
         filename= 'graphs/' + file[0:3] + '/' + file[:-4] + '_time.html')

    plot({'data': [go.Histogram2d(x=hw, y=t, nbinsx = 256, autobinx = False)],
         'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title=file[0:3].upper() + ' heat - Random exponent (hw/ time / occurences)', xaxis=dict(title='Value of hamming weight'), yaxis=dict(title='Value of time(ms)'))},
         filename= 'graphs/' + file[0:3] + '/' + file[:-4] + '_heat.html')

    plot({'data': [go.Bar(x=id, y=t)],
         'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title=file[0:3].upper() + ' bar - Random exponent (hw / time)', xaxis=dict(title='Value of id'), yaxis=dict(title='Value of time(ms)'))},
         filename= 'graphs/' + file[0:3] + '/' + file[:-4] + '_bar.html')

def get_time(str_time):
    return float(str_time[:-3])

##get_graphs('rsa_random_message_sig.txt')
##get_graphs('rsa_random_exp_sig.txt')
##get_graphs('rsa_high_hw.txt')
##get_graphs('rsa_random_msg_dec.txt')
get_graphs_hw_time('rsa_random_exp_dec.txt')
get_graphs_hw_time('ecc_random_messages.txt')
get_graphs_hw_time('ecc_random_exp.txt')
