from plotly.offline import plot
import plotly.graph_objs as go
import csv
import math
from pprint import pprint

def get_data_rsa(file):
    csv_reader = csv.reader(open(file), delimiter=';')
    temp_d_msb = []
    d_msb = []
    t = []
    occ = []

    for row in csv_reader:
        temp_msb = get_msb(row[5])
        temp_t = round(get_time(row[6]) // 1000000)

        d_msb_index = next((index for (index, d) in enumerate(temp_d_msb) if d["msb"] == temp_msb and d["t"] == temp_t), None)

        if d_msb_index:
            temp_d_msb[d_msb_index]['occ'] += 1
        else:
            temp_d_msb.append({'msb' : temp_msb, 't' : temp_t, 'occ' : 1})

    for i in range(len(temp_d_msb)):
        d_msb.append(temp_d_msb[i]['msb'])
        t.append(temp_d_msb[i]['t'])
        occ.append(temp_d_msb[i]['occ'])


    plot({"data" : [go.Heatmap(z=occ, x=d_msb, y=t)],
	"layout" : go.Layout(autosize=True, plot_bgcolor='#ffffff', title= file[:-4].upper() + " private key MSB and time generation heatmap", xaxis=dict(title="Private key MSB value"), yaxis=dict(title="Keygen time(ms)"))},
	filename= file[:-4] + '_heat_d_msb.html')

def get_data_rsa_modulus(file):
    csv_reader = csv.reader(open(file), delimiter=';')
    temp_n_msb = []
    n_msb = []
    t = []
    occ = []

    for row in csv_reader:
        temp_msb = get_msb(row[1])
        temp_t = round(get_time(row[6]) // 1000000)

        n_msb_index = next((index for (index, d) in enumerate(temp_n_msb) if d["msb"] == temp_msb and d["t"] == temp_t), None)

        if n_msb_index:
            temp_n_msb[n_msb_index]['occ'] += 1
        else:
            temp_n_msb.append({'msb' : temp_msb, 't' : temp_t, 'occ' : 1})

    for i in range(len(temp_n_msb)):
        n_msb.append(temp_n_msb[i]['msb'])
        t.append(temp_n_msb[i]['t'])
        occ.append(temp_n_msb[i]['occ'])


    plot({"data" : [go.Heatmap(z=occ, x=n_msb, y=t)],
	"layout" : go.Layout(autosize=True, plot_bgcolor='#ffffff', title= file[:-4].upper() + " private key MSB and time generation heatmap", xaxis=dict(title="Private key MSB value"), yaxis=dict(title="Keygen time(ms)"))},
	filename= file[:-4] + '_heat_n_msb.html')

def get_data_ecc(file):
    csv_reader = csv.reader(open(file), delimiter=';')
    temp_d_msb = []
    d_msb = []
    t = []
    occ = []

    for row in csv_reader:
        temp_msb = get_msb(row[2])
        temp_t = round(get_time(row[3]) // 100000)

        d_msb_index = next((index for (index, d) in enumerate(temp_d_msb) if d["msb"] == temp_msb and d["t"] == temp_t), None)

        if d_msb_index:
            temp_d_msb[d_msb_index]['occ'] += 1
        else:
            temp_d_msb.append({'msb' : temp_msb, 't' : temp_t, 'occ' : 1})

    for i in range(len(temp_d_msb)):
        d_msb.append(temp_d_msb[i]['msb'])
        t.append(temp_d_msb[i]['t'])
        occ.append(temp_d_msb[i]['occ'])


    plot({"data" : [go.Heatmap(z=occ, x=d_msb, y=t)],
	"layout" : go.Layout(autosize=True, plot_bgcolor='#ffffff', title="EC private key MSB and time generation heatmap", xaxis=dict(title="Private key MSB value"), yaxis=dict(title="Keygen time(ms)"))},
	filename= file[:-4] + 'ms_heat_d_msb.html')

def get_msb(str_number):
    str_msb = str_number[:2]
    return int(str_msb, 16)

def get_lsb(str_number):
    str_msb = str_number[-2:]
    return int(str_msb, 16)

def get_time(str_time):
    return float(str_time[:-3])

##get_data_rsa_modulus('rsa2048.txt')
##get_data_rsa_modulus('rsa1024.txt')
get_data_rsa_modulus('rsa512.txt')
##get_data_rsa('rsa2048.txt')
##get_data_rsa('rsa1024.txt')
##get_data_rsa('rsa512.txt')
##get_data_ecc('result.csv')
