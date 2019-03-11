from plotly.offline import plot
import plotly.graph_objs as go
import csv
import math

def get_data_rsa(file):
    csv_reader = csv.reader(open(file), delimiter=';')
    n_msb = []
    n_lsb = []
    p_msb = []
    p_lsb = []
    q_msb = []
    q_lsb = []
    d_msb = []
    d_lsb = []
    t = []
    for row in csv_reader:
        n_msb.append(get_msb(row[1]))
        n_lsb.append(get_lsb(row[1]))
        p_msb.append(get_msb(row[3]))
        p_lsb.append(get_lsb(row[3]))
        q_msb.append(get_msb(row[4]))
        q_lsb.append(get_lsb(row[4]))
        d_msb.append(get_msb(row[5]))
        d_lsb.append(get_lsb(row[5]))
        t.append(get_time(row[6]))

    plot([go.Histogram(x=n_msb, nbinsx = 256, autobinx = False)], filename= file[:-4] + '_n_msb.html')
    plot([go.Histogram(x=n_lsb, nbinsx = 256, autobinx = False)], filename= file[:-4] + '_n_lsb.html')
    plot([go.Histogram(x=p_msb, nbinsx = 256, autobinx = False)], filename= file[:-4] + '_p_msb.html')
    plot([go.Histogram(x=p_lsb, nbinsx = 256, autobinx = False)], filename= file[:-4] + '_p_lsb.html')
    plot([go.Histogram(x=q_msb, nbinsx = 256, autobinx = False)], filename= file[:-4] + '_q_msb.html')
    plot([go.Histogram(x=q_lsb, nbinsx = 256, autobinx = False)], filename= file[:-4] + '_q_lsb.html')
    plot([go.Histogram(x=d_msb, nbinsx = 256, autobinx = False)], filename= file[:-4] + '_d_msb.html')
    plot([go.Histogram(x=d_lsb, nbinsx = 256, autobinx = False)], filename= file[:-4] + '_d_lsb.html')
    plot([go.Histogram(x=t, autobinx = False)], filename= file[:-4] + '_t.html')

def get_data_ecc(file):
    csv_reader = csv.reader(open(file), delimiter=';')
    e_msb = []
    e_lsb = []
    d_msb = []
    d_lsb = []
    t = []
    for row in csv_reader:
        e_msb.append(get_msb(row[1]))
        e_lsb.append(get_lsb(row[1]))
        d_msb.append(get_msb(row[2]))
        d_lsb.append(get_lsb(row[2]))
        t.append(get_time(row[3]))
    
    plot([go.Histogram(x=e_msb, nbinsx = 256, autobinx = False)], filename= file[:-4] + '_e_msb.html')
    plot([go.Histogram(x=e_lsb, nbinsx = 256, autobinx = False)], filename= file[:-4] + '_e_lsb.html')
    plot([go.Histogram(x=d_msb, nbinsx = 256, autobinx = False)], filename= file[:-4] + '_d_msb.html')
    plot([go.Histogram(x=d_lsb, nbinsx = 256, autobinx = False)], filename= file[:-4] + '_d_lsb.html')
    plot([go.Histogram(x=t, autobinx = False)], filename= file[:-4] + '_t.html')

def get_msb(str_number):
    str_msb = str_number[:2]
    return int(str_msb, 16)

def get_lsb(str_number):
    str_msb = str_number[-2:]
    return int(str_msb, 16)

def get_time(str_time):
    return float(str_time[:-3])


##get_data_rsa('rsa1024.txt')
##get_data_rsa('rsa2048.txt')
##get_data_rsa('rsa512.txt')
##get_data_ecc('ecc.csv')
