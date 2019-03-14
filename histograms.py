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

    plot({'data': [go.Histogram(x=n_msb, nbinsx = 256, autobinx = False)],
          'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title='Modulus - MSB', xaxis=dict(title='Value of MSB'), yaxis=dict(title='Number of occurrences'))},
         filename= file[:-4] + '_n_msb.html')
    plot({'data': [go.Histogram(x=n_lsb, nbinsx = 256, autobinx = False)],
         'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title='Modulus - LSB', xaxis=dict(title='Value of LSB'), yaxis=dict(title='Number of occurrences'))},
         filename= file[:-4] + '_n_lsb.html')
    plot({'data': [go.Histogram(x=p_msb, nbinsx = 256, autobinx = False)],
         'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title='First prime - MSB', xaxis=dict(title='Value of MSB'), yaxis=dict(title='Number of occurrences'))},
         filename= file[:-4] + '_p_msb.html')
    plot({'data': [go.Histogram(x=p_lsb, nbinsx = 256, autobinx = False)],
         'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title='First prime - LSB', xaxis=dict(title='Value of LSB'), yaxis=dict(title='Number of occurrences'))},
         filename= file[:-4] + '_p_lsb.html')
    plot({'data': [go.Histogram(x=q_msb, nbinsx = 256, autobinx = False)],
         'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title='Second prime - MSB', xaxis=dict(title='Value of MSB'), yaxis=dict(title='Number of occurrences'))},
         filename= file[:-4] + '_q_msb.html')
    plot({'data': [go.Histogram(x=q_lsb, nbinsx = 256, autobinx = False)],
         'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title='Second prime - LSB', xaxis=dict(title='Value of LSB'), yaxis=dict(title='Number of occurrences'))},
         filename= file[:-4] + '_q_lsb.html')
    plot({'data': [go.Histogram(x=d_msb, nbinsx = 256, autobinx = False)],
         'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title='Private exponent - MSB', xaxis=dict(title='Value of MSB'), yaxis=dict(title='Number of occurrences'))},
         filename= file[:-4] + '_d_msb.html')
    plot({'data': [go.Histogram(x=d_lsb, nbinsx = 256, autobinx = False)],
         'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title='Private exponent - LSB', xaxis=dict(title='Value of LSB'), yaxis=dict(title='Number of occurrences'))},
         filename= file[:-4] + '_d_lsb.html')
    plot({'data': [go.Histogram(x=t, autobinx = False)],
         'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title='Keygen time', xaxis=dict(title='Time (ns)'), yaxis=dict(title='Number of occurrences'))},
         filename= file[:-4] + '_t.html')

def get_data_ecc(file):
    csv_reader = csv.reader(open(file), delimiter=';')
    e_x = []
    e_y = []
    d_msb = []
    d_lsb = []
    t = []
    for row in csv_reader:
        coordinates = get_coordinates(row[1])
        e_x.append(coordinates[0])
        e_y.append(coordinates[1])
        d_msb.append(get_msb(row[2]))
        d_lsb.append(get_lsb(row[2]))
        t.append(get_time(row[3]))



##    trace = go.Scatter(
##        x = e_x,
##        y = e_y,
##        mode = 'markers'
##    )
##    data = [trace]
##    plot(data, filename= file[:-4] + '_points.html')

    plot({'data': [go.Histogram(x=d_msb, nbinsx = 256, autobinx = False)],
         'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title='Private key - MSB', xaxis=dict(title='Value of MSB'), yaxis=dict(title='Number of occurrences'))},
         filename= file[:-4] + '_d_msb.html')
    plot({'data': [go.Histogram(x=d_lsb, nbinsx = 256, autobinx = False)],
         'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title='Private key - LSB', xaxis=dict(title='Value of LSB'), yaxis=dict(title='Number of occurrences'))},
         filename= file[:-4] + '_d_lsb.html')
    plot({'data': [go.Histogram(x=t, autobinx = False)],
         'layout': go.Layout(autosize=True, plot_bgcolor='#ffffff', title='Keygen time', xaxis=dict(title='Time (ns)'), yaxis=dict(title='Number of occurrences'))},filename= file[:-4] + '_t.html')

def get_msb(str_number):
    str_msb = str_number[:2]
    return int(str_msb, 16)

def get_lsb(str_number):
    str_msb = str_number[-2:]
    return int(str_msb, 16)

def get_time(str_time):
    return float(str_time[:-3])

def get_coordinates(str_key):
    tmp = str_key.split('||')
    return (int(tmp[1], 16), int(tmp[2], 16))


##get_data_rsa('rsa1024.txt')
##get_data_rsa('rsa2048.txt')
##get_data_rsa('rsa512.txt')
##get_data_ecc('ecc.csv')
