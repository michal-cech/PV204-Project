from plotly.offline import plot
import plotly.graph_objs as go
import csv
import math

def generate_histogram(file_name, file_name2, file_name3):
    csv_reader = csv.reader(open(file_name), delimiter=';')
    csv_reader2 = csv.reader(open(file_name2), delimiter=';')
    csv_reader3 = csv.reader(open(file_name3), delimiter=';')
    xid = []
    time = []
    xid2 = []
    time2 = []
    xid3 = []
    time3 = []
    for row in csv_reader:
        if row[0] == 'ID':
            continue
        xid.append(row[0])
        if get_time(row[2]) <= 14:
            time.append(get_time(row[2]))

    for row in csv_reader2:
        if row[0] == 'ID':
            continue
        xid2.append(row[0])
        if get_time(row[1]) <= 14:
            time2.append(get_time(row[1]))
        
    for row in csv_reader3:
        if row[0] == 'ID':
            continue
        xid3.append(row[0])
        if get_time(row[1]) <= 14:
            time3.append(get_time(row[1]))


##    print(len(time))
##    print(len(time2))
##    print(len(time3))

    trace = go.Histogram(
        x = time,
        opacity = 0.75,
        autobinx = False
    )

    trace2 = go.Histogram(
        x = time2,
        opacity = 0.75,
        autobinx = False
    )

    trace3 = go.Histogram(
        x = time3,
        opacity = 0.75,
        autobinx = False
    )
    
    data = [trace, trace2, trace3]
    layout = go.Layout(barmode='overlay')
    fig = go.Figure(data=data, layout=layout)
    plot(fig, filename= file_name[:-4] + '_' + file_name2[:-4] + '_' +
         file_name3[:-4] +'.html')

def get_time(str_time):
    return float(str_time)/1000000



