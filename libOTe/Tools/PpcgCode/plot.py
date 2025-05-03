import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
import sys
import numpy as np
import math


def myMin(values):
    return min(v for v in values if v != float('-inf'))
def myMax(values):
    m = max(v for v in values if not math.isnan(v))
    print("myMax ",m)
    return m

def roundUp(number, step):
    return math.ceil(number / step) * step
def roundDown(number, step):
    return math.floor(number / step) * step

def enum(values, filename):
    
    print("enum")
    #print(values)

    #dist in on the last row
    if values[-3][0] != -303:
        print("checksum not found")
        return
    dist = values[-2]
    sDist = values[-1]
    dist = [float(d) for d in dist]
    sDist = [float(d) for d in sDist]

    #print(dist)

    #remove the last row
    values.pop()
    values.pop()
    values.pop()


    fig =  make_subplots(
        rows=2, cols=1,
        shared_xaxes=True,
        row_heights=[0.7, 0.3],
        vertical_spacing=0.05
    )
    fig.update_layout(
        title=dict(
            text=filename,
            font=dict(size=20),
            x=0.5,  # Center the title (0 = left, 1 = right)
            xanchor='center'
        )
    )

    high = roundUp(myMax(dist), 10)
    label = max(roundUp(high / 3, 10),1)
    low = roundDown(myMin(dist), label)
    step = max(math.ceil(label / 5), 1);
    fig.add_trace(go.Contour(
            z=values,
            # colorscale = [
            #           [0, 'blue'],      # start
            #           [0.5, 'white'],   # middle
            #           [1, 'red']        # end
            #       ],
            #colorscale='grey',
            colorscale='RdYlGn_r',
            contours=dict(
                start=-100,
                end=100,
                size=step,
            ),
            line=dict(width=0),
    ), row=1, col=1)

    fig.add_trace(go.Contour(
        z=values,
        contours=dict(
            start=low,
            end=1000,
            size=step,  # Only half as many lines
            showlabels=False,
            coloring='none'
        ),
        line=dict(width=1),
        colorscale='Greys',
        showscale=False,
        showlegend=False
    ), row=1, col=1)


    # Top layer: every other line, with labels
    fig.add_trace(go.Contour(
        z=values,
        contours=dict(
            start=low,
            end=high,
            size=label,       # Only half as many lines
            showlabels=True,
            coloring='none'
        ),
        line=dict(width=2),
        colorscale='Greys',
        showscale=False,
        showlegend=False
    ), row=1, col=1)

    bar_y = np.linspace(0, 1, len(dist))
    # Bottom: aligned scatter or bar plot
    fig.add_trace(go.Scatter(
        x=[i for i in range(len(dist))],
        y=dist,
        mode='lines',
        name='X Projection',
        showlegend=False,
        line=dict(color='black', width=2),
    ), row=2, col=1)
    fig.add_trace(go.Scatter(
        x=[i for i in range(len(dist))],
        y=sDist,
        mode='lines',
        name='X Projection',
        showlegend=False,
        line=dict(color='blue', width=2),
    ), row=2, col=1)

    yMin = min(-5, roundDown(myMin(dist[:len(dist)//2]), 5))
    yMax = max(20, math.fabs(1.2 * myMin(dist[:len(dist)//2])))
    fig.update_yaxes(range=[yMin,yMax], row=2, col=1)  # adjust 1.0 to your desired max

    fig.show()


def dist(values, filename):
    print("dist")

# main
if len(sys.argv) < 3 or sys.argv[1] != "enum" and sys.argv[1] != "dist":
    print("Usage: python script.py enum <filename.csv>")
    print("Usage: python script.py dist <filename.csv>")
    sys.exit(1)

filename = sys.argv[2]
df = pd.read_csv(filename, header=None)  # header=None if no column names
values = df.values.tolist()  # convert to 2D list

if sys.argv[1] == "enum":
    enum(values, filename)
elif sys.argv[1] == "dist":
    dist(values, filename)

#dist = go.Figure()
