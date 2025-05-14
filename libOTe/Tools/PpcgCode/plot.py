import plotly
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
import sys
import numpy as np
import math
import argparse
import os
import time
import kaleido
import plotly.express as px

from matplotlib.colors import to_rgb
from matplotlib.colors import to_hex

def lighten_color(color, factor=0.5):
    """
    Lightens the given color by blending it with white.
    :param color: A string representing the color (e.g., "#1f77b4" or "blue").
    :param factor: A float between 0 and 1. Higher values make the color lighter.
    :return: A string representing the lightened color in hex format.
    """
    rgb = np.array(to_rgb(color))  # Convert color to RGB
    white = np.array([1, 1, 1])    # RGB for white
    lightened_rgb = rgb + (white - rgb) * factor  # Blend with white
    return to_hex(lightened_rgb)  # Convert back to hex

#import dash
#from dash import dcc, html


def myMin(values):
    return min(v for v in values if v != float('-inf'))
def myMax(values):
    m = max(v for v in values if not math.isnan(v))
    return m

def roundUp(number, step):
    return math.ceil(number / step) * step
def roundDown(number, step):
    return math.floor(number / step) * step

def enum(filename, percent, title, includeSum, pdf, fullDh,noMinor):
    
    print("enum")

    df = pd.read_csv(filename, header=None)  # header=None if no column names
    values = df.values#.tolist()  # convert to 2D list

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
    values = values[:-3]

    
    # values = values[::2, ::4]   # from (256,512) to (128,128)
    # dist   = dist[::4]          # from (512,) to (128,)
    # sDist  = sDist[::4]         # from (512,) to (128,)

    fig =  make_subplots(
        rows=2, cols=1,
        shared_xaxes=True,
        row_heights=[0.7, 0.3],
        vertical_spacing=0.05
    )
    fig.update_layout(
        title=dict(
            text=title,
            font=dict(size=20),
            x=0.5,  # Center the title (0 = left, 1 = right)
            xanchor='center'
        )
    )
    if percent:
        # From 0 to 1 inclusive, with len(dist) points
        bar_x = np.linspace(0, 1, len(dist))
    else:
        # Integer positions
        bar_x = list(range(len(dist)))


    high = roundUp(myMax(dist), 10)
    label = 50 #max(roundUp(high / 3, 10),1)
    low = roundDown(myMin(dist), label)
    step = max(math.ceil(label / 5), 1);
    fig.add_trace(go.Contour(
            z=values,
            x=bar_x,
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
            # colorbar=dict(
            #     title=dict(
            #         text="$\mathsf{E}_{w,h}$",
            #         side="right",   # or "top"
            #     ),
            #     x=1.02,  
            #     thickness=20,
            # ),
            line=dict(width=0),
    ), row=1, col=1)
    fig.update_layout(
        annotations=[
            dict(
                text=r"$\log_2 \mathsf{E}_{w,h}$",  # LaTeX-style math
                x=1.135,                     # x position (0 = left, 1 = right)
                y=0.5,                      # y position (0 = bottom, 1 = top)
                xref="paper",              # relative to entire figure width
                yref="paper",
                showarrow=False,
                font=dict(size=14),
                xanchor="left",
                yanchor="middle"
            )
        ]
    )
    fig.update_layout(
        margin=dict(l=60, r=130, t=50, b=100)  # increase right margin to make room
    )

    if not noMinor:
        fig.add_trace(go.Contour(
            z=values,
            x=bar_x,
            contours=dict(
                start=low,
                end=1000,
                size=step,  # Only half as many lines
                showlabels=False,
                coloring='none'
            ),
            line=dict(width=0.1),
            colorscale='Greys',
            showscale=False,
            showlegend=False
        ), row=1, col=1)


    # Top layer: every other line, with labels
    fig.add_trace(go.Contour(
        z=values,
        x=bar_x,
        contours=dict(
            start=low,
            end=high,
            size=label,       # Only half as many lines
            showlabels=True,
            coloring='none'
        ),
        line=dict(width=1),
        colorscale='Greys',
        showscale=False,
        showlegend=False
    ), row=1, col=1)

    bar_y = np.linspace(0, 1, len(dist))
    # Bottom: aligned scatter or bar plot
    fig.add_trace(go.Scatter(
        x=bar_x,
        y=dist,
        mode='lines',
        name='X Projection',
        showlegend=False,
        line=dict(color='black', width=2),
    ), row=2, col=1)

    if includeSum:
        fig.add_trace(go.Scatter(
            x=bar_x,
            y=sDist,
            mode='lines',
            name='X Projection',
            showlegend=False,
            line=dict(color='blue', width=2),
        ), row=2, col=1)

    if not fullDh:
        yMin = min(-5, roundDown(myMin(dist[:len(dist)//2]), 5))
        yMax = max(20, math.fabs(1.2 * myMin(dist[:len(dist)//2])))
        fig.update_yaxes(
            dtick=20, 
            #tickvals=list(range(-40, 41, 20)),  # only show labels at every 10
            #ticktext=[str(i) for i in range(-40, 41, 20)],  # labels
            range=[yMin,yMax], 
            row=2, col=1) 


        
    
    fig.update_yaxes(title=r"$w$",row=1, col=1) 
    fig.update_yaxes(title_text=r"$\log_2 \delta_h$", row=2, col=1)
    if percent:
        fig.update_xaxes(
            title_text=r"$h/n$", row=2, col=1
        )
    else:
        fig.update_xaxes(
            title_text=r"$h$", row=2, col=1
        )

    if pdf:
        print("output: " + filename + ".pdf")
        fig.write_image(filename +".pdf")
    else:
        print("show")
        fig.show()

def parse_line(line):
    raw_values = line.strip().split(',')
    dist = []
    for i, val in enumerate(raw_values):
        val = val.strip()  # remove whitespace
        if val == '':
            print(f"Skipping empty string at position {i}")
            continue
        try:
            num = float(val)
            dist.append(num)
        except ValueError:
            print(f"Could not convert '{val}' to float at position {i}")
    return dist


def dist(filenames, percent, watch, pdf, showSum, both):
    
    fig = go.Figure()
    fig.update_yaxes(range=[-40,60]) 
    fig.update_xaxes(range=[0,0.2]) 
    fig.update_yaxes(title_text=r"$\log_2 \delta_h$")
    if percent:
        fig.update_xaxes(
            title_text=r"$h/n$"
        )
    else:
        fig.update_xaxes(
            title_text=r"$h$"
        )
    fig.update_layout(
    legend=dict(
        x=0.98,         # Horizontal position (0=left, 1=right)
        y=0.98,         # Vertical position (0=bottom, 1=top)
        xanchor='right',
        yanchor='top',
        bgcolor='rgba(255,255,255,0.7)',  # optional semi-transparent white background
        bordercolor='black',
        borderwidth=1
    )
)
    existing_files = set()
    if len(filenames) == 1 and os.path.isdir(filenames[0]):
        folder = filenames[0]
    else:
        folder = None
    # Get a color from the default cycle
    color_index = 0  # increment this manually if you add multiple traces


    while True:

        if folder is not None:
            filenames = [os.path.join(folder, f) for f in os.listdir(folder) if f.endswith('.txt')]

        newFiles = [p for p in filenames if p not in existing_files]
        if len(newFiles) != 0:

            for filename in newFiles:
                print("filename=",filename)
                with open(filename, 'r') as f:
                    lines = f.readlines()

                name = lines[0].strip()  # First line: the name
                if showSum:
                    dist = parse_line(lines[2])  # Parse the second line
                else:
                    dist = parse_line(lines[1])

                #print(dist)
                if percent:
                    # From 0 to 1 inclusive, with len(dist) points
                    bar_x = np.linspace(0, 1, len(dist))
                else:
                    # Integer positions
                    bar_x = list(range(len(dist)))
                    
                color = px.colors.qualitative.Plotly[color_index]
                color_index = color_index + 1
                # Line 1
                trace1 = go.Scatter(
                    x=bar_x,
                    y=dist,
                    mode='lines',
                    name=name,
                    line=dict(color=color),
                    legendgroup=name,  # same legend group
                )
                fig.add_trace(trace1)
                if both:
                    sDist = parse_line(lines[2])  # Parse the second line
                    lighter_color = lighten_color(color, factor=0.35)  # Make the color lighter

                    trace2 = go.Scatter(
                        x=bar_x,
                        y=sDist,
                        mode='lines',
                        name=name+"_sum",
                        line=dict(dash='dash', color=lighter_color),
                        legendgroup=name,  # same legend group
                        showlegend=False  # hide duplicate legend entry if desired
                    )

                    fig.add_trace(trace2)


            #fig.update_layout(title='Multiple Lines on One Scatter Plot')

            if pdf:            
                print("output: " + filename + ".pdf")
                fig.write_image(filename +".pdf")
            else:
                fig.show()

        # Check if the user wants to continue watching
        if not watch:
            break

        # Update the set of existing files
        existing_files.update(newFiles)
        # Wait for a second before checking again
        time.sleep(4)




    
parser = argparse.ArgumentParser(description="Process multiple input files.")
parser.add_argument("--dist", nargs='+', help="List of input files")
parser.add_argument("--enum", help="input file")
parser.add_argument("--percent", help="List of input files", action='store_true')
parser.add_argument("--watch", help="List of input files", action='store_true')
parser.add_argument("--title", help="title (default filename)")
parser.add_argument("--sum", help="show output sum", action='store_true')
parser.add_argument("--both", help="show both ", action='store_true')
parser.add_argument("--pdf", help="make a pdf", action='store_true')
parser.add_argument("--fullDh", help="full delta_h range", action='store_true')
parser.add_argument("--noMinor", help="no minor lines", action='store_true')
args = parser.parse_args()

# main
if not args.dist and args.enum == None:
    print("Usage: python script.py --enum <filename.csv>")
    print("Usage: python script.py --dist <filename.csv> ...")
    print("other options: --percent")
    sys.exit(1)


if not args.enum == None:
    enum(args.enum, args.percent, args.title, args.sum, args.pdf, args.fullDh, args.noMinor)
if args.dist:
    dist(args.dist, args.percent, args.watch, args.pdf, args.sum, args.both)

#dist = go.Figure()
