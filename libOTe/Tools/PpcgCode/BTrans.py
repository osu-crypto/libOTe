import numpy as np
import argparse
import plotly.graph_objects as go
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


B2 = np.array([
[13.00140819, 7.357552005],
[11.97477307, 6.845490051],
[10.98370619, 6.339850003],
[10.00281502, 5.832890014],
[9.022367813, 5.321928095],
[8.027905997, 4.857980995],
[7.129283017, 4.321928095]
])
L2 = (1.0/2, 0.75)

B3 = np.array([
[12.15576694, 4.754887502],
[11.83368075, 4.64385619],
[11.45121111, 4.523561956],
[11.00702727, 4.392317423],
[10.60547952, 4.247927513],
[10.16741815, 4.087462841],
[9.607330314, 3.906890596],
[8.985841937, 3.700439718],
[8.129283017, 3.459431619],
[7.257387843, 3.169925001],
[6.129283017, 2.807354922]
])
L3 = (1.0/3, 0.75)

B4 = np.array([
[11.80372753, 3.700439718],
[11.33985, 3.584962501],
[10.81698362, 3.459431619],
[10.22881869, 3.321928095],
[9.677719642, 3.169925001],
[9.0, 3.0],
[8.233619677, 2.807354922],
[7.339850003, 2.584962501]
])
L4 = (1.0/4, 0.75)

B5 = np.array([
[12.4252159, 3.321928095],
[11.75238065, 3.169925001],
[10.82654849, 3.0],
[9.891783703, 2.807354922],
[8.813781191, 2.584962501],
[7.531381461, 2.321928095]
])
L5 = (0.2063, .766666)

# Example: 5 datasets
datasets = [ B2,B3,B4,B5]

# Your predefined linear equations: list of (slope, intercept) pairs
# For example, here just dummy values, you put yours:
linear_models = [L2,L3,L4,L5]

fig = go.Figure()
color_index = 0  # increment this manually if you add multiple traces
max_x = max([np.max(dataset[:, 0]) for dataset in datasets])
x_range = np.linspace(0, 1.1 * max_x, 500)  # Generate x values from 0 to 1.1 * max_x

# Loop through each dataset and its corresponding linear model
for i, (xy, (slope, intercept)) in enumerate(zip(datasets, linear_models)):
    name = f"$t={i+2}$"
    x = xy[:,0]
    y = xy[:,1]
    #print(i, xy)
    print(i, " x " , x , " y ", y)
    
    color = px.colors.qualitative.Plotly[color_index]
    lighter_color = lighten_color(color, factor=0.5)  # Make the color lighter
   
    color_index = color_index + 1

    # Compute your custom linear trend line
    
    y_custom = slope * x_range + intercept

    # Add custom trend line
    fig.add_trace(go.Scatter(
        x=x_range,
        y=y_custom,
        mode='lines',
        name=f"{name} Custom Trend",
        line=dict(dash='dash',color=lighter_color),
        showlegend=False
    ))
        # Scatter plot
    fig.add_trace(go.Scatter(x=x, y=y, mode='markers', name=name, line=dict(color=color)))


fig.update_layout(
    #title="Scatter Plots with Custom Linear Trend Lines",
    xaxis_title="$\log_2 k$",
    yaxis_title="$\log_2 \sigma$"
)


parser = argparse.ArgumentParser(description="Process multiple input files.")
parser.add_argument("--pdf", help="make a pdf", action='store_true')
args = parser.parse_args()
pdf = args.pdf

if pdf:            
    filename = "BTrans"
    print("output: " + filename + ".pdf")
    fig.write_image(filename +".pdf")
else:
    fig.show()