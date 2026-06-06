import plotly.express as px
import plotly.graph_objects as go
from typing import Dict

# Consistent, premium color palette for vulnerability severities
SEVERITY_COLORS = {
    "Critical": "#D9534F",  # Soft Dark Red
    "High": "#FD7E14",      # Vibrant Orange
    "Medium": "#F0AD4E",    # Warm Yellow/Amber
    "Low": "#5CB85C"        # Emerald Green
}

def create_severity_pie(stats: Dict[str, int]) -> go.Figure:
    """
    Generates a Plotly Pie chart representing the distribution of severity levels.
    """
    # Filter out 'Total' from stats
    labels = ["Critical", "High", "Medium", "Low"]
    values = [stats.get(l, 0) for l in labels]
    
    # Filter out severities with 0 count to keep chart clean
    filtered_data = [(l, v) for l, v in zip(labels, values) if v > 0]
    if not filtered_data:
        # Fallback if no counts
        labels_f, values_f = ["No Data"], [1]
        colors_f = ["#cccccc"]
    else:
        labels_f = [item[0] for item in filtered_data]
        values_f = [item[1] for item in filtered_data]
        colors_f = [SEVERITY_COLORS.get(l, "#cccccc") for l in labels_f]

    fig = px.pie(
        names=labels_f,
        values=values_f,
        color=labels_f,
        color_discrete_map=SEVERITY_COLORS,
        hole=0.4,
        title="Vulnerability Severity Distribution"
    )
    
    fig.update_traces(
        textposition='inside',
        textinfo='percent+label',
        marker=dict(colors=colors_f, line=dict(color='#ffffff', width=2))
    )
    
    fig.update_layout(
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=-0.1, xanchor="center", x=0.5),
        margin=dict(t=40, b=40, l=10, r=10),
        height=350,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)'
    )
    
    return fig

def create_severity_bar(stats: Dict[str, int]) -> go.Figure:
    """
    Generates a Plotly Bar chart showing the count of vulnerabilities by severity level.
    """
    labels = ["Critical", "High", "Medium", "Low"]
    values = [stats.get(l, 0) for l in labels]
    
    fig = go.Figure(data=[
        go.Bar(
            x=labels,
            y=values,
            marker_color=[SEVERITY_COLORS[l] for l in labels],
            text=values,
            textposition='auto',
            width=0.6
        )
    ])
    
    max_val = max(values) if values else 0
    yaxis_config = dict(
        gridcolor='rgba(200, 200, 200, 0.2)',
        rangemode='nonnegative',
        minallowed=0
    )
    # If maximum count is small, force ticks to be integer steps of 1 to avoid fractional labels
    if max_val < 6:
        yaxis_config['dtick'] = 1

    fig.update_layout(
        title="Vulnerability Count by Severity",
        xaxis_title="Severity Level",
        yaxis_title="Count",
        margin=dict(t=40, b=40, l=10, r=10),
        height=350,
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        yaxis=yaxis_config
    )
    
    return fig
