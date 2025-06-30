import plotly.graph_objects as go
import plotly.io as pio

# Ensure image export capability
import sys, subprocess
try:
    import kaleido  # noqa: F401
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "kaleido", "--quiet"])

# Step labels (<=15 chars)
steps = [
    "Start",        # 1
    "CreateHSM",    # 2
    "InitHSM",      # 3
    "InstallSDK",   # 4
    "GenKey",       # 5
    "Encrypt",      # 6
    "UpS3",         # 7
    "DownS3",       # 8
    "Verify",       # 9
    "End"           # 10
]

x_vals = list(range(1, len(steps) + 1))
y_vals = [1] * len(steps)  # single row for horizontal flow

# Edge list: (from_idx, to_idx, category)
edges = [
    (1, 2, "AWSCLI"),
    (2, 3, "HSMCLI"),
    (3, 4, "EC2"),
    (4, 5, "Python"),
    (5, 6, "Python"),
    (6, 7, "Python"),
    (7, 8, "AWSCLI"),
    (8, 9, "Python"),
    (9, 10, "EC2")
]

# Color map following brand palette order
cat_colors = {
    "AWSCLI": "#1FB8CD",  # Strong cyan
    "HSMCLI": "#FFC185",  # Light orange
    "EC2": "#ECEBD5",     # Light green
    "Python": "#5D878F"    # Cyan
}

fig = go.Figure()

# Add edge traces grouped by category for legend
from collections import defaultdict
edge_points = defaultdict(lambda: {"x": [], "y": []})
for start, end, cat in edges:
    x0, x1 = start, end
    edge_points[cat]["x"].extend([x0, x1, None])  # None breaks line
    edge_points[cat]["y"].extend([1, 1, None])

for cat, pts in edge_points.items():
    fig.add_trace(
        go.Scatter(
            x=pts["x"],
            y=pts["y"],
            mode="lines",
            line=dict(color=cat_colors[cat], width=4),
            name=cat,
            hovertemplate=f"{cat}<extra></extra>",
            cliponaxis=False
        )
    )

# Add node markers (single trace, no legend)
fig.add_trace(
    go.Scatter(
        x=x_vals,
        y=y_vals,
        mode="markers",
        marker=dict(color="#D2BA4C", size=18),  # Moderate yellow
        hovertemplate="Step %{x}: %{text}<extra></extra>",
        text=steps,
        showlegend=False,
        cliponaxis=False
    )
)

# Layout settings
fig.update_layout(
    title="CloudHSM S3 PKCS Flow",
    legend=dict(orientation='h', yanchor='bottom', y=1.05, xanchor='center', x=0.5)
)

fig.update_xaxes(
    title_text="Workflow",
    tickmode="array",
    tickvals=x_vals,
    ticktext=steps
)

fig.update_yaxes(
    title_text="Seq",
    showticklabels=False
)

# Save as PNG
file_path = "cloudhsm_flow.png"
fig.write_image(file_path)
file_path