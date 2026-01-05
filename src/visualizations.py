import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import pandas as pd
from matplotlib.figure import Figure

# Set style
plt.style.use('seaborn-v0_8-whitegrid')
sns.set_palette("husl")


def create_time_series_plot(df):
    """Create time series visualization of network data"""
    fig = Figure(figsize=(12, 8))

    # Find timestamp column
    time_cols = [col for col in df.columns
                 if any(keyword in col.lower()
                        for keyword in ['time', 'timestamp', 'date'])]

    if time_cols:
        time_col = time_cols[0]
        # Find numeric columns to plot
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        plot_cols = [col for col in numeric_cols
                     if col != time_col][:3]  # Plot up to 3 metrics

        if plot_cols:
            ax = fig.add_subplot(111)

            for i, col in enumerate(plot_cols):
                ax.plot(df[time_col], df[col],
                        label=col, linewidth=2, alpha=0.8)

            ax.set_xlabel(time_col)
            ax.set_ylabel('Value')
            ax.set_title('Network Traffic Over Time')
            ax.legend()
            ax.grid(True, alpha=0.3)

            # Rotate x-axis labels if many points
            if len(df) > 50:
                plt.setp(ax.xaxis.get_majorticklabels(), rotation=45)
        else:
            ax = fig.add_subplot(111)
            ax.text(0.5, 0.5, 'No numeric data found for time series',
                    ha='center', va='center', transform=ax.transAxes)
    else:
        ax = fig.add_subplot(111)
        ax.text(0.5, 0.5, 'No timestamp column found',
                ha='center', va='center', transform=ax.transAxes)

    fig.tight_layout()
    return fig


def create_distribution_plot(df):
    """Create distribution plots for numeric columns"""
    numeric_cols = df.select_dtypes(include=[np.number]).columns

    if len(numeric_cols) == 0:
        fig = Figure(figsize=(8, 6))
        ax = fig.add_subplot(111)
        ax.text(0.5, 0.5, 'No numeric columns found',
                ha='center', va='center', transform=ax.transAxes)
        return fig

    # Create subplots
    n_cols = min(4, len(numeric_cols))
    n_rows = (len(numeric_cols) + n_cols - 1) // n_cols

    fig = Figure(figsize=(n_cols * 4, n_rows * 3))

    for i, col in enumerate(numeric_cols[:n_cols * n_rows]):
        ax = fig.add_subplot(n_rows, n_cols, i + 1)

        # Plot histogram
        ax.hist(df[col].dropna(), bins=30, alpha=0.7, edgecolor='black')
        ax.set_title(col)
        ax.set_xlabel('Value')
        ax.set_ylabel('Frequency')
        ax.grid(True, alpha=0.3)

    fig.suptitle('Distribution of Network Features', fontsize=16)
    fig.tight_layout()
    return fig


def create_anomaly_scatter(df):
    """Create scatter plot showing anomalies"""
    fig = Figure(figsize=(10, 8))
    ax = fig.add_subplot(111)

    if 'anomaly' not in df.columns:
        ax.text(0.5, 0.5, 'Run anomaly detection first',
                ha='center', va='center', transform=ax.transAxes)
        return fig

    # Get numeric columns for plotting
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    plot_cols = [col for col in numeric_cols
                 if col not in ['anomaly', 'anomaly_score', 'anomaly_confidence']]

    if len(plot_cols) >= 2:
        x_col, y_col = plot_cols[:2]

        # Separate normal and anomaly points
        normal = df[df['anomaly'] == 0]
        anomalies = df[df['anomaly'] == 1]

        # Plot normal points
        ax.scatter(normal[x_col], normal[y_col],
                   alpha=0.6, s=20, label='Normal', c='blue')

        # Plot anomalies
        if len(anomalies) > 0:
            ax.scatter(anomalies[x_col], anomalies[y_col],
                       alpha=0.8, s=50, label='Anomaly', c='red',
                       edgecolors='black', linewidth=1)

        ax.set_xlabel(x_col)
        ax.set_ylabel(y_col)
        ax.set_title('Anomaly Detection Results')
        ax.legend()
        ax.grid(True, alpha=0.3)
    else:
        ax.text(0.5, 0.5, 'Need at least 2 numeric columns for scatter plot',
                ha='center', va='center', transform=ax.transAxes)

    fig.tight_layout()
    return fig


def create_protocol_analysis(df):
    """Analyze protocol distribution"""
    fig = Figure(figsize=(12, 8))

    # Find protocol column
    protocol_cols = [col for col in df.columns
                     if any(keyword in col.lower()
                            for keyword in ['proto', 'protocol', 'type'])]

    if protocol_cols:
        protocol_col = protocol_cols[0]

        # Create subplots
        ax1 = fig.add_subplot(221)
        ax2 = fig.add_subplot(222)
        ax3 = fig.add_subplot(212)

        # Pie chart of protocol distribution
        protocol_counts = df[protocol_col].value_counts().head(10)
        ax1.pie(protocol_counts.values, labels=protocol_counts.index,
                autopct='%1.1f%%', startangle=90)
        ax1.set_title('Protocol Distribution (Top 10)')

        # Bar chart
        ax2.bar(range(len(protocol_counts)), protocol_counts.values)
        ax2.set_xticks(range(len(protocol_counts)))
        ax2.set_xticklabels(protocol_counts.index, rotation=45, ha='right')
        ax2.set_title('Protocol Counts')
        ax2.set_ylabel('Count')

        # Protocol over time (if timestamp exists)
        time_cols = [col for col in df.columns
                     if any(keyword in col.lower()
                            for keyword in ['time', 'timestamp'])]

        if time_cols:
            time_col = time_cols[0]
            # Get top 3 protocols
            top_protocols = protocol_counts.index[:3]

            for protocol in top_protocols:
                protocol_data = df[df[protocol_col] == protocol]
                if len(protocol_data) > 0:
                    ax3.plot(protocol_data[time_col],
                             range(len(protocol_data)),
                             label=str(protocol), linewidth=2)

            ax3.set_xlabel(time_col)
            ax3.set_ylabel('Cumulative Count')
            ax3.set_title('Protocol Activity Over Time')
            ax3.legend()
            ax3.grid(True, alpha=0.3)
        else:
            ax3.text(0.5, 0.5, 'No timestamp data available',
                     ha='center', va='center', transform=ax3.transAxes)

    else:
        ax = fig.add_subplot(111)
        ax.text(0.5, 0.5, 'No protocol column found',
                ha='center', va='center', transform=ax.transAxes)

    fig.suptitle('Protocol Analysis', fontsize=16)
    fig.tight_layout()
    return fig


def create_arp_analysis(df):
    """Specialized ARP traffic analysis"""
    fig = Figure(figsize=(12, 8))

    # Check if we have ARP-related data
    has_arp = False

    # Method 1: Check for protocol column with ARP values
    protocol_cols = [col for col in df.columns
                     if any(keyword in col.lower()
                            for keyword in ['proto', 'protocol'])]

    if protocol_cols:
        protocol_col = protocol_cols[0]
        arp_data = df[df[protocol_col].astype(str).str.contains('arp', case=False, na=False)]
        has_arp = len(arp_data) > 0

    # Method 2: Check for ARP in any column
    if not has_arp:
        for col in df.columns:
            if df[col].astype(str).str.contains('arp', case=False, na=False).any():
                has_arp = True
                break

    if has_arp:
        # Create ARP-specific analysis
        ax1 = fig.add_subplot(221)
        ax2 = fig.add_subplot(222)
        ax3 = fig.add_subplot(223)
        ax4 = fig.add_subplot(224)

        # Example ARP analysis visualizations
        ax1.text(0.5, 0.5, 'ARP Request/Response\nDistribution',
                 ha='center', va='center', transform=ax1.transAxes)
        ax1.set_title('ARP Message Types')

        ax2.text(0.5, 0.5, 'ARP Source IP\nFrequency',
                 ha='center', va='center', transform=ax2.transAxes)
        ax2.set_title('Top ARP Sources')

        ax3.text(0.5, 0.5, 'Possible ARP Spoofing\nDetection',
                 ha='center', va='center', transform=ax3.transAxes)
        ax3.set_title('Security Analysis')

        ax4.text(0.5, 0.5, 'ARP Traffic\nOver Time',
                 ha='center', va='center', transform=ax4.transAxes)
        ax4.set_title('Temporal Pattern')

    else:
        ax = fig.add_subplot(111)
        ax.text(0.5, 0.5, 'No ARP data found in this dataset\n'
                          'Try uploading network packet capture (PCAP) data',
                ha='center', va='center', transform=ax.transAxes)

    fig.suptitle('ARP Traffic Analysis', fontsize=16)
    fig.tight_layout()
    return fig


def create_heatmap(df):
    """Create correlation heatmap"""
    fig = Figure(figsize=(10, 8))
    ax = fig.add_subplot(111)

    # Get numeric columns
    numeric_cols = df.select_dtypes(include=[np.number]).columns

    if len(numeric_cols) < 2:
        ax.text(0.5, 0.5, 'Need at least 2 numeric columns for heatmap',
                ha='center', va='center', transform=ax.transAxes)
        return fig

    # Calculate correlation matrix
    corr_matrix = df[numeric_cols].corr()

    # Create heatmap
    im = ax.imshow(corr_matrix, cmap='coolwarm', aspect='auto',
                   vmin=-1, vmax=1)

    # Add colorbar
    cbar = fig.colorbar(im, ax=ax)
    cbar.set_label('Correlation')

    # Set ticks
    ax.set_xticks(range(len(numeric_cols)))
    ax.set_yticks(range(len(numeric_cols)))
    ax.set_xticklabels(numeric_cols, rotation=45, ha='right')
    ax.set_yticklabels(numeric_cols)

    # Add correlation values
    for i in range(len(numeric_cols)):
        for j in range(len(numeric_cols)):
            text = ax.text(j, i, f'{corr_matrix.iloc[i, j]:.2f}',
                           ha='center', va='center',
                           color='white' if abs(corr_matrix.iloc[i, j]) > 0.5 else 'black')

    ax.set_title('Feature Correlation Heatmap')
    fig.tight_layout()
    return fig