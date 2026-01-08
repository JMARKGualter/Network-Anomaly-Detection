import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import pandas as pd
from matplotlib.figure import Figure
import matplotlib.animation as animation
from matplotlib.animation import FuncAnimation
import warnings

warnings.filterwarnings('ignore')

# Set style
plt.style.use('seaborn-v0_8-darkgrid')
sns.set_palette("husl")


# ============== STATIC PLOTS ==============

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


# ============== ANIMATED PLOTS ==============

def create_animated_time_series(df, ax):
    """Create animated time series plot - returns animation function"""
    if 'timestamp' not in df.columns:
        # Create dummy time if none exists
        df = df.reset_index()
        df['timestamp'] = df.index

    # Sort by time
    df = df.sort_values('timestamp')

    # Get first numeric column
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    if len(numeric_cols) == 0:
        return None

    y_col = numeric_cols[0]

    # Create line for animation
    line, = ax.plot([], [], lw=3, color='#4361ee', alpha=0.8)
    point, = ax.plot([], [], 'o', color='#f72585', markersize=10)

    # Set up plot
    ax.set_xlim(df['timestamp'].min(), df['timestamp'].max())
    ax.set_ylim(df[y_col].min() * 0.9, df[y_col].max() * 1.1)
    ax.set_xlabel('Time')
    ax.set_ylabel(y_col)
    ax.set_title('Network Traffic Over Time (Animated)')
    ax.grid(True, alpha=0.3)

    def animate(i):
        """Animation function"""
        if i < len(df):
            x_data = df['timestamp'].iloc[:i + 1]
            y_data = df[y_col].iloc[:i + 1]
            line.set_data(x_data, y_data)
            point.set_data([df['timestamp'].iloc[i]], [df[y_col].iloc[i]])

        return line, point

    return animate


def create_animated_scatter(df, ax):
    """Create animated scatter plot showing anomalies - returns animation function"""
    if 'anomaly' not in df.columns:
        return None

    numeric_cols = df.select_dtypes(include=[np.number]).columns
    numeric_cols = [col for col in numeric_cols if col not in ['anomaly', 'anomaly_score']]

    if len(numeric_cols) < 2:
        return None

    x_col, y_col = numeric_cols[:2]

    # Create scatter plots
    normal_scatter = ax.scatter([], [], alpha=0.6, s=20, label='Normal',
                                color='#4361ee', animated=True)
    anomaly_scatter = ax.scatter([], [], alpha=0.9, s=50, label='Anomaly',
                                 color='#f72585', edgecolors='black',
                                 linewidth=1.5, animated=True)

    # Set limits
    ax.set_xlim(df[x_col].min() * 0.9, df[x_col].max() * 1.1)
    ax.set_ylim(df[y_col].min() * 0.9, df[y_col].max() * 1.1)
    ax.set_xlabel(x_col)
    ax.set_ylabel(y_col)
    ax.set_title('Anomaly Detection (Animated)')
    ax.legend()
    ax.grid(True, alpha=0.3)

    def animate(i):
        """Animation function"""
        # Show more points over time
        step = max(1, len(df) // 50)
        idx = min(i * step, len(df))

        df_partial = df.iloc[:idx]
        normal_partial = df_partial[df_partial['anomaly'] == 0]
        anomaly_partial = df_partial[df_partial['anomaly'] == 1]

        if len(normal_partial) > 0:
            normal_scatter.set_offsets(np.c_[normal_partial[x_col], normal_partial[y_col]])

        if len(anomaly_partial) > 0:
            anomaly_scatter.set_offsets(np.c_[anomaly_partial[x_col], anomaly_partial[y_col]])

        # Update title with progress
        ax.set_title(f'Anomaly Detection ({idx}/{len(df)} points)')

        return normal_scatter, anomaly_scatter

    return animate


def create_pulsing_heatmap(df, ax):
    """Create heatmap with pulsing animation - returns animation function"""
    numeric_cols = df.select_dtypes(include=[np.number]).columns

    if len(numeric_cols) < 2:
        return None

    # Calculate correlation matrix
    corr_matrix = df[numeric_cols].corr()

    # Initial heatmap
    im = ax.imshow(corr_matrix, cmap='coolwarm', aspect='auto',
                   vmin=-1, vmax=1, animated=True)

    # Add colorbar
    cbar = plt.colorbar(im, ax=ax)
    cbar.set_label('Correlation')

    # Set ticks
    ax.set_xticks(range(len(numeric_cols)))
    ax.set_yticks(range(len(numeric_cols)))
    ax.set_xticklabels(numeric_cols, rotation=45, ha='right')
    ax.set_yticklabels(numeric_cols)
    ax.set_title('Feature Correlation Heatmap')

    def animate(i):
        """Pulsing animation"""
        # Create pulsing effect by modulating vmin/vmax
        pulse = 0.1 * np.sin(i * 0.1)  # Gentle pulse
        im.set_clim(vmin=-1 + pulse, vmax=1 - pulse)

        # Add correlation values with fade effect
        for text in ax.texts:
            text.remove()

        alpha = 0.5 + 0.5 * abs(np.sin(i * 0.1))  # Fading effect
        for i_idx in range(len(numeric_cols)):
            for j_idx in range(len(numeric_cols)):
                value = corr_matrix.iloc[i_idx, j_idx]
                color = 'white' if abs(value) > 0.5 else 'black'
                ax.text(j_idx, i_idx, f'{value:.2f}',
                        ha='center', va='center',
                        color=color, alpha=alpha,
                        fontsize=8, fontweight='bold')

        return im,

    return animate


def create_protocol_bar_animation(df, ax):
    """Animated bar chart for protocol distribution - returns animation function"""
    protocol_cols = [col for col in df.columns
                     if any(keyword in col.lower()
                            for keyword in ['proto', 'protocol', 'type'])]

    if not protocol_cols:
        return None

    protocol_col = protocol_cols[0]
    protocol_counts = df[protocol_col].value_counts().head(8)

    # Create bars
    bars = ax.bar(range(len(protocol_counts)), [0] * len(protocol_counts),
                  color='#4361ee', alpha=0.7, edgecolor='black')

    # Set up plot
    ax.set_xlabel('Protocol')
    ax.set_ylabel('Count')
    ax.set_title('Protocol Distribution (Loading...)')
    ax.set_xticks(range(len(protocol_counts)))
    ax.set_xticklabels(protocol_counts.index, rotation=45, ha='right')
    ax.grid(True, alpha=0.3, axis='y')

    def animate(i):
        """Growing bars animation"""
        for idx, bar in enumerate(bars):
            target_height = protocol_counts.iloc[idx]
            current_height = bar.get_height()

            # Smooth growth
            if current_height < target_height:
                new_height = current_height + target_height * 0.05
                bar.set_height(min(new_height, target_height))

            # Add value labels at the end
            if i > 40:  # Show labels after animation
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width() / 2., height,
                        f'{int(height):,}', ha='center', va='bottom',
                        fontsize=9, fontweight='bold')

        # Update title
        progress = min(i / 50, 1.0)
        ax.set_title(f'Protocol Distribution ({progress * 100:.0f}% loaded)')

        return bars

    return animate


def create_loading_animation(ax):
    """Create a loading animation for empty states - returns animation function"""
    # Create rotating dots
    dots = []
    colors = ['#4361ee', '#4cc9f0', '#7209b7', '#f72585', '#3a0ca3']

    for i in range(5):
        dot, = ax.plot([], [], 'o', color=colors[i], markersize=15,
                       alpha=0.7, animated=True)
        dots.append(dot)

    ax.set_xlim(-1.5, 1.5)
    ax.set_ylim(-1.5, 1.5)
    ax.axis('off')
    ax.set_title('Loading Analysis...', fontsize=14, pad=20)

    def animate(i):
        """Rotating dots animation"""
        angle = i * 0.1
        radius = 1.0

        for idx, dot in enumerate(dots):
            offset = idx * (2 * np.pi / 5)
            x = radius * np.cos(angle + offset)
            y = radius * np.sin(angle + offset)
            dot.set_data([x], [y])

        # Add pulsing effect
        for idx, dot in enumerate(dots):
            pulse = 0.3 * abs(np.sin(angle + idx * 0.5)) + 0.7
            dot.set_alpha(pulse)
            dot.set_markersize(15 * pulse)

        return dots

    return animate