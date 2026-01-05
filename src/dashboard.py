import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import pandas as pd
import numpy as np
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
from matplotlib.figure import Figure
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import json
import os
import sys

# Import project modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from data_loader import load_and_validate_csv
from enhanced_model import EnhancedAnomalyDetector
from visualizations import (
    create_time_series_plot,
    create_distribution_plot,
    create_anomaly_scatter,
    create_protocol_analysis,
    create_heatmap,
    create_arp_analysis
)
from report_generator import generate_report

# ---------- THEME ----------
BG_COLOR = "#f8f9fa"  # Light gray background
PANEL_COLOR = "#ffffff"  # White panels
ACCENT_COLOR = "#4361ee"  # Blue accent
WARNING_COLOR = "#f72585"  # Pink for anomalies
SUCCESS_COLOR = "#4cc9f0"  # Cyan for success
TEXT_COLOR = "#2b2d42"  # Dark text
BORDER_COLOR = "#dee2e6"  # Light border


class NetworkAnomalyDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Anomaly Detection System")
        self.root.geometry("1400x900")
        self.root.configure(bg=BG_COLOR)

        # Application state
        self.data = None
        self.anomaly_results = None
        self.current_view = "overview"

        # Initialize UI
        self.setup_styles()
        self.create_main_layout()

    def setup_styles(self):
        """Configure ttk styles"""
        style = ttk.Style()
        style.theme_use('clam')

        # Configure colors
        style.configure('Title.TLabel',
                        background=BG_COLOR,
                        foreground=TEXT_COLOR,
                        font=('Segoe UI', 16, 'bold'))

        style.configure('Panel.TFrame',
                        background=PANEL_COLOR,
                        relief='solid',
                        borderwidth=1)

        style.configure('Accent.TButton',
                        background=ACCENT_COLOR,
                        foreground='white',
                        font=('Segoe UI', 10),
                        borderwidth=0)

        style.map('Accent.TButton',
                  background=[('active', '#3a56d4')])

        style.configure('Warning.TButton',
                        background=WARNING_COLOR,
                        foreground='white')

    def create_main_layout(self):
        """Create the main dashboard layout"""

        # Header
        header_frame = ttk.Frame(self.root, style='Panel.TFrame')
        header_frame.pack(fill='x', padx=20, pady=10)

        ttk.Label(header_frame,
                  text="🔍 Network Anomaly Detection System",
                  style='Title.TLabel').pack(side='left', padx=10)

        # Status label
        self.status_label = ttk.Label(header_frame,
                                      text="Ready to analyze network data",
                                      foreground='#6c757d')
        self.status_label.pack(side='right', padx=10)

        # Main container (sidebar + content)
        main_container = ttk.Frame(self.root)
        main_container.pack(fill='both', expand=True, padx=20, pady=10)

        # Left sidebar
        self.create_sidebar(main_container)

        # Right content area
        self.content_frame = ttk.Frame(main_container, style='Panel.TFrame')
        self.content_frame.pack(side='right', fill='both', expand=True, padx=(10, 0))

        # Initial empty state
        self.show_welcome_screen()

    def create_sidebar(self, parent):
        """Create the sidebar with navigation"""
        sidebar = ttk.Frame(parent, width=250, style='Panel.TFrame')
        sidebar.pack(side='left', fill='y')
        sidebar.pack_propagate(False)

        # Upload section
        upload_frame = ttk.Frame(sidebar)
        upload_frame.pack(fill='x', padx=15, pady=15)

        ttk.Label(upload_frame,
                  text="DATA SOURCE",
                  font=('Segoe UI', 10, 'bold')).pack(anchor='w')

        self.upload_btn = ttk.Button(upload_frame,
                                     text="📁 Upload CSV/PCAP",
                                     command=self.upload_data,
                                     style='Accent.TButton')
        self.upload_btn.pack(fill='x', pady=5)

        self.data_info_label = ttk.Label(upload_frame,
                                         text="No data loaded",
                                         font=('Segoe UI', 9),
                                         foreground='#6c757d')
        self.data_info_label.pack(anchor='w')

        # Separator
        ttk.Separator(sidebar, orient='horizontal').pack(fill='x', padx=15, pady=10)

        # Analysis sections (initially disabled)
        self.analysis_frame = ttk.Frame(sidebar)
        self.analysis_frame.pack(fill='x', padx=15, pady=5)

        ttk.Label(self.analysis_frame,
                  text="ANALYSIS VIEWS",
                  font=('Segoe UI', 10, 'bold')).pack(anchor='w')

        # View buttons
        views = [
            ("📊 Overview", "overview"),
            ("⏰ Time Series", "time_series"),
            ("📈 Distributions", "distributions"),
            ("🎯 Anomaly Detection", "anomaly_detection"),
            ("🔢 Protocol Analysis", "protocols"),
            ("🌐 ARP Analysis", "arp"),
            ("🔥 Heatmap", "heatmap"),
            ("📋 Detailed View", "detailed")
        ]

        self.view_buttons = {}
        for text, view_key in views:
            btn = ttk.Button(self.analysis_frame,
                             text=text,
                             command=lambda v=view_key: self.switch_view(v))
            btn.pack(fill='x', pady=2)
            btn.state(['disabled'])
            self.view_buttons[view_key] = btn

        # Separator
        ttk.Separator(sidebar, orient='horizontal').pack(fill='x', padx=15, pady=10)

        # Actions section
        actions_frame = ttk.Frame(sidebar)
        actions_frame.pack(fill='x', padx=15, pady=5)

        ttk.Label(actions_frame,
                  text="ACTIONS",
                  font=('Segoe UI', 10, 'bold')).pack(anchor='w')

        # Action buttons
        self.detect_btn = ttk.Button(actions_frame,
                                     text="🚨 Run Anomaly Detection",
                                     command=self.run_anomaly_detection,
                                     style='Warning.TButton')
        self.detect_btn.pack(fill='x', pady=2)
        self.detect_btn.state(['disabled'])

        self.export_btn = ttk.Button(actions_frame,
                                     text="💾 Export Report",
                                     command=self.export_report)
        self.export_btn.pack(fill='x', pady=2)
        self.export_btn.state(['disabled'])

        # Model selection
        ttk.Label(actions_frame,
                  text="Detection Model:",
                  font=('Segoe UI', 9)).pack(anchor='w', pady=(10, 0))

        self.model_var = tk.StringVar(value="Isolation Forest")
        model_combo = ttk.Combobox(actions_frame,
                                   textvariable=self.model_var,
                                   values=["Isolation Forest",
                                           "Local Outlier Factor",
                                           "One-Class SVM",
                                           "Autoencoder",
                                           "Ensemble Voting"],
                                   state="readonly",
                                   width=20)
        model_combo.pack(fill='x', pady=2)

    def show_welcome_screen(self):
        """Show initial welcome/upload screen"""
        for widget in self.content_frame.winfo_children():
            widget.destroy()

        welcome_frame = ttk.Frame(self.content_frame)
        welcome_frame.pack(expand=True, fill='both', padx=50, pady=50)

        # Welcome text
        ttk.Label(welcome_frame,
                  text="Welcome to Network Anomaly Detection",
                  font=('Segoe UI', 24, 'bold'),
                  foreground=TEXT_COLOR).pack(pady=20)

        ttk.Label(welcome_frame,
                  text="Upload network traffic data to begin analysis",
                  font=('Segoe UI', 14),
                  foreground='#6c757d').pack(pady=10)

        # Upload card
        upload_card = ttk.Frame(welcome_frame, style='Panel.TFrame')
        upload_card.pack(pady=30, ipadx=20, ipady=20)

        ttk.Label(upload_card,
                  text="📁",
                  font=('Segoe UI', 48)).pack(pady=10)

        ttk.Label(upload_card,
                  text="Upload Data",
                  font=('Segoe UI', 16, 'bold')).pack()

        ttk.Label(upload_card,
                  text="Supports: CSV, PCAP, NetFlow",
                  font=('Segoe UI', 11),
                  foreground='#6c757d').pack(pady=5)

        upload_inner_btn = ttk.Button(upload_card,
                                      text="Select File",
                                      command=self.upload_data,
                                      style='Accent.TButton')
        upload_inner_btn.pack(pady=15, ipadx=20, ipady=5)

        # Features list
        features_frame = ttk.Frame(welcome_frame)
        features_frame.pack(pady=30)

        features = [
            "✓ Time-series analysis of network traffic",
            "✓ Multi-algorithm anomaly detection",
            "✓ Protocol-specific anomaly analysis",
            "✓ ARP spoofing/malicious activity detection",
            "✓ Interactive visualizations",
            "✓ Exportable reports"
        ]

        for feature in features:
            ttk.Label(features_frame,
                      text=feature,
                      font=('Segoe UI', 11)).pack(anchor='w', pady=2)

    def upload_data(self):
        """Handle file upload"""
        filetypes = [
            ("CSV files", "*.csv"),
            ("PCAP files", "*.pcap"),
            ("Text files", "*.txt"),
            ("All files", "*.*")
        ]

        filepath = filedialog.askopenfilename(
            title="Select network data file",
            filetypes=filetypes
        )

        if filepath:
            try:
                self.status_label.config(text=f"Loading {os.path.basename(filepath)}...")
                self.root.update()

                # Load data
                self.data = load_and_validate_csv(filepath)

                # Update UI
                self.data_info_label.config(
                    text=f"✓ {len(self.data)} rows, {len(self.data.columns)} features"
                )

                # Enable analysis buttons
                for btn in self.view_buttons.values():
                    btn.state(['!disabled'])
                self.detect_btn.state(['!disabled'])

                # Show overview
                self.switch_view("overview")
                self.status_label.config(text=f"Loaded: {os.path.basename(filepath)}")

            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file:\n{str(e)}")
                self.status_label.config(text="Error loading file")

    def switch_view(self, view_key):
        """Switch between different analysis views"""
        self.current_view = view_key

        # Update button states
        for key, btn in self.view_buttons.items():
            if key == view_key:
                btn.configure(style='Accent.TButton')
            else:
                btn.configure(style='TButton')

        # Clear content area
        for widget in self.content_frame.winfo_children():
            widget.destroy()

        # Add back button for non-overview views
        if view_key != "overview":
            nav_frame = ttk.Frame(self.content_frame)
            nav_frame.pack(fill='x', padx=20, pady=10)

            ttk.Button(nav_frame,
                       text="← Back to Overview",
                       command=lambda: self.switch_view("overview")).pack(anchor='w')

        # Show appropriate view
        if view_key == "overview":
            self.show_overview()
        elif view_key == "time_series":
            self.show_time_series()
        elif view_key == "distributions":
            self.show_distributions()
        elif view_key == "anomaly_detection":
            self.show_anomaly_detection()
        elif view_key == "protocols":
            self.show_protocol_analysis()
        elif view_key == "arp":
            self.show_arp_analysis()
        elif view_key == "heatmap":
            self.show_heatmap()
        elif view_key == "detailed":
            self.show_detailed_view()

    def show_overview(self):
        """Show data overview dashboard"""
        if self.data is None:
            return

        # Create notebook for multiple overview tabs
        notebook = ttk.Notebook(self.content_frame)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)

        # Tab 1: Quick Stats
        stats_frame = ttk.Frame(notebook)
        notebook.add(stats_frame, text="📋 Quick Stats")

        # Calculate statistics
        stats_text = self.get_data_statistics()
        stats_display = scrolledtext.ScrolledText(stats_frame, height=20)
        stats_display.insert('1.0', stats_text)
        stats_display.configure(state='disabled')
        stats_display.pack(fill='both', expand=True, padx=10, pady=10)

        # Tab 2: Data Preview
        preview_frame = ttk.Frame(notebook)
        notebook.add(preview_frame, text="👀 Data Preview")

        # Show first few rows
        preview_text = scrolledtext.ScrolledText(preview_frame, height=20)
        preview_text.insert('1.0', str(self.data.head(20)))
        preview_text.configure(state='disabled')
        preview_text.pack(fill='both', expand=True, padx=10, pady=10)

        # Tab 3: Column Info
        columns_frame = ttk.Frame(notebook)
        notebook.add(columns_frame, text="🔠 Columns")

        columns_text = scrolledtext.ScrolledText(columns_frame, height=20)
        col_info = "\n".join([f"{col}: {str(dtype)}"
                              for col, dtype in self.data.dtypes.items()])
        columns_text.insert('1.0', col_info)
        columns_text.configure(state='disabled')
        columns_text.pack(fill='both', expand=True, padx=10, pady=10)

        # Quick visualization
        if len(self.data.columns) >= 2:
            viz_frame = ttk.Frame(self.content_frame)
            viz_frame.pack(fill='both', expand=True, padx=10, pady=10)

            try:
                fig = Figure(figsize=(10, 4))
                ax = fig.add_subplot(111)

                # Plot first numeric column
                numeric_cols = self.data.select_dtypes(include=[np.number]).columns
                if len(numeric_cols) > 0:
                    self.data[numeric_cols[0]].plot(kind='line', ax=ax)
                    ax.set_title(f"Trend: {numeric_cols[0]}")
                    ax.grid(True, alpha=0.3)

                    canvas = FigureCanvasTkAgg(fig, viz_frame)
                    canvas.draw()
                    canvas.get_tk_widget().pack(fill='both', expand=True)
            except:
                pass

    def get_data_statistics(self):
        """Generate statistics text for overview"""
        stats = []
        stats.append("=" * 50)
        stats.append("DATA OVERVIEW")
        stats.append("=" * 50)
        stats.append(f"Total Rows: {len(self.data):,}")
        stats.append(f"Total Columns: {len(self.data.columns)}")
        stats.append(f"Memory Usage: {self.data.memory_usage(deep=True).sum() / 1024:.1f} KB")
        stats.append("")

        stats.append("COLUMN TYPES:")
        stats.append("-" * 30)
        for dtype in self.data.dtypes.unique():
            count = (self.data.dtypes == dtype).sum()
            stats.append(f"{dtype}: {count} columns")
        stats.append("")

        stats.append("MISSING VALUES:")
        stats.append("-" * 30)
        missing = self.data.isnull().sum()
        for col, count in missing[missing > 0].items():
            stats.append(f"{col}: {count} ({count / len(self.data) * 100:.1f}%)")

        if missing.sum() == 0:
            stats.append("No missing values found")
        stats.append("")

        stats.append("NUMERIC STATISTICS:")
        stats.append("-" * 30)
        numeric_cols = self.data.select_dtypes(include=[np.number]).columns
        for col in numeric_cols[:5]:  # Limit to first 5
            stats.append(f"{col}:")
            stats.append(f"  Mean: {self.data[col].mean():.2f}")
            stats.append(f"  Std: {self.data[col].std():.2f}")
            stats.append(f"  Min: {self.data[col].min():.2f}")
            stats.append(f"  Max: {self.data[col].max():.2f}")
            stats.append("")

        return "\n".join(stats)

    def show_time_series(self):
        """Show time series analysis"""
        if self.data is None:
            return

        # Create visualization
        fig = create_time_series_plot(self.data)

        # Embed in tkinter
        canvas = FigureCanvasTkAgg(fig, self.content_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill='both', expand=True, padx=10, pady=10)

        # Add toolbar
        toolbar = NavigationToolbar2Tk(canvas, self.content_frame)
        toolbar.update()
        canvas.get_tk_widget().pack(fill='both', expand=True)

    def show_distributions(self):
        """Show distribution plots"""
        if self.data is None:
            return

        fig = create_distribution_plot(self.data)

        canvas = FigureCanvasTkAgg(fig, self.content_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill='both', expand=True, padx=10, pady=10)

        toolbar = NavigationToolbar2Tk(canvas, self.content_frame)
        toolbar.update()

    def run_anomaly_detection(self):
        """Run anomaly detection on loaded data"""
        if self.data is None:
            messagebox.showwarning("Warning", "Please upload data first!")
            return

        try:
            self.status_label.config(text="Running anomaly detection...")
            self.root.update()

            # Use enhanced model
            detector = EnhancedAnomalyDetector()
            self.anomaly_results = detector.detect(
                self.data,
                model_type=self.model_var.get()
            )

            # Enable export button
            self.export_btn.state(['!disabled'])

            # Switch to anomaly view
            self.switch_view("anomaly_detection")
            self.status_label.config(text="Anomaly detection completed!")

            # Show results summary
            anomaly_count = (self.anomaly_results.get('anomaly', 0) == 1).sum()
            messagebox.showinfo(
                "Detection Complete",
                f"Found {anomaly_count} anomalies ({anomaly_count / len(self.data) * 100:.1f}%)\n"
                f"Model: {self.model_var.get()}"
            )

        except Exception as e:
            messagebox.showerror("Error", f"Detection failed:\n{str(e)}")
            self.status_label.config(text="Detection failed")

    def show_anomaly_detection(self):
        """Show anomaly detection results"""
        if self.anomaly_results is None:
            # Show instruction
            ttk.Label(self.content_frame,
                      text="Run anomaly detection first to see results",
                      font=('Segoe UI', 14)).pack(pady=50)
            return

        # Create notebook for anomaly views
        notebook = ttk.Notebook(self.content_frame)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)

        # Tab 1: Scatter plot
        scatter_frame = ttk.Frame(notebook)
        notebook.add(scatter_frame, text="Scatter Plot")

        fig = create_anomaly_scatter(self.anomaly_results)
        canvas = FigureCanvasTkAgg(fig, scatter_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill='both', expand=True)

        # Tab 2: Anomaly list
        list_frame = ttk.Frame(notebook)
        notebook.add(list_frame, text="Anomaly List")

        # Get anomalies
        anomalies = self.anomaly_results[self.anomaly_results.get('anomaly', 0) == 1]

        # Create treeview
        tree_frame = ttk.Frame(list_frame)
        tree_frame.pack(fill='both', expand=True, padx=10, pady=10)

        tree_scroll = ttk.Scrollbar(tree_frame)
        tree_scroll.pack(side='right', fill='y')

        tree = ttk.Treeview(tree_frame,
                            yscrollcommand=tree_scroll.set,
                            selectmode='extended')
        tree_scroll.config(command=tree.yview)

        # Define columns
        columns = list(anomalies.columns[:10])  # First 10 columns
        tree['columns'] = columns

        # Format columns
        tree.column("#0", width=0, stretch=False)
        for col in columns:
            tree.column(col, anchor='w', width=100)
            tree.heading(col, text=col, anchor='w')

        # Add data
        for idx, row in anomalies.head(100).iterrows():  # Limit to 100 rows
            values = [str(row[col])[:50] for col in columns]  # Truncate long values
            tree.insert(parent='', index='end', values=values)

        tree.pack(fill='both', expand=True)

    def show_protocol_analysis(self):
        """Show protocol-specific analysis"""
        if self.data is None:
            return

        fig = create_protocol_analysis(self.data)

        canvas = FigureCanvasTkAgg(fig, self.content_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill='both', expand=True, padx=10, pady=10)

        toolbar = NavigationToolbar2Tk(canvas, self.content_frame)
        toolbar.update()

    def show_arp_analysis(self):
        """Show ARP-specific analysis"""
        if self.data is None:
            return

        try:
            fig = create_arp_analysis(self.data)

            canvas = FigureCanvasTkAgg(fig, self.content_frame)
            canvas.draw()
            canvas.get_tk_widget().pack(fill='both', expand=True, padx=10, pady=10)

            toolbar = NavigationToolbar2Tk(canvas, self.content_frame)
            toolbar.update()

        except Exception as e:
            ttk.Label(self.content_frame,
                      text=f"ARP analysis requires specific columns\nError: {str(e)}",
                      font=('Segoe UI', 12)).pack(pady=50)

    def show_heatmap(self):
        """Show correlation heatmap"""
        if self.data is None:
            return

        fig = create_heatmap(self.data)

        canvas = FigureCanvasTkAgg(fig, self.content_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill='both', expand=True, padx=10, pady=10)

        toolbar = NavigationToolbar2Tk(canvas, self.content_frame)
        toolbar.update()

    def show_detailed_view(self):
        """Show detailed data view"""
        if self.data is None:
            return

        # Create searchable/filterable data table
        main_frame = ttk.Frame(self.content_frame)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)

        # Search bar
        search_frame = ttk.Frame(main_frame)
        search_frame.pack(fill='x', pady=(0, 10))

        ttk.Label(search_frame, text="Search:").pack(side='left', padx=(0, 5))
        search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=search_var, width=40)
        search_entry.pack(side='left')

        # Filter by column
        filter_frame = ttk.Frame(main_frame)
        filter_frame.pack(fill='x', pady=(0, 10))

        ttk.Label(filter_frame, text="Filter Column:").pack(side='left', padx=(0, 5))
        column_var = tk.StringVar(value=self.data.columns[0])
        column_combo = ttk.Combobox(filter_frame,
                                    textvariable=column_var,
                                    values=list(self.data.columns))
        column_combo.pack(side='left', padx=(0, 10))

        ttk.Label(filter_frame, text="Value:").pack(side='left', padx=(0, 5))
        value_entry = ttk.Entry(filter_frame, width=20)
        value_entry.pack(side='left')

        # Data display
        text_widget = scrolledtext.ScrolledText(main_frame, height=30)
        text_widget.pack(fill='both', expand=True)

        # Show all data (truncated if large)
        if len(self.data) > 1000:
            display_data = self.data.head(1000)
            text_widget.insert('1.0',
                               f"Showing first 1000 of {len(self.data)} rows\n\n")
            text_widget.insert('end', str(display_data))
            text_widget.insert('end',
                               f"\n\n... and {len(self.data) - 1000} more rows")
        else:
            text_widget.insert('1.0', str(self.data))

        text_widget.configure(state='disabled')

    def export_report(self):
        """Export analysis report"""
        if self.data is None:
            return

        try:
            report = generate_report(self.data, self.anomaly_results)

            # Save dialog
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[
                    ("Text files", "*.txt"),
                    ("Markdown files", "*.md"),
                    ("All files", "*.*")
                ]
            )

            if filename:
                with open(filename, 'w') as f:
                    f.write(report)

                messagebox.showinfo(
                    "Success",
                    f"Report saved to:\n{filename}"
                )
                self.status_label.config(text=f"Report exported: {os.path.basename(filename)}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to export report:\n{str(e)}")


def main():
    root = tk.Tk()
    app = NetworkAnomalyDashboard(root)
    root.mainloop()


if __name__ == "__main__":
    main()